//! Print what the demuxers of this crate deliver for a file, one line
//! per stream and one per packet, or re-multiplex a file into a new
//! transport stream.
//!
//! ```text
//! tsdump dump  <file> [program_number]
//! tsdump remux <in> <out.ts> [mux_rate_bps]
//! tsdump psi   <file>
//! ```
//!
//! `psi` prints every distinct PAT and PMT section of a transport
//! stream (plain 188-byte packets): the program list, and per program
//! map entry the `stream_type`, PID and descriptors (tag and bytes).
//!
//! `dump` output:
//!
//! ```text
//! S <index> <codec> <media> <width>x<height> <sample_rate> <channels> <language> <start_time>
//! P <index> <pts> <dts> <duration> <K|-> <size> <adler32 of the payload>
//! ```
//!
//! Missing values print as `-`. A file whose first bytes are a program
//! stream pack header goes through the program-stream demuxer,
//! everything else through the transport-stream demuxer.

use std::fs::File;
use std::io::{BufWriter, Read, Write};

use oxideav_core::{Demuxer, Error, MediaType, NullCodecResolver};
use oxideav_mpegts::demuxer::MpegTsDemuxer;

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65_521;
        b %= 65_521;
    }
    (b << 16) | a
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "-".to_string(), |x| x.to_string())
}

fn open(path: &str, program: Option<u16>) -> Result<Box<dyn Demuxer>, Error> {
    let mut head = [0u8; 4];
    let n = File::open(path)?.read(&mut head)?;
    let file = Box::new(File::open(path)?);
    if n == 4 && head == [0, 0, 1, 0xBA] {
        return oxideav_mpegts::open_ps_demuxer(file, &NullCodecResolver);
    }
    match program {
        Some(p) => Ok(Box::new(MpegTsDemuxer::open_program(file, p)?)),
        None => oxideav_mpegts::open_demuxer(file, &NullCodecResolver),
    }
}

fn dump(path: &str, program: Option<u16>) -> Result<(), Error> {
    let mut dmx = open(path, program)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut packets = Vec::new();
    loop {
        match dmx.next_packet() {
            Ok(p) => packets.push(p),
            Err(Error::Eof) => break,
            Err(e) => return Err(e),
        }
    }
    for s in dmx.streams() {
        let p = &s.params;
        let media = match p.media_type {
            MediaType::Video => "video",
            MediaType::Audio => "audio",
            MediaType::Subtitle => "subtitle",
            _ => "data",
        };
        writeln!(
            out,
            "S {} {} {} {}x{} {} {} {} {}",
            s.index,
            p.codec_id.as_str(),
            media,
            opt(p.width),
            opt(p.height),
            opt(p.sample_rate),
            opt(p.channels),
            opt(p.language.as_deref()),
            opt(s.start_time),
        )?;
    }
    for p in &packets {
        writeln!(
            out,
            "P {} {} {} {} {} {} {:08x}",
            p.stream_index,
            opt(p.pts),
            opt(p.dts),
            opt(p.duration),
            if p.flags.keyframe { 'K' } else { '-' },
            p.data.len(),
            adler32(&p.data),
        )?;
    }
    Ok(())
}

fn remux(src: &str, dst: &str, rate: Option<u64>) -> Result<(), Error> {
    let mut dmx = open(src, None)?;
    let streams = dmx.streams().to_vec();
    let out = Box::new(File::create(dst)?);
    let mut mux = oxideav_mpegts::MpegTsMuxer::with_config(
        out,
        &streams,
        oxideav_mpegts::muxer::MpegTsMuxConfig::default(),
    )?;
    mux.set_mux_rate(rate);
    use oxideav_core::Muxer;
    mux.write_header()?;
    loop {
        match dmx.next_packet() {
            Ok(p) => mux.write_packet(&p)?,
            Err(Error::Eof) => break,
            Err(e) => return Err(e),
        }
    }
    mux.write_trailer()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn psi(path: &str) -> Result<(), Error> {
    use oxideav_mpegts::{ProgramAssociationTable, ProgramMapTable, PsiSectionAssembler, TsPacket};
    let data = std::fs::read(path)?;
    let mut assemblers: std::collections::BTreeMap<u16, PsiSectionAssembler> = Default::default();
    assemblers.insert(0, PsiSectionAssembler::new());
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for raw in data.as_chunks::<188>().0 {
        let Ok(pkt) = TsPacket::parse(raw) else {
            continue;
        };
        let Some(asm) = assemblers.get_mut(&pkt.pid) else {
            continue;
        };
        if pkt.payload.is_empty() {
            continue;
        }
        let Ok(sections) = asm.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
        else {
            continue;
        };
        for section in sections {
            if seen.contains(&section) {
                continue;
            }
            if pkt.pid == 0 {
                if let Ok(pat) = ProgramAssociationTable::parse(&section) {
                    println!("PAT {:?}", pat.programs);
                    for &(number, pid) in &pat.programs {
                        if number != 0 {
                            assemblers.entry(pid).or_default();
                        }
                    }
                }
            } else if let Ok(pmt) = ProgramMapTable::parse(&section) {
                println!(
                    "PMT program {} version {} pcr_pid 0x{:04x}",
                    pmt.program_number, pmt.version_number, pmt.pcr_pid
                );
                for d in pmt.iter_program_descriptors().flatten() {
                    println!("  program descriptor 0x{:02x} {}", d.tag, hex(d.data));
                }
                for e in &pmt.streams {
                    println!(
                        "  stream_type 0x{:02x} pid 0x{:04x}",
                        e.stream_type, e.elementary_pid
                    );
                    for d in e.iter_descriptors().flatten() {
                        println!("    descriptor 0x{:02x} {}", d.tag, hex(d.data));
                    }
                }
            }
            seen.push(section);
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let res = match args.get(1).map(String::as_str) {
        Some("dump") if args.len() >= 3 => dump(&args[2], args.get(3).and_then(|v| v.parse().ok())),
        Some("remux") if args.len() >= 4 => {
            remux(&args[2], &args[3], args.get(4).and_then(|v| v.parse().ok()))
        }
        Some("psi") if args.len() >= 3 => psi(&args[2]),
        _ => {
            eprintln!(
                "usage: tsdump dump <file> [program] | tsdump remux <in> <out.ts> [rate] | tsdump psi <file>"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("tsdump: {e}");
        std::process::exit(1);
    }
}
