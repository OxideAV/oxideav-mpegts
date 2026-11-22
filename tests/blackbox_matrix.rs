//! Live matrix against a black-box multiplexer and reader.
//!
//! Needs `ffmpeg` and `ffprobe` on the `PATH`; without them the test
//! prints a note and passes. Everything is generated into a temporary
//! directory that is removed afterwards.
//!
//! **Foreign → ours.** Every case is a file the black-box multiplexer
//! wrote. It is read with the black-box reader (`ffprobe -show_packets
//! -show_data_hash`) and with this crate's demuxers, and per stream
//! (matched by PID for transport streams, by order for program streams)
//! the following must agree:
//!
//! * codec, picture size (codecs whose size this crate reads), sample
//!   rate, channel count, language;
//! * packet count, and per packet: size, payload hash, key-frame flag,
//!   PTS and DTS.
//!
//! Time stamps are compared up to one constant multiple of 2^33 per
//! stream (the reader starts a wrapping stream below zero, this crate
//! above), exactly — except audio at 44.1 / 22.05 / 11.025 kHz, where
//! the frames inside a PES packet are interpolated and the reader
//! accumulates a truncated frame duration (8 ticks allowed). Where the
//! reader reports no time stamp nothing is compared.
//!
//! **Ours → foreign.** Each file is remultiplexed with this crate's
//! writer (unpaced, and at a constant rate) and the black-box reader
//! must report, for the result, the packets it reported for the source,
//! without a warning it did not also give for the source.
//!
//! Cases listed with a `Gap` are streams this crate does not carry and
//! says so in its README; the test pins that they still fail the same
//! way.

#![cfg(feature = "registry")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use oxideav_core::{Demuxer, Error, Muxer, NullCodecResolver, Packet, StreamInfo};
use oxideav_mpegts::demuxer::MpegTsDemuxer;
use oxideav_mpegts::muxer::{MpegTsMuxConfig, MpegTsMuxer, ProgramSpec};

/// What a case is expected to do.
#[derive(Clone, Copy, PartialEq)]
enum Expect {
    /// Demux and remux agree with the black-box reader.
    Match,
    /// Demux agrees; the remux is not attempted (see the note).
    DemuxOnly(&'static str),
    /// Not carried: opening fails or a stream is missing.
    Gap(&'static str),
}

struct Case {
    name: &'static str,
    /// Arguments between the inputs and the output file.
    args: &'static str,
    /// `v` video, `a` audio, `b` second audio — in input order.
    inputs: &'static str,
    expect: Expect,
}

const fn case(name: &'static str, inputs: &'static str, args: &'static str) -> Case {
    Case {
        name,
        args,
        inputs,
        expect: Expect::Match,
    }
}

const fn gap(
    name: &'static str,
    inputs: &'static str,
    args: &'static str,
    why: &'static str,
) -> Case {
    Case {
        name,
        args,
        inputs,
        expect: Expect::Gap(why),
    }
}

#[rustfmt::skip]
fn cases() -> Vec<Case> {
    vec![
        // --- codecs in a transport stream
        case("h264_aac.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a aac -ac 2"),
        case("hevc_ac3.ts", "va", "-c:v libx265 -x265-params log-level=none -g 12 -c:a ac3 -ac 2"),
        case("m2v_mp2.ts", "va", "-c:v mpeg2video -g 12 -bf 2 -c:a mp2 -ac 2"),
        case("m1v_mp3.ts", "va", "-c:v mpeg1video -g 12 -bf 2 -c:a libmp3lame -ac 2"),
        case("m4v_eac3.ts", "va", "-c:v mpeg4 -g 12 -bf 2 -c:a eac3 -ac 2"),
        case("h264_dts.ts", "va", "-c:v libx264 -c:a dca -strict -2 -ac 2"),
        case("h264_latm.ts", "va", "-c:v libx264 -c:a aac -ac 2 -mpegts_flags latm"),
        case("h264_lpcm.m2ts", "va", "-c:v libx264 -c:a pcm_bluray -ac 2 -mpegts_m2ts_mode 1"),
        gap("h264_s302m.ts", "va", "-c:v libx264 -c:a s302m -strict -2 -ac 2",
            "SMPTE 302M audio (registration BSSD): carriage not staged"),
        gap("av1_opus.ts", "va", "-c:v libsvtav1 -svtav1-params lp=1 -g 12 -c:a libopus -ac 2",
            "Opus in a transport stream: carriage not staged; AV1 is written as untyped private data"),
        // --- audio shapes
        case("mp2_mono_44k.ts", "A44100", "-c:a mp2 -ac 1"),
        case("mp2_22k.ts", "A22050", "-c:a mp2"),
        case("mp3_32k.ts", "A32000", "-c:a libmp3lame"),
        case("mp3_24k.ts", "A24000", "-c:a libmp3lame"),
        case("ac3_51.ts", "a", "-c:a ac3 -ac 6"),
        case("eac3_51.ts", "a", "-c:a eac3 -ac 6"),
        case("aac_51.ts", "a", "-c:a aac -ac 6"),
        case("aac_22k_mono.ts", "A22050", "-c:a aac -ac 1"),
        case("latm.ts", "a", "-c:a aac -mpegts_flags latm"),
        case("dts.ts", "a", "-c:a dca -strict -2"),
        case("lpcm.m2ts", "a", "-c:a pcm_bluray -mpegts_m2ts_mode 1"),
        gap("opus.ts", "a", "-c:a libopus", "Opus in a transport stream: carriage not staged"),
        // --- video shapes
        case("h264_1080.ts", "V1920x1080@30000/1001", "-c:v libx264 -preset ultrafast"),
        case("h264_odd_444.ts", "V322x242@25", "-c:v libx264 -pix_fmt yuv444p"),
        case("m4v_qcif.ts", "V176x144@15", "-c:v mpeg4"),
        case("hevc.ts", "v", "-c:v libx265 -x265-params log-level=none"),
        case("h264_1frame.ts", "v", "-frames:v 1 -c:v libx264"),
        case("m2v_long.ts", "V320x240@50", "-c:v mpeg2video -b:v 3M -g 25"),
        // --- layouts
        case("m2ts.m2ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_m2ts_mode 1"),
        case("pcr20.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pcr_period 20"),
        case("pcr100.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pcr_period 100"),
        case("tables_fast.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pat_period 0.1 -sdt_period 0.2"),
        case("tables_slow.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pat_period 2 -sdt_period 5"),
        case("resend_headers.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_flags resend_headers"),
        case("system_b.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_flags system_b"),
        case("initial_discontinuity.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_flags initial_discontinuity"),
        case("tables_at_frames.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_flags pat_pmt_at_frames"),
        case("nit.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_flags nit"),
        case("no_indicator.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_flags omit_rai"),
        case("cbr_2m.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -muxrate 2000000"),
        case("cbr_800k.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -muxrate 800000"),
        case("pes_one_frame.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pes_payload_size 0"),
        case("pes_16k.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pes_payload_size 16000"),
        case("pes_300.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -pes_payload_size 300"),
        case("aac_pes_one_frame.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a aac -pes_payload_size 0"),
        case("ac3_pes_8k.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a ac3 -pes_payload_size 8000"),
        case("wrap.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -output_ts_offset 95440"),
        case("start_1h.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -output_ts_offset 3600"),
        case("pids.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -mpegts_start_pid 0x200 -mpegts_pmt_start_pid 0x1f00 -mpegts_transport_stream_id 0x1234 -mpegts_service_id 0x777"),
        case("no_delay.ts", "va", "-c:v libx264 -g 12 -bf 2 -c:a mp2 -ac 2 -flush_packets 1 -max_delay 0"),
        case("languages.ts", "vab", "-map 0 -map 1 -map 2 -c:v libx264 -g 12 -c:a:0 mp2 -c:a:1 ac3 -metadata:s:a:0 language=eng -metadata:s:a:1 language=fra"),
        case("two_programs.ts", "vab", "-map 0 -map 1 -map 0 -map 2 -c:v mpeg2video -g 12 -c:a mp2 -program program_num=1:title=one:st=0:st=1 -program program_num=2:title=two:st=2:st=3"),
        case("audio_only.ts", "a", "-c:a mp2"),
        case("video_only.ts", "v", "-c:v libx264 -g 12"),
        // --- program streams
        case("vob.vob", "va", "-c:v mpeg2video -g 12 -bf 2 -c:a mp2 -f vob"),
        case("dvd.mpg", "va", "-c:v mpeg2video -g 12 -bf 2 -c:a ac3 -f dvd"),
        case("svcd.mpg", "va", "-c:v mpeg2video -g 12 -bf 2 -s 480x576 -c:a mp2 -f svcd"),
        case("h264_ac3.vob", "va", "-c:v libx264 -g 12 -c:a ac3 -f vob"),
        Case {
            name: "lpcm.vob", inputs: "va", args: "-c:v mpeg2video -g 12 -c:a pcm_s16be -f vob",
            expect: Expect::DemuxOnly(
                "program-stream LPCM leaves as headerless samples; the transport-stream \
                 LPCM stream_type is the Blu-ray framing, whose header is not staged"),
        },
        case("dts.vob", "va", "-c:v mpeg2video -g 12 -c:a dca -strict -2 -f vob"),
        case("m1v.vob", "va", "-c:v mpeg1video -g 12 -c:a mp2 -f vob"),
        case("two_audio.vob", "vab", "-map 0 -map 1 -map 2 -c:v mpeg2video -c:a:0 mp2 -c:a:1 ac3 -f vob"),
        case("m4v_mp3.vob", "va", "-c:v mpeg4 -c:a libmp3lame -f vob"),
        gap("mpeg1_system.mpg", "va", "-c:v mpeg1video -c:a mp2 -f mpeg",
            "ISO/IEC 11172-1 system stream: not staged"),
    ]
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Write one case with the black-box multiplexer. `false` when the
/// installed build cannot (a missing encoder).
fn generate(dir: &Path, c: &Case) -> bool {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-hide_banner", "-loglevel", "error", "-y"]);
    let mut rest = c.inputs;
    while let Some(kind) = rest.chars().next() {
        rest = &rest[1..];
        let spec_end = rest.find(['v', 'a', 'b', 'V', 'A']).unwrap_or(rest.len());
        let (spec, tail) = rest.split_at(spec_end);
        rest = tail;
        let source = match kind {
            'v' => "testsrc2=s=320x240:r=25".to_string(),
            'V' => {
                let (size, rate) = spec.split_once('@').expect("size@rate");
                format!("testsrc2=s={size}:r={rate}")
            }
            'a' => "sine=f=440:r=48000".to_string(),
            'A' => format!("sine=f=440:r={spec}"),
            _ => "sine=f=880:r=44100".to_string(),
        };
        let seconds = if c.name == "m2v_long.ts" { "8" } else { "2" };
        cmd.args(["-f", "lavfi", "-i", &source, "-t", seconds]);
    }
    cmd.args(c.args.split_whitespace());
    cmd.arg(dir.join(c.name));
    cmd.output().is_ok_and(|o| o.status.success()) && dir.join(c.name).exists()
}

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

/// One packet as either side reports it.
#[derive(Debug, Clone, PartialEq)]
struct Row {
    pts: Option<i64>,
    dts: Option<i64>,
    key: bool,
    size: usize,
    hash: u32,
}

#[derive(Debug, Clone, Default)]
struct Track {
    id: u32,
    codec: String,
    width: Option<u32>,
    height: Option<u32>,
    sample_rate: Option<u32>,
    channels: Option<u16>,
    language: Option<String>,
    rows: Vec<Row>,
}

/// The black-box reader's view of a file, plus what it wrote to stderr.
fn reader_view(path: &Path) -> (Vec<Track>, String) {
    let out = Command::new("ffprobe")
        .args(["-v", "error", "-show_data_hash", "adler32", "-show_entries"])
        .arg(
            "packet=stream_index,pts,dts,flags,size,data_hash:\
             stream=index,id,codec_name,width,height,sample_rate,channels:stream_tags=language",
        )
        .args(["-of", "compact=nk=0"])
        .arg(path)
        .output()
        .expect("ffprobe runs");
    let mut tracks: BTreeMap<u32, Track> = BTreeMap::new();
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.strip_prefix("program|").unwrap_or(line);
        let mut fields = line.split('|');
        let section = fields.next().unwrap_or("");
        let kv: BTreeMap<&str, &str> = fields.filter_map(|f| f.split_once('=')).collect();
        let num = |k: &str| kv.get(k).and_then(|v| v.parse::<i64>().ok());
        match section {
            "stream" => {
                let Some(index) = num("index") else { continue };
                let t = tracks.entry(index as u32).or_default();
                t.id = kv
                    .get("id")
                    .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0);
                t.codec = kv.get("codec_name").unwrap_or(&"").to_string();
                t.width = num("width").map(|v| v as u32);
                t.height = num("height").map(|v| v as u32);
                t.sample_rate = num("sample_rate").map(|v| v as u32);
                t.channels = num("channels").map(|v| v as u16);
                t.language = kv.get("tag:language").map(|v| v.to_string());
            }
            "packet" => {
                let Some(index) = num("stream_index") else {
                    continue;
                };
                let hash = kv
                    .get("data_hash")
                    .and_then(|v| v.rsplit(':').next())
                    .and_then(|v| u32::from_str_radix(v, 16).ok())
                    .unwrap_or(0);
                tracks.entry(index as u32).or_default().rows.push(Row {
                    pts: num("pts"),
                    dts: num("dts"),
                    key: kv.get("flags").is_some_and(|f| f.starts_with('K')),
                    size: num("size").unwrap_or(0) as usize,
                    hash,
                });
            }
            _ => {}
        }
    }
    // A stream the reader lists and never delivers a packet for (DVD
    // navigation packs) is not compared.
    let tracks = tracks
        .into_values()
        .filter(|t| !t.rows.is_empty())
        .collect();
    (tracks, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn is_program_stream(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|b| b.starts_with(&[0, 0, 1, 0xBA]))
}

fn drain(d: &mut dyn Demuxer) -> Result<Vec<Packet>, Error> {
    let mut out = Vec::new();
    loop {
        match d.next_packet() {
            Ok(p) => out.push(p),
            Err(Error::Eof) => return Ok(out),
            Err(e) => return Err(e),
        }
    }
}

fn tracks_of(streams: &[StreamInfo], ids: &[u32], packets: &[Packet]) -> Vec<Track> {
    let mut tracks: Vec<Track> = streams
        .iter()
        .zip(ids)
        .map(|(s, &id)| Track {
            id,
            codec: s.params.codec_id.as_str().to_string(),
            width: s.params.width,
            height: s.params.height,
            sample_rate: s.params.sample_rate,
            channels: s.params.channels,
            language: s.params.language.clone(),
            rows: Vec::new(),
        })
        .collect();
    for p in packets {
        tracks[p.stream_index as usize].rows.push(Row {
            pts: p.pts,
            dts: p.dts,
            key: p.flags.keyframe,
            size: p.data.len(),
            hash: adler32(&p.data),
        });
    }
    tracks
}

/// This crate's view: every program of a transport stream (streams
/// carry their PID), or the streams of a program stream (id 0).
fn our_view(path: &Path) -> Result<Vec<Track>, Error> {
    let open = || -> Result<Box<std::fs::File>, Error> { Ok(Box::new(std::fs::File::open(path)?)) };
    if is_program_stream(path) {
        let mut d = oxideav_mpegts::open_ps_demuxer(open()?, &NullCodecResolver)?;
        let packets = drain(d.as_mut())?;
        let ids = vec![0; d.streams().len()];
        return Ok(tracks_of(d.streams(), &ids, &packets));
    }
    let programs: Vec<u16> = MpegTsDemuxer::new(open()?)?
        .programs()
        .iter()
        .map(|p| p.program_number)
        .collect();
    let mut all = Vec::new();
    for number in programs {
        let mut d = MpegTsDemuxer::open_program(open()?, number)?;
        let packets = drain(&mut d)?;
        let ids: Vec<u32> = (0..d.streams().len() as u32)
            .map(|i| u32::from(d.pmt_entry(i).expect("entry").elementary_pid))
            .collect();
        all.extend(tracks_of(d.streams(), &ids, &packets));
    }
    Ok(all)
}

/// The name this crate gives the codec the reader calls `name`.
fn our_codec_name(name: &str) -> &str {
    match name {
        "hevc" => "h265",
        "mpeg4" => "mpeg4video",
        "vvc" => "h266",
        // Linear PCM: this crate has one id for the samples whatever
        // the carriage.
        "pcm_bluray" | "pcm_dvd" => "pcm_s16be",
        other => other,
    }
}

/// Compare the packets of one stream. `strict_source` is `false` when
/// `theirs` is the reader's view of a source file whose missing time
/// stamps the other side may fill in.
fn compare_rows(
    label: &str,
    codec: &str,
    rate: Option<u32>,
    theirs: &[Row],
    ours: &[Row],
) -> Vec<String> {
    let mut problems = Vec::new();
    if theirs.len() != ours.len() {
        problems.push(format!(
            "{label}: {} packets, reader has {}",
            ours.len(),
            theirs.len()
        ));
    }
    let tolerance = match rate {
        Some(44_100 | 22_050 | 11_025) => 8,
        _ => 0,
    };
    const WRAP: i64 = 1 << 33;
    let mut offset: Option<i64> = None;
    let mut bad = 0usize;
    for (k, (t, o)) in theirs.iter().zip(ours).enumerate() {
        // The reader repeats the previous DTS-audio time stamp once in
        // a while; the frames are evenly spaced.
        if codec == "dts" && theirs.get(k + 1).is_some_and(|n| n.pts == t.pts) {
            continue;
        }
        let mut what = Vec::new();
        // DVD LPCM: the reader keeps three header bytes with each
        // packet, this crate hands out the samples.
        let dvd_lpcm = codec == "pcm_dvd" && t.size == o.size + 3;
        if !dvd_lpcm && (t.size != o.size || t.hash != o.hash) {
            what.push("payload");
        }
        if t.key != o.key {
            what.push("key");
        }
        if offset.is_none()
            && let (Some(a), Some(b)) = (t.pts, o.pts)
        {
            offset = Some(if (b - a) % WRAP == 0 { b - a } else { 0 });
        }
        for (name, a, b) in [("pts", t.pts, o.pts), ("dts", t.dts, o.dts)] {
            match (a, b) {
                (None, _) => {}
                (Some(_), None) => what.push(name),
                (Some(a), Some(b)) => {
                    if (b - a - offset.unwrap_or(0)).abs() > tolerance {
                        what.push(name);
                    }
                }
            }
        }
        if !what.is_empty() {
            bad += 1;
            if bad <= 3 {
                problems.push(format!(
                    "{label} packet {k}: {what:?} reader {t:?} ours {o:?}"
                ));
            }
        }
    }
    if bad > 3 {
        problems.push(format!("{label}: {bad} packets differ"));
    }
    problems
}

/// Foreign → ours.
fn compare_demux(path: &Path) -> Vec<String> {
    let (theirs, _) = reader_view(path);
    let ours = match our_view(path) {
        Ok(t) => t,
        Err(e) => return vec![format!("open: {e}")],
    };
    let ps = is_program_stream(path);
    let mut problems = Vec::new();
    if theirs.len() != ours.len() {
        problems.push(format!(
            "streams: reader {:?}, ours {:?}",
            theirs.iter().map(|t| t.codec.as_str()).collect::<Vec<_>>(),
            ours.iter().map(|t| t.codec.as_str()).collect::<Vec<_>>()
        ));
    }
    for (n, t) in theirs.iter().enumerate() {
        let o = if ps {
            ours.get(n)
        } else {
            ours.iter().find(|o| o.id == t.id)
        };
        let Some(o) = o else {
            problems.push(format!("stream {:#x} ({}) missing", t.id, t.codec));
            continue;
        };
        let label = format!("{} {:#x}", t.codec, t.id);
        if our_codec_name(&t.codec) != o.codec {
            problems.push(format!("{label}: codec {}", o.codec));
        }
        // Picture size: read from the headers of these codecs only.
        if matches!(o.codec.as_str(), "h264" | "mpeg1video" | "mpeg2video")
            && (t.width, t.height) != (o.width, o.height)
        {
            problems.push(format!("{label}: size {:?}x{:?}", o.width, o.height));
        }
        // Blu-ray LPCM: its header is not staged, no parameters.
        if t.sample_rate.is_some()
            && t.codec != "pcm_bluray"
            && (t.sample_rate, t.channels) != (o.sample_rate, o.channels)
        {
            problems.push(format!(
                "{label}: audio {:?} / {:?}",
                o.sample_rate, o.channels
            ));
        }
        if t.language != o.language {
            problems.push(format!("{label}: language {:?}", o.language));
        }
        // Program streams: presentation times of reordered pictures
        // without a coded PTS are derived for MPEG-1/2 only.
        let mut ours_rows = o.rows.clone();
        if ps && matches!(o.codec.as_str(), "mpeg4video" | "h264") {
            for (r, t) in ours_rows.iter_mut().zip(&t.rows) {
                r.pts = r.pts.or(t.pts);
            }
        }
        problems.extend(compare_rows(
            &label,
            &t.codec,
            t.sample_rate,
            &t.rows,
            &ours_rows,
        ));
    }
    problems
}

/// Remultiplex the first program of `src` into `dst` with this crate.
fn remux(src: &Path, dst: &Path, rate: Option<u64>) -> Result<(), Error> {
    let open = || -> Result<Box<std::fs::File>, Error> { Ok(Box::new(std::fs::File::open(src)?)) };
    let mut descriptors = Vec::new();
    let mut demuxer: Box<dyn Demuxer> = if is_program_stream(src) {
        oxideav_mpegts::open_ps_demuxer(open()?, &NullCodecResolver)?
    } else {
        let d = MpegTsDemuxer::new(open()?)?;
        for s in d.streams() {
            descriptors.push((
                s.index,
                d.pmt_entry(s.index).expect("entry").descriptors.clone(),
            ));
        }
        Box::new(d)
    };
    let streams = demuxer.streams().to_vec();
    let mut packets = drain(demuxer.as_mut())?;
    if rate.is_some() {
        // The paced writer takes frames in decoding order.
        let mut last = 0;
        let mut keyed: Vec<(i64, Packet)> = packets
            .into_iter()
            .map(|p| {
                last = p.dts.or(p.pts).unwrap_or(last);
                (last, p)
            })
            .collect();
        keyed.sort_by_key(|&(t, _)| t);
        packets = keyed.into_iter().map(|(_, p)| p).collect();
    }
    let program = ProgramSpec::new(1, 0x0100)
        .with_stream_indices(streams.iter().map(|s| s.index).collect())
        .with_es_descriptors(descriptors);
    let config = MpegTsMuxConfig::default().with_programs(vec![program]);
    let mut mux =
        MpegTsMuxer::with_config(Box::new(std::fs::File::create(dst)?), &streams, config)?;
    mux.set_mux_rate(rate);
    mux.write_header()?;
    for p in &packets {
        mux.write_packet(p)?;
    }
    mux.write_trailer()
}

/// Warnings the black-box reader gives while copying every packet.
fn reader_warnings(path: &Path) -> Vec<String> {
    let out = Command::new("ffmpeg")
        .args(["-v", "warning", "-i"])
        .arg(path)
        .args(["-map", "0", "-c", "copy", "-f", "null", "-"])
        .output()
        .expect("ffmpeg runs");
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.contains("Last message repeated"))
        .map(|l| {
            // Drop the instance address: `[h264 @ 0x...]`.
            match (l.find(" @ 0x"), l.find(']')) {
                (Some(a), Some(b)) if a < b => format!("{}{}", &l[..a], &l[b..]),
                _ => l.to_string(),
            }
        })
        .collect()
}

/// Ours → foreign: the reader's view of the remux against its view of
/// the source (first program).
fn compare_remux(src: &Path, dst: &Path, rate: Option<u64>) -> Vec<String> {
    if let Err(e) = remux(src, dst, rate) {
        return vec![format!("remux: {e}")];
    }
    let (source, _) = reader_view(src);
    let (result, _) = reader_view(dst);
    // The remux holds the first program: the streams this crate opens
    // by default, in order.
    let wanted: Vec<Track> = if is_program_stream(src) {
        source
    } else {
        let first = MpegTsDemuxer::new(Box::new(std::fs::File::open(src).unwrap())).unwrap();
        (0..first.streams().len() as u32)
            .filter_map(|i| {
                let pid = u32::from(first.pmt_entry(i)?.elementary_pid);
                source.iter().find(|t| t.id == pid).cloned()
            })
            .collect()
    };
    let mut problems = Vec::new();
    let known = reader_warnings(src);
    for w in reader_warnings(dst) {
        if !known.contains(&w) {
            problems.push(format!("reader warning: {w}"));
            break;
        }
    }
    if wanted.len() != result.len() {
        problems.push(format!(
            "streams: source {:?}, remux {:?}",
            wanted.iter().map(|t| t.codec.as_str()).collect::<Vec<_>>(),
            result.iter().map(|t| t.codec.as_str()).collect::<Vec<_>>()
        ));
    }
    for (t, o) in wanted.iter().zip(&result) {
        let label = format!("remux {}", t.codec);
        if t.codec != o.codec
            || (t.width, t.height, t.sample_rate, t.channels, &t.language)
                != (o.width, o.height, o.sample_rate, o.channels, &o.language)
        {
            problems.push(
                format!("{label}: parameters {o:?}")
                    .chars()
                    .take(300)
                    .collect(),
            );
        }
        // A program stream source: the reader sees more time stamps in
        // the remux than in the source, never fewer.
        problems.extend(compare_rows(
            &label,
            &t.codec,
            t.sample_rate,
            &t.rows,
            &o.rows,
        ));
    }
    problems
}

/// Damage injected into a foreign transport stream: a lost packet, a
/// flagged packet and a broken sync byte cost the PES packets they hit
/// and nothing else.
fn damage_is_contained(path: &Path, dir: &Path) -> Vec<String> {
    let clean = std::fs::read(path).unwrap();
    let packets = clean.len() / 188;
    let reference = our_view(path).unwrap();
    let mut problems = Vec::new();
    for (name, edit) in [
        ("lost packet", 0u8),
        ("transport_error_indicator", 1),
        ("sync byte", 2),
    ] {
        let mut bytes = clean.clone();
        // A video packet in the middle of the file.
        let Some(at) = (packets / 2..packets).find(|&k| {
            let p = &clean[k * 188..];
            ((u16::from(p[1] & 0x1F) << 8) | u16::from(p[2])) == reference[0].id as u16
                && p[1] & 0x40 == 0
        }) else {
            return vec!["no continuation packet to damage".into()];
        };
        match edit {
            0 => {
                bytes.drain(at * 188..(at + 1) * 188);
            }
            1 => bytes[at * 188 + 1] |= 0x80,
            _ => bytes[at * 188] = 0x00,
        }
        let damaged = dir.join("damaged.ts");
        std::fs::write(&damaged, &bytes).unwrap();
        let got = match our_view(&damaged) {
            Ok(g) => g,
            Err(e) => {
                problems.push(format!("{name}: {e}"));
                continue;
            }
        };
        for (r, g) in reference.iter().zip(&got) {
            let missing = r.rows.iter().filter(|row| !g.rows.contains(row)).count();
            let limit = if r.id == reference[0].id { 2 } else { 0 };
            if missing > limit {
                problems.push(format!(
                    "{name}: stream {:#x} lost {missing} of {} packets",
                    r.id,
                    r.rows.len()
                ));
            }
        }
    }
    problems
}

/// Seeking in a foreign stream lands on a key frame at or before the
/// target and the next video packet is that key frame.
fn seek_lands_on_keyframes(path: &Path) -> Vec<String> {
    let mut d = MpegTsDemuxer::new(Box::new(std::fs::File::open(path).unwrap())).unwrap();
    let all = drain(&mut d).unwrap();
    let video: Vec<&Packet> = all.iter().filter(|p| p.stream_index == 0).collect();
    let keys: Vec<i64> = video
        .iter()
        .filter(|p| p.flags.keyframe)
        .filter_map(|p| p.pts)
        .collect();
    let mut problems = Vec::new();
    if keys.len() < 3 {
        return vec![format!("only {} key frames", keys.len())];
    }
    for (k, &target) in keys.iter().enumerate().skip(1) {
        // Just before the next key frame: must land on this one.
        let ask = keys.get(k + 1).map_or(target + 1000, |n| n - 1);
        match d.seek_to(0, ask) {
            Ok(_) => {
                let next = loop {
                    match d.next_packet() {
                        Ok(p) if p.stream_index == 0 => break Some(p),
                        Ok(_) => {}
                        Err(_) => break None,
                    }
                };
                match next {
                    Some(p) if p.pts == Some(target) && p.flags.keyframe => {}
                    other => problems.push(format!(
                        "seek to {ask}: next video packet {:?}, wanted the key frame at {target}",
                        other.map(|p| (p.pts, p.flags.keyframe))
                    )),
                }
            }
            Err(e) => problems.push(format!("seek to {ask}: {e}")),
        }
    }
    problems
}

#[test]
fn foreign_streams_match_the_black_box_reader() {
    if !have("ffmpeg") || !have("ffprobe") {
        eprintln!("blackbox_matrix: ffmpeg / ffprobe not found, skipped");
        return;
    }
    let dir: PathBuf =
        std::env::temp_dir().join(format!("oxideav-mpegts-matrix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut failures: Vec<String> = Vec::new();
    let (mut demux_total, mut demux_ok, mut remux_total, mut remux_ok) = (0, 0, 0, 0);
    let (mut gaps, mut skipped) = (0, 0);
    for c in cases() {
        if !generate(&dir, &c) {
            // An encoder this build of the black box lacks.
            skipped += 1;
            continue;
        }
        let path = dir.join(c.name);
        let problems = compare_demux(&path);
        if let Expect::Gap(why) = c.expect {
            gaps += 1;
            if problems.is_empty() {
                failures.push(format!("{}: listed as a gap ({why}) and matches", c.name));
            }
            continue;
        }
        demux_total += 1;
        if problems.is_empty() {
            demux_ok += 1;
        } else {
            failures.extend(problems.iter().map(|p| format!("{}: {p}", c.name)));
        }
        if matches!(c.expect, Expect::DemuxOnly(_)) {
            continue;
        }
        // The two high-rate cases get a paced rate above their own.
        let paced = if matches!(c.name, "m2v_long.ts" | "h264_1080.ts") {
            40_000_000
        } else {
            6_000_000
        };
        let rates = [None, Some(paced)];
        for rate in rates {
            remux_total += 1;
            let out = dir.join("remux.ts");
            let problems = compare_remux(&path, &out, rate);
            if problems.is_empty() {
                remux_ok += 1;
            } else {
                failures.extend(
                    problems
                        .iter()
                        .map(|p| format!("{} (rate {rate:?}): {p}", c.name)),
                );
            }
        }
    }

    // Layout variations cut from generated files.
    let base = dir.join("resend_headers.ts");
    if base.exists() {
        let bytes = std::fs::read(&base).unwrap();
        for (name, cut) in [
            ("cut mid-packet", 20_077usize),
            ("cut mid-stream", 600 * 188),
        ] {
            let path = dir.join("cut.ts");
            std::fs::write(&path, &bytes[cut.min(bytes.len())..]).unwrap();
            demux_total += 1;
            let problems = compare_demux(&path);
            if problems.is_empty() {
                demux_ok += 1;
            } else {
                failures.extend(problems.iter().map(|p| format!("{name}: {p}")));
            }
        }
        // 204-byte packets: the same stream with 16 trailer bytes.
        let mut wide = Vec::with_capacity(bytes.len() / 188 * 204);
        for packet in bytes.as_chunks::<188>().0 {
            wide.extend_from_slice(packet);
            wide.extend_from_slice(&[0xA5; 16]);
        }
        let path = dir.join("wide.ts");
        std::fs::write(&path, &wide).unwrap();
        demux_total += 1;
        match (our_view(&base), our_view(&path)) {
            (Ok(a), Ok(b)) if a.iter().map(|t| &t.rows).eq(b.iter().map(|t| &t.rows)) => {
                demux_ok += 1
            }
            _ => failures.push("204-byte packets: differs from the 188-byte stream".into()),
        }
        failures.extend(
            damage_is_contained(&base, &dir)
                .into_iter()
                .map(|p| format!("damage: {p}")),
        );
    }
    let long = dir.join("m2v_long.ts");
    if long.exists() {
        failures.extend(
            seek_lands_on_keyframes(&long)
                .into_iter()
                .map(|p| format!("seek: {p}")),
        );
    }

    // Codecs the black box cannot be made to write here: this crate
    // writes them, the reader must name them.
    {
        use oxideav_core::{CodecId, CodecParameters, TimeBase};
        let tb = TimeBase::new(1, 90_000);
        let mut params = vec![
            CodecParameters::video(CodecId::new("h264")),
            CodecParameters::subtitle(CodecId::new("dvb_subtitle")),
            CodecParameters::subtitle(CodecId::new("dvb_teletext")),
        ];
        params[1].language = Some("eng".into());
        let streams: Vec<StreamInfo> = params
            .into_iter()
            .enumerate()
            .map(|(i, params)| StreamInfo {
                index: i as u32,
                time_base: tb,
                duration: None,
                start_time: None,
                params,
            })
            .collect();
        let path = dir.join("own.ts");
        let mut mux =
            oxideav_mpegts::open_muxer(Box::new(std::fs::File::create(&path).unwrap()), &streams)
                .unwrap();
        mux.write_header().unwrap();
        for k in 0..10i64 {
            for s in 0..3u32 {
                let data = match s {
                    // An access unit delimiter and an IDR slice start.
                    0 => vec![0, 0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x65, 0x88, 0x84, 0x00],
                    // EN 300 743 PES data: data_identifier,
                    // subtitle_stream_id, end_of_PES_data_field_marker.
                    1 => vec![0x20, 0x00, 0xFF],
                    _ => vec![0x10; 46],
                };
                let mut p = Packet::new(s, tb, data).with_pts(90_000 + k * 3600);
                p.flags.keyframe = true;
                mux.write_packet(&p).unwrap();
            }
        }
        mux.write_trailer().unwrap();
        drop(mux);
        let out = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name:stream_tags=language",
            ])
            .args(["-of", "csv=p=0"])
            .arg(&path)
            .output()
            .unwrap();
        let named = String::from_utf8_lossy(&out.stdout).replace(['\r', '\n'], " ");
        for want in ["h264", "dvb_subtitle,eng", "dvb_teletext"] {
            if !named.contains(want) {
                failures.push(format!("own stream: reader names {named:?}, wanted {want}"));
            }
        }
    }

    // A second black-box reader plays what this crate wrote.
    if have("mpv") {
        for name in ["h264_aac.ts", "m2v_mp2.ts", "vob.vob"] {
            let (src, out) = (dir.join(name), dir.join("play.ts"));
            if src.exists() && remux(&src, &out, None).is_ok() {
                let ok = Command::new("mpv")
                    .args(["--no-config", "--vo=null", "--ao=null", "--frames=20"])
                    .arg(&out)
                    .output()
                    .is_ok_and(|o| o.status.success());
                if !ok {
                    failures.push(format!("mpv did not play the remux of {name}"));
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "blackbox_matrix: demux {demux_ok}/{demux_total}, remux {remux_ok}/{remux_total}, \
         {gaps} documented gaps, {skipped} cases the black box could not write"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
