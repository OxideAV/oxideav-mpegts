//! Mux / demux throughput on a self-muxed multi-program transport
//! stream.
//!
//! Run with `cargo bench --bench throughput`. Environment knobs:
//!
//! * `MPEGTS_BENCH_FRAMES` — video frames per program (default 900);
//! * `MPEGTS_BENCH_RUNS` — timed repetitions, the median is reported
//!   (default 5);
//! * `MPEGTS_BENCH_DIR` — directory for the on-disk copy used by the
//!   unbuffered-file demux leg (default: the system temp directory);
//! * `MPEGTS_BENCH_KEEP` — when set, the on-disk copy is left behind;
//! * `MPEGTS_BENCH_FILE` — measure on this transport or program stream
//!   (one written by another multiplexer, say) instead of the
//!   self-muxed one: open time, demux throughput, remux throughput of
//!   the first program and, for a transport stream, the median seek.
//!
//! The stream holds four programs, each with one video stream (40 kB
//! frames at 25 Hz) and two MPEG audio streams (576-byte frames), so
//! the demux leg crosses the PID lookup, PES reassembly and audio
//! access-unit splitting paths at a realistic mix.

use std::io::{Cursor, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use oxideav_core::{
    CodecId, CodecParameters, Demuxer, Muxer, Packet, ReadSeek, StreamInfo, TimeBase, WriteSeek,
};
use oxideav_mpegts::demuxer::MpegTsDemuxer;
use oxideav_mpegts::muxer::{MpegTsMuxConfig, MpegTsMuxer, ProgramSpec};

const PROGRAMS: usize = 4;
const VIDEO_FRAME: usize = 40_000;
const AUDIO_FRAME: usize = 576;
/// Audio frames multiplexed with each picture, per audio stream.
const AUDIO_PER_VIDEO: usize = 2;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Cursor<Vec<u8>>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for SharedBuf {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.lock().unwrap().seek(pos)
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn stream(index: u32, codec: &str, video: bool) -> StreamInfo {
    let params = if video {
        CodecParameters::video(CodecId::new(codec))
    } else {
        CodecParameters::audio(CodecId::new(codec))
    };
    StreamInfo {
        index,
        time_base: TimeBase::new(1, 90_000),
        duration: None,
        start_time: None,
        params,
    }
}

/// Deterministic filler that never forms a start code or a sync word.
fn filler(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            0x10 | (x as u8 & 0x6F)
        })
        .collect()
}

/// One MPEG-1 Layer II frame: 48 kHz, 192 kbit/s → 576 bytes.
fn audio_frame(seed: u32) -> Vec<u8> {
    let mut f = filler(seed, AUDIO_FRAME);
    f[..4].copy_from_slice(&[0xFF, 0xFD, 0xA4, 0x00]);
    f
}

/// The packets of the whole stream, in multiplex order.
fn plan(frames: usize) -> (Vec<StreamInfo>, Vec<Packet>) {
    let mut infos = Vec::new();
    for p in 0..PROGRAMS as u32 {
        infos.push(stream(p * 3, "h264", true));
        infos.push(stream(p * 3 + 1, "mp2", false));
        infos.push(stream(p * 3 + 2, "mp2", false));
    }
    let tb = TimeBase::new(1, 90_000);
    let mut packets = Vec::new();
    for k in 0..frames {
        let pts = 90_000 + k as i64 * 3_600;
        for p in 0..PROGRAMS {
            let base = (p * 3) as u32;
            let mut v = Packet::new(base, tb, filler((k * PROGRAMS + p) as u32, VIDEO_FRAME))
                .with_pts(pts)
                .with_dts(pts);
            v.flags.keyframe = k % 25 == 0;
            packets.push(v);
            for a in 0..2usize {
                for j in 0..AUDIO_PER_VIDEO {
                    let slot = p * 2 + a;
                    // Audio stays interleaved with its picture.
                    let apts = pts + (j * 3_600 / AUDIO_PER_VIDEO) as i64;
                    let mut pkt =
                        Packet::new(base + 1 + a as u32, tb, audio_frame((k * 16 + slot) as u32))
                            .with_pts(apts);
                    pkt.flags.keyframe = true;
                    packets.push(pkt);
                }
            }
        }
    }
    (infos, packets)
}

fn mux_config() -> MpegTsMuxConfig {
    let programs = (0..PROGRAMS as u32)
        .map(|p| {
            ProgramSpec::new(p as u16 + 1, 0x0100 + p as u16 * 0x10).with_stream_indices(vec![
                p * 3,
                p * 3 + 1,
                p * 3 + 2,
            ])
        })
        .collect();
    MpegTsMuxConfig::default().with_programs(programs)
}

fn mux_into(out: Box<dyn WriteSeek>, infos: &[StreamInfo], packets: &[Packet]) {
    let mut m = MpegTsMuxer::with_config(out, infos, mux_config()).expect("mux config");
    m.write_header().expect("header");
    for p in packets {
        m.write_packet(p).expect("packet");
    }
    m.write_trailer().expect("trailer");
}

fn mux(infos: &[StreamInfo], packets: &[Packet]) -> Vec<u8> {
    let buf = SharedBuf::default();
    mux_into(Box::new(buf.clone()), infos, packets);
    let mut sink = buf.0.lock().unwrap();
    std::mem::take(sink.get_mut())
}

/// Drain every program; returns `(packets, payload bytes)`.
fn demux(open: &dyn Fn() -> Box<dyn ReadSeek>) -> (usize, usize) {
    let mut n = 0usize;
    let mut bytes = 0usize;
    for p in 0..PROGRAMS as u16 {
        let mut d = MpegTsDemuxer::open_program(open(), p + 1).expect("open");
        while let Ok(pkt) = d.next_packet() {
            n += 1;
            bytes += pkt.data.len();
        }
    }
    (n, bytes)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// The legs on a stream somebody else wrote.
fn foreign(path: &std::path::Path, runs: usize) {
    use oxideav_core::{Demuxer, NullCodecResolver};
    let bytes: Arc<[u8]> = std::fs::read(path).expect("read MPEGTS_BENCH_FILE").into();
    let mib = bytes.len() as f64 / (1 << 20) as f64;
    let program_stream = bytes.starts_with(&[0, 0, 1, 0xBA]);
    let open = |data: &Arc<[u8]>| -> Box<dyn Demuxer> {
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(data.clone()));
        if program_stream {
            oxideav_mpegts::open_ps_demuxer(input, &NullCodecResolver).expect("open")
        } else {
            Box::new(MpegTsDemuxer::new(input).expect("open"))
        }
    };
    println!("stream: {} ({mib:.1} MiB)", path.display());

    let mut opens = Vec::new();
    let mut rates = Vec::new();
    let mut packets = Vec::new();
    let mut infos = Vec::new();
    for _ in 0..runs {
        let t = Instant::now();
        let mut d = open(&bytes);
        opens.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        packets.clear();
        while let Ok(p) = d.next_packet() {
            packets.push(p);
        }
        rates.push(mib / t.elapsed().as_secs_f64());
        infos = d.streams().to_vec();
    }
    let payload: usize = packets.iter().map(|p| p.data.len()).sum();
    println!(
        "open           : {:8.2} ms (median of {runs})",
        median(opens)
    );
    println!(
        "demux (memory) : {:8.1} MiB/s (median of {runs}; {} streams, {} packets, {payload} payload bytes)",
        median(rates),
        infos.len(),
        packets.len()
    );

    let program =
        ProgramSpec::new(1, 0x0100).with_stream_indices(infos.iter().map(|s| s.index).collect());
    let config = MpegTsMuxConfig::default().with_programs(vec![program]);
    let mut rates = Vec::new();
    let mut written = 0usize;
    for _ in 0..runs {
        let buf = SharedBuf::default();
        let t = Instant::now();
        let mut m = MpegTsMuxer::with_config(Box::new(buf.clone()), &infos, config.clone())
            .expect("mux config");
        m.write_header().expect("header");
        for p in &packets {
            m.write_packet(p).expect("packet");
        }
        m.write_trailer().expect("trailer");
        drop(m);
        written = buf.0.lock().unwrap().get_ref().len();
        rates.push(written as f64 / (1 << 20) as f64 / t.elapsed().as_secs_f64());
    }
    println!(
        "remux (memory) : {:8.1} MiB/s (median of {runs}; {written} bytes out)",
        median(rates)
    );

    if program_stream {
        return;
    }
    let mut d = MpegTsDemuxer::new(Box::new(Cursor::new(bytes.clone()))).expect("open");
    let (first, last) = packets
        .iter()
        .filter(|p| p.stream_index == 0)
        .filter_map(|p| p.pts)
        .fold((i64::MAX, i64::MIN), |(lo, hi), t| (lo.min(t), hi.max(t)));
    let mut cold = Vec::new();
    let mut warm = Vec::new();
    for (round, times) in [&mut cold, &mut warm].into_iter().enumerate() {
        for k in 0..200i64 {
            // A fixed scatter over the whole duration.
            let target = first + (last - first) * ((k * 7919 + round as i64 * 13) % 200) / 200;
            let t = Instant::now();
            d.seek_to(0, target).expect("seek");
            let _ = d.next_packet();
            times.push(t.elapsed().as_secs_f64() * 1e6);
        }
    }
    println!(
        "seek + packet  : {:8.1} us first pass, {:.1} us second (median of 200 each)",
        median(cold),
        median(warm)
    );
}

fn main() {
    let frames = env_usize("MPEGTS_BENCH_FRAMES", 900);
    let runs = env_usize("MPEGTS_BENCH_RUNS", 5).max(1);
    if let Some(path) = std::env::var_os("MPEGTS_BENCH_FILE") {
        foreign(std::path::Path::new(&path), runs);
        return;
    }
    let (infos, packets) = plan(frames);
    let es_bytes: usize = packets.iter().map(|p| p.data.len()).sum();

    let mut ts = Vec::new();
    let mut mux_rates = Vec::new();
    for _ in 0..runs {
        let t = Instant::now();
        ts = mux(&infos, &packets);
        mux_rates.push(ts.len() as f64 / (1 << 20) as f64 / t.elapsed().as_secs_f64());
    }
    let mib = ts.len() as f64 / (1 << 20) as f64;
    println!(
        "stream: {PROGRAMS} programs x (1 video + 2 audio), {frames} pictures each, \
         {:.1} MiB elementary, {mib:.1} MiB transport",
        es_bytes as f64 / (1 << 20) as f64
    );
    // FNV-1a over the whole stream: equal across runs and versions
    // whenever the muxer's output is byte-identical.
    let digest = ts.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    println!("stream digest  : {digest:016x}");
    println!(
        "mux (memory)   : {:8.1} MiB/s (median of {runs})",
        median(mux_rates)
    );

    let dir = std::env::var_os("MPEGTS_BENCH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join(format!("oxideav-mpegts-bench-{}.ts", std::process::id()));
    let mut rates = Vec::new();
    for _ in 0..runs {
        let t = Instant::now();
        let file = std::fs::File::create(&path).expect("create bench stream");
        mux_into(Box::new(file), &infos, &packets);
        rates.push(mib / t.elapsed().as_secs_f64());
    }
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        ts,
        "file and memory mux must agree"
    );
    println!(
        "mux (file)     : {:8.1} MiB/s (median of {runs}; unbuffered std::fs::File)",
        median(rates)
    );

    // Each program is demuxed over the whole stream, so the work per
    // run is PROGRAMS passes.
    let passes = PROGRAMS as f64;
    let shared: Arc<[u8]> = ts.into();
    let mut rates = Vec::new();
    let mut seen = (0, 0);
    for _ in 0..runs {
        let t = Instant::now();
        let data = shared.clone();
        seen = demux(&move || Box::new(Cursor::new(data.clone())));
        rates.push(mib * passes / t.elapsed().as_secs_f64());
    }
    println!(
        "demux (memory) : {:8.1} MiB/s (median of {runs}; {} packets, {} payload bytes)",
        median(rates),
        seen.0,
        seen.1
    );
    assert_eq!(seen.1, es_bytes, "demux must return every payload byte");

    let mut rates = Vec::new();
    for _ in 0..runs {
        let t = Instant::now();
        let p = path.clone();
        let got = demux(&move || Box::new(std::fs::File::open(&p).expect("open bench stream")));
        assert_eq!(got, seen);
        rates.push(mib * passes / t.elapsed().as_secs_f64());
    }
    if std::env::var_os("MPEGTS_BENCH_KEEP").is_none() {
        let _ = std::fs::remove_file(&path);
    } else {
        println!("kept {}", path.display());
    }
    println!(
        "demux (file)   : {:8.1} MiB/s (median of {runs}; unbuffered std::fs::File)",
        median(rates)
    );
}
