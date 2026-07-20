//! Round-trip seek validation: streams built by this crate's own
//! muxer (PCR insertion + §2.4.3.5 `random_access_indicator` on
//! keyframe PES starts) are demuxed and seeked, so target-vs-landed
//! accuracy is exactly measurable against the known mux timeline.

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use oxideav_core::{
    CodecId, CodecParameters, Demuxer, Muxer, Packet, ReadSeek, StreamInfo, TimeBase,
};

use crate::demuxer::MpegTsDemuxer;
use crate::muxer::{MpegTsMuxConfig, MpegTsMuxer, ProgramSpec};

fn stream_info(idx: u32, codec_id: &str, is_video: bool) -> StreamInfo {
    let params = if is_video {
        CodecParameters::video(CodecId::new(codec_id))
    } else {
        CodecParameters::audio(CodecId::new(codec_id))
    };
    StreamInfo {
        index: idx,
        time_base: TimeBase::new(1, 90_000),
        duration: None,
        start_time: None,
        params,
    }
}

/// Shared in-memory sink shaped as `Box<dyn WriteSeek + 'static>`; the
/// muxer owns its writer, so tests keep an `Arc` clone to extract the
/// bytes afterwards.
#[derive(Clone)]
struct SharedSink(Arc<Mutex<Cursor<Vec<u8>>>>);

impl SharedSink {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Cursor::new(Vec::new()))))
    }
    fn into_bytes(self) -> Vec<u8> {
        Arc::try_unwrap(self.0)
            .map_err(|_| "shared sink still has live references")
            .unwrap()
            .into_inner()
            .unwrap()
            .into_inner()
    }
}

impl std::io::Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}
impl std::io::Seek for SharedSink {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.lock().unwrap().seek(pos)
    }
}

/// Mux `frames` video packets on one h264 stream: PTS starts at
/// `pts0` and steps `step` ticks; every `gop`-th packet is
/// keyframe-flagged (→ §2.4.3.5 indicator on the wire). `payload_len`
/// maps a frame index to its packet size, so VBR byte layouts are one
/// closure away.
fn mux_video(
    pts0: i64,
    frames: i64,
    step: i64,
    gop: i64,
    payload_len: impl Fn(i64) -> usize,
) -> Vec<u8> {
    let streams = vec![stream_info(0, "h264", true)];
    let sink = SharedSink::new();
    {
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
        let mut mx = MpegTsMuxer::with_config(
            output,
            &streams,
            MpegTsMuxConfig {
                transport_stream_id: 1,
                original_network_id: 1,
                programs: vec![ProgramSpec {
                    program_number: 1,
                    pmt_pid: 0x0100,
                    pcr_pid: None,
                    stream_indices: vec![0],
                    service: None,
                    events: Vec::new(),
                    es_descriptors: Vec::new(),
                }],
                network: None,
            },
        )
        .expect("mux open");
        mx.write_header().expect("hdr");
        for i in 0..frames {
            let pts = pts0 + i * step;
            let pkt = Packet::new(0, TimeBase::new(1, 90_000), vec![0xA5u8; payload_len(i)])
                .with_pts(pts)
                .with_keyframe(i % gop == 0);
            mx.write_packet(&pkt).expect("packet");
        }
        mx.write_trailer().expect("trailer");
    }
    sink.into_bytes()
}

/// Sweep seeks across a self-muxed CBR-ish stream and measure the
/// target-vs-landed delta against the known keyframe grid: the landing
/// must be EXACTLY the last keyframe at or before each target, and the
/// demuxed packet at the landing must be that keyframe.
#[test]
fn roundtrip_seek_accuracy_sweep_lands_on_keyframe_grid() {
    // 300 frames at 25 fps (3_600 ticks), keyframe every 12 →
    // keyframe grid 43_200 ticks (0.48 s); PTS 0..1_076_400.
    let (pts0, frames, step, gop) = (0i64, 300i64, 3_600i64, 12i64);
    let bytes = mux_video(pts0, frames, step, gop, |_| 512);
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    let mut dmx = MpegTsDemuxer::open_program(input, 1).expect("open");

    let kf_grid = step * gop;
    let last_kf = ((frames - 1) / gop) * kf_grid;
    let mut max_delta = 0i64;
    // Targets: exact keyframes, mid-GOP, first/last frame, past-end.
    for target in [
        0,
        1,
        step,
        kf_grid - 1,
        kf_grid,
        kf_grid + step,
        123_456,
        250_000,
        499_999,
        500_000,
        743_999,
        864_000,
        1_000_000,
        1_076_400,
        2_000_000,
    ] {
        let expect = (target / kf_grid * kf_grid).min(last_kf);
        let landed = dmx.seek_to(0, target).expect("seek");
        assert_eq!(landed, expect, "target {target}");
        let pkt = dmx.next_packet().expect("PES at landing");
        assert_eq!(pkt.pts, Some(expect), "landing PES PTS, target {target}");
        assert!(pkt.flags.keyframe, "landing must be a keyframe");
        max_delta = max_delta.max(target.min(last_kf) - landed);
    }
    // Accuracy bound: within one GOP of every in-range target.
    assert!(
        max_delta < kf_grid,
        "worst delta {max_delta} ≥ GOP {kf_grid}"
    );
}

/// A wildly VBR byte layout (frame sizes 64 B .. ~24 KiB) breaks any
/// byte-linear time assumption; the PCR bisection + window scan must
/// still land exactly.
#[test]
fn roundtrip_seek_exact_on_vbr_mux() {
    let (pts0, frames, step, gop) = (900i64, 240i64, 3_600i64, 24i64);
    let bytes = mux_video(pts0, frames, step, gop, |i| {
        if i % 24 == 0 {
            24 * 1024 // fat keyframes
        } else if i % 7 == 0 {
            64
        } else {
            (i as usize * 131) % 4096 + 32
        }
    });
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    let mut dmx = MpegTsDemuxer::open_program(input, 1).expect("open");

    let kf_grid = step * gop; // 86_400
    let last_kf = pts0 + ((frames - 1) / gop) * kf_grid;
    for target in [pts0, 90_000, 180_000, 431_999, 432_000, 700_000, 860_000] {
        let expect = (pts0 + (target - pts0).max(0) / kf_grid * kf_grid).min(last_kf);
        let landed = dmx.seek_to(0, target).expect("seek");
        assert_eq!(landed, expect, "target {target}");
        let pkt = dmx.next_packet().expect("PES");
        assert_eq!(pkt.pts, Some(expect));
        assert!(pkt.flags.keyframe);
    }
}

/// Two programs with distinct PCR PIDs and disjoint timelines: seeking
/// the demuxer opened on program 2 must bisect along program 2's
/// PCR_PID and land on program 2's keyframes — program 1's timeline
/// (5 000 000 ticks away) would land wildly elsewhere.
#[test]
fn roundtrip_multi_program_seek_uses_selected_programs_pcr() {
    let streams = vec![stream_info(0, "h264", true), stream_info(1, "hevc", true)];
    let sink = SharedSink::new();
    {
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
        let mut mx = MpegTsMuxer::with_config(
            output,
            &streams,
            MpegTsMuxConfig {
                transport_stream_id: 7,
                original_network_id: 1,
                programs: vec![
                    ProgramSpec {
                        program_number: 1,
                        pmt_pid: 0x0100,
                        pcr_pid: None,
                        stream_indices: vec![0],
                        service: None,
                        events: Vec::new(),
                        es_descriptors: Vec::new(),
                    },
                    ProgramSpec {
                        program_number: 2,
                        pmt_pid: 0x0110,
                        pcr_pid: None,
                        stream_indices: vec![1],
                        service: None,
                        events: Vec::new(),
                        es_descriptors: Vec::new(),
                    },
                ],
                network: None,
            },
        )
        .expect("mux open");
        mx.write_header().expect("hdr");
        // Interleave the two programs; program 1 at PTS 0.., program 2
        // at PTS 5_000_000.. — same frame cadence, keyframe every 10.
        for i in 0..200i64 {
            let kf = i % 10 == 0;
            let p1 = Packet::new(0, TimeBase::new(1, 90_000), vec![0x11; 256])
                .with_pts(i * 3_600)
                .with_keyframe(kf);
            let p2 = Packet::new(1, TimeBase::new(1, 90_000), vec![0x22; 256])
                .with_pts(5_000_000 + i * 3_600)
                .with_keyframe(kf);
            mx.write_packet(&p1).expect("p1");
            mx.write_packet(&p2).expect("p2");
        }
        mx.write_trailer().expect("trailer");
    }
    let bytes = sink.into_bytes();

    // Program 2: keyframe grid 36_000 starting at 5_000_000.
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes.clone()));
    let mut dmx = MpegTsDemuxer::open_program(input, 2).expect("open p2");
    assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "hevc");
    let landed = dmx.seek_to(0, 5_360_000).expect("seek p2");
    assert_eq!(
        landed, 5_360_000,
        "5_360_000 is on program 2's keyframe grid"
    );
    let pkt = dmx.next_packet().expect("PES");
    assert_eq!(pkt.pts, Some(5_360_000));
    assert!(pkt.flags.keyframe);
    // A mid-GOP target on program 2's timeline.
    let landed = dmx.seek_to(0, 5_250_000).expect("seek p2 mid-GOP");
    assert_eq!(landed, 5_216_000);

    // Program 1 timeline seeks stay on program 1's grid.
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    let mut dmx = MpegTsDemuxer::open_program(input, 1).expect("open p1");
    assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "h264");
    let landed = dmx.seek_to(0, 100_000).expect("seek p1");
    assert_eq!(landed, 72_000);
    assert_eq!(dmx.next_packet().expect("PES").pts, Some(72_000));
}

/// A stream whose packets carry no keyframe flags (no §2.4.3.5
/// indicator, no §2.4.3.7 alignment on the wire) degrades to the
/// PCR-granular landing: at or before the target, within the mux's
/// PCR cadence.
#[test]
fn roundtrip_unflagged_stream_degrades_to_pcr_landing() {
    // gop bigger than the frame count → only frame 0 is a keyframe;
    // drop even that by flagging none.
    let streams = vec![stream_info(0, "h264", true)];
    let sink = SharedSink::new();
    {
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
        let mut mx = crate::muxer::open(output, &streams).expect("mux open");
        mx.write_header().expect("hdr");
        for i in 0..120i64 {
            let pkt = Packet::new(0, TimeBase::new(1, 90_000), vec![0x33; 200]).with_pts(i * 3_600);
            mx.write_packet(&pkt).expect("packet");
        }
        mx.write_trailer().expect("trailer");
    }
    let bytes = sink.into_bytes();
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    let mut dmx = MpegTsDemuxer::open_program(input, 1).expect("open");

    let target = 250_000i64;
    let landed = dmx.seek_to(0, target).expect("seek");
    assert!(landed <= target, "landed {landed} must not overshoot");
    // The muxer PCRs ride the video PES at pts − 900 (T-STD offset)
    // on a ≤ PCR_MAX_INTERVAL cadence; the landing can therefore trail
    // the target by at most one frame step + the offset.
    assert!(
        target - landed <= 3_600 + 900,
        "landed {landed} too far below target {target}"
    );
    // Post-seek stream is decodable forward: monotonic PTS from the
    // landing.
    let a = dmx.next_packet().expect("a").pts.unwrap();
    let b = dmx.next_packet().expect("b").pts.unwrap();
    assert!(a <= b);
    assert!(a >= landed && a <= target + 3_600);
}

/// Seeking after streaming to EOF must fully revive the demuxer (the
/// eof flag, reassemblers, pending queue, trackers).
#[test]
fn roundtrip_seek_revives_after_eof() {
    let bytes = mux_video(0, 60, 3_600, 6, |_| 128);
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    let mut dmx = MpegTsDemuxer::open_program(input, 1).expect("open");
    let mut n = 0;
    while dmx.next_packet().is_ok() {
        n += 1;
    }
    assert_eq!(n, 60, "streamed every frame to EOF");
    let landed = dmx.seek_to(0, 90_000).expect("seek after EOF");
    assert_eq!(landed, 86_400); // keyframe grid 21_600 → 4 × 21_600
    let pkt = dmx.next_packet().expect("PES after revive");
    assert_eq!(pkt.pts, Some(86_400));
    assert!(pkt.flags.keyframe);
}
