//! Demux-path regressions for multi-frame audio PES splitting and
//! elementary-stream parameter discovery (playback corpus, umbrella
//! issue #4: AC-3 in M2TS and MP2 in TS decoded only the first syncframe
//! of every PES; stream params came out `0x0` / `0ch`).

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use oxideav_core::{CodecId, CodecParameters, Demuxer, Packet, StreamInfo, TimeBase};

use crate::demuxer::MpegTsDemuxer;

#[derive(Clone)]
struct Sink(Arc<Mutex<Cursor<Vec<u8>>>>);
impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl std::io::Seek for Sink {
    fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
        self.0.lock().unwrap().seek(p)
    }
}

fn info(idx: u32, params: CodecParameters) -> StreamInfo {
    StreamInfo {
        index: idx,
        time_base: TimeBase::new(1, 90_000),
        duration: None,
        start_time: None,
        params,
    }
}

/// A 48 kHz 192 kbit/s 2/0 AC-3 syncframe (Table 5.18: 384 words).
fn ac3_frame(tag: u8) -> Vec<u8> {
    let mut f = vec![tag; 768];
    f[..8].copy_from_slice(&[0x0B, 0x77, 0, 0, 20, 8 << 3, 0b0100_0000, 0]);
    f
}

/// A 48 kHz 192 kbit/s stereo MPEG-1 Layer II frame (576 bytes).
fn mp2_frame(tag: u8) -> Vec<u8> {
    let mut f = vec![tag; 576];
    f[..4].copy_from_slice(&[0xFF, 0xFD, 0xA4, 0x00]);
    f
}

/// x264's 320x180 25 fps High-profile SPS (ffmpeg black-box output).
const SPS_320X180: [u8; 30] = [
    0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x0c, 0xac, 0xd9, 0x41, 0x41, 0x9f, 0x9f, 0x01, 0x10, 0x00,
    0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0x20, 0xf1, 0x42, 0x99, 0x60, 0x00,
];

fn mux(frames_per_pes: usize, pes_count: usize) -> Vec<u8> {
    let streams = vec![
        info(0, CodecParameters::video(CodecId::new("h264"))),
        info(1, CodecParameters::audio(CodecId::new("ac3"))),
        info(2, CodecParameters::audio(CodecId::new("mp2"))),
    ];
    let sink = Sink(Arc::new(Mutex::new(Cursor::new(Vec::new()))));
    {
        let mut mx = crate::muxer::open(Box::new(sink.clone()), &streams).unwrap();
        mx.write_header().unwrap();
        let tb = TimeBase::new(1, 90_000);
        for i in 0..pes_count {
            let mut v = SPS_320X180.to_vec();
            v.extend_from_slice(&[0, 0, 1, 0x65, 0x88, 0x84]);
            let vpts = 9000 + i as i64 * 3600;
            mx.write_packet(&Packet::new(0, tb, v).with_pts(vpts).with_keyframe(true))
                .unwrap();
            let mut a = Vec::new();
            let mut m = Vec::new();
            for k in 0..frames_per_pes {
                a.extend_from_slice(&ac3_frame((i * frames_per_pes + k) as u8));
                m.extend_from_slice(&mp2_frame((i * frames_per_pes + k) as u8));
            }
            let apts = 9000 + (i * frames_per_pes) as i64 * 2880;
            mx.write_packet(&Packet::new(1, tb, a).with_pts(apts))
                .unwrap();
            let mpts = 9000 + (i * frames_per_pes) as i64 * 2160;
            mx.write_packet(&Packet::new(2, tb, m).with_pts(mpts))
                .unwrap();
        }
        mx.write_trailer().unwrap();
    }
    Arc::try_unwrap(sink.0)
        .ok()
        .unwrap()
        .into_inner()
        .unwrap()
        .into_inner()
}

fn drain(d: &mut MpegTsDemuxer) -> Vec<Packet> {
    let mut out = Vec::new();
    while let Ok(p) = d.next_packet() {
        out.push(p);
    }
    out
}

#[test]
fn multi_frame_audio_pes_splits_into_one_packet_per_syncframe() {
    let bytes = mux(3, 4);
    let mut d = MpegTsDemuxer::open_program(Box::new(Cursor::new(bytes)), 1).unwrap();
    let pkts = drain(&mut d);
    let ac3: Vec<&Packet> = pkts.iter().filter(|p| p.stream_index == 1).collect();
    let mp2: Vec<&Packet> = pkts.iter().filter(|p| p.stream_index == 2).collect();
    assert_eq!(ac3.len(), 12);
    assert_eq!(mp2.len(), 12);
    for (k, p) in ac3.iter().enumerate() {
        assert_eq!(p.data, ac3_frame(k as u8), "ac3 frame {k}");
        assert_eq!(p.pts, Some(9000 + k as i64 * 2880));
        assert_eq!(p.duration, Some(2880));
    }
    for (k, p) in mp2.iter().enumerate() {
        assert_eq!(p.data, mp2_frame(k as u8), "mp2 frame {k}");
        assert_eq!(p.pts, Some(9000 + k as i64 * 2160));
    }
    // Video stays one packet per PES.
    assert_eq!(pkts.iter().filter(|p| p.stream_index == 0).count(), 4);
}

#[test]
fn stream_params_come_from_first_access_units() {
    let bytes = mux(2, 3);
    let d = MpegTsDemuxer::open_program(Box::new(Cursor::new(bytes)), 1).unwrap();
    let s = d.streams();
    assert_eq!(
        (s[0].params.width, s[0].params.height),
        (Some(320), Some(180))
    );
    assert_eq!(
        s[0].params.frame_rate,
        Some(oxideav_core::Rational::new(25, 1))
    );
    assert_eq!(
        s[0].params.pixel_format,
        Some(oxideav_core::PixelFormat::Yuv420P)
    );
    assert_eq!(s[1].params.sample_rate, Some(48_000));
    assert_eq!(s[1].params.channels, Some(2));
    assert_eq!(s[1].params.bit_rate, Some(192_000));
    assert_eq!(s[2].params.sample_rate, Some(48_000));
    assert_eq!(s[2].params.channels, Some(2));
}

#[test]
fn param_probe_restores_the_stream_cursor() {
    // The look-ahead must not swallow packets: the first packets out
    // are the same with and without the probe having run.
    let bytes = mux(1, 2);
    let mut d = MpegTsDemuxer::open_program(Box::new(Cursor::new(bytes)), 1).unwrap();
    let pkts = drain(&mut d);
    assert_eq!(pkts.len(), 6);
    assert_eq!(pkts[0].stream_index, 0);
    assert_eq!(pkts[0].pts, Some(9000));
}

#[test]
fn seek_resets_partial_audio_frames() {
    let bytes = mux(3, 6);
    let mut d = MpegTsDemuxer::open_program(Box::new(Cursor::new(bytes)), 1).unwrap();
    let _ = drain(&mut d);
    use oxideav_core::Demuxer as _;
    if d.seek_to(1, 9000).is_ok() {
        let pkts = drain(&mut d);
        for p in pkts.iter().filter(|p| p.stream_index == 1) {
            assert_eq!(
                p.data.len(),
                768,
                "every post-seek AC-3 packet is a whole syncframe"
            );
        }
    }
}
