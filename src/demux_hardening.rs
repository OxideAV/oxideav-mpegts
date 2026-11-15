//! Damaged-input behaviour of the transport-stream demuxer (test-only
//! module): streams are assembled packet by packet so each defect —
//! leading bytes, inserted / deleted bytes, a truncated tail, packets
//! that do not parse, duplicates, lost packets, a broken PES header,
//! an endless PES packet — sits exactly where the test puts it.

use std::io::Cursor;

use oxideav_core::{Demuxer, Error as CoreError, Packet, ReadSeek};

use crate::build::{PmtStreamEntry, build_pat, build_pmt};
use crate::demuxer::MpegTsDemuxer;
use crate::packet::{AdaptationFieldSpec, TS_PACKET_LEN, TS_SYNC_BYTE};
use crate::pes::PesHeaderSpec;

const PAT: u16 = 0x0000;
const PMT: u16 = 0x0100;
const VIDEO: u16 = 0x0101;
const AUDIO: u16 = 0x0102;

/// Packet-by-packet stream writer with per-PID continuity counters.
#[derive(Default)]
struct Ts {
    bytes: Vec<u8>,
    cc: std::collections::HashMap<u16, u8>,
}

impl Ts {
    fn next_cc(&mut self, pid: u16) -> u8 {
        let c = self.cc.entry(pid).or_insert(0);
        let v = *c;
        *c = (v + 1) & 0x0F;
        v
    }

    /// One PSI section in one packet (pointer_field 0).
    fn psi(&mut self, pid: u16, section: &[u8]) {
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = 0x40 | (pid >> 8) as u8 & 0x1F;
        pkt[2] = pid as u8;
        pkt[3] = 0x10 | self.next_cc(pid);
        pkt[4] = 0;
        pkt[5..5 + section.len()].copy_from_slice(section);
        self.bytes.extend_from_slice(&pkt);
    }

    /// PAT + single-program PMT: H.264 on [`VIDEO`] (also the PCR
    /// PID) and an audio stream type that is passed through whole.
    fn tables(&mut self) {
        self.psi(PAT, &build_pat(1, 0, &[(1, PMT)]));
        let pmt = build_pmt(
            1,
            0,
            VIDEO,
            &[],
            &[
                PmtStreamEntry::new(0x1B, VIDEO, Vec::new()),
                PmtStreamEntry::new(0x83, AUDIO, Vec::new()),
            ],
        );
        self.psi(PMT, &pmt);
    }

    /// A PES packet (bytes from the start code) cut into TS packets.
    /// The first packet carries `pcr` / the random-access indicator;
    /// short fragments are padded with adaptation-field stuffing.
    fn pes_bytes(&mut self, pid: u16, pes: &[u8], rai: bool, pcr: Option<u64>) {
        let mut at = 0usize;
        let mut first = true;
        while at < pes.len() {
            let spec = AdaptationFieldSpec {
                random_access_indicator: first && rai,
                pcr: pcr.filter(|_| first).map(|b| (b, 0)),
                ..Default::default()
            };
            let min_af = if spec.is_empty() {
                0
            } else {
                spec.encode(None).unwrap().len()
            };
            let take = (pes.len() - at).min(184 - min_af);
            let af_len = 184 - take;
            let mut pkt = Vec::with_capacity(TS_PACKET_LEN);
            pkt.push(TS_SYNC_BYTE);
            pkt.push(if first { 0x40 } else { 0 } | (pid >> 8) as u8 & 0x1F);
            pkt.push(pid as u8);
            let cc = self.next_cc(pid);
            if af_len > 0 {
                pkt.push(0x30 | cc);
                pkt.extend(spec.encode(Some(af_len)).unwrap());
            } else {
                pkt.push(0x10 | cc);
            }
            pkt.extend_from_slice(&pes[at..at + take]);
            assert_eq!(pkt.len(), TS_PACKET_LEN);
            self.bytes.extend_from_slice(&pkt);
            at += take;
            first = false;
        }
    }

    /// One timestamped PES packet with `payload` on `pid`.
    fn pes(&mut self, pid: u16, pts: u64, payload: &[u8], key: bool) {
        let sid = if pid == VIDEO { 0xE0 } else { 0xBD };
        let mut spec = PesHeaderSpec::with_timestamps(sid, pts, None);
        if pid == VIDEO && payload.len() > 60_000 {
            spec.unbounded_length = true;
        }
        let pes = spec.encode(payload).unwrap();
        let pcr = (pid == VIDEO).then(|| pts.saturating_sub(900));
        self.pes_bytes(pid, &pes, key, pcr);
    }
}

fn frame(tag: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| 0x10 | ((tag as usize * 31 + i * 7) as u8 & 0x6F))
        .collect()
}

/// `n` video frames (every fifth a keyframe) with one audio packet
/// each, behind the tables.
fn sample(n: u32) -> Ts {
    let mut ts = Ts::default();
    ts.tables();
    for k in 0..n {
        let pts = 90_000 + u64::from(k) * 3_600;
        ts.pes(
            VIDEO,
            pts,
            &frame(k, 700 + (k as usize % 5) * 90),
            k % 5 == 0,
        );
        ts.pes(AUDIO, pts, &frame(1000 + k, 200), false);
    }
    ts
}

fn open(bytes: Vec<u8>) -> MpegTsDemuxer {
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    MpegTsDemuxer::open_program(input, 1).expect("open")
}

/// Drain to end of stream; any error other than end-of-stream fails.
fn drain(d: &mut MpegTsDemuxer) -> Vec<Packet> {
    let mut out = Vec::new();
    loop {
        match d.next_packet() {
            Ok(p) => out.push(p),
            Err(CoreError::Eof) => return out,
            Err(e) => panic!("demux error: {e}"),
        }
    }
}

type Shape = Vec<(u32, Option<i64>, Vec<u8>, bool)>;

fn shape(packets: &[Packet]) -> Shape {
    packets
        .iter()
        .map(|p| (p.stream_index, p.pts, p.data.to_vec(), p.flags.keyframe))
        .collect()
}

fn reframe(bytes: &[u8], prefix: usize, trailer: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, pkt) in bytes.chunks(TS_PACKET_LEN).enumerate() {
        out.extend(std::iter::repeat_n(k as u8 | 0x80, prefix));
        out.extend_from_slice(pkt);
        out.extend(std::iter::repeat_n(0x55, trailer));
    }
    out
}

#[test]
fn leading_bytes_ahead_of_the_first_packet_in_every_layout() {
    let clean = sample(40).bytes;
    let want = shape(&drain(&mut open(clean.clone())));
    assert_eq!(want.len(), 80);
    for (prefix, trailer) in [(0usize, 0usize), (4, 0), (0, 16)] {
        let framed = reframe(&clean, prefix, trailer);
        for lead in [0usize, 1, 57, 187, 188, 203, 1000] {
            // Leading bytes that never form a sync byte.
            let mut bytes: Vec<u8> = (0..lead).map(|i| 0x20 | (i as u8 & 0x0F)).collect();
            bytes.extend_from_slice(&framed);
            let mut d = open(bytes);
            assert_eq!(d.packet_layout().packet_size, 188 + prefix + trailer);
            assert_eq!(d.leading_bytes(), lead as u64, "layout {prefix}/{trailer}");
            let got = shape(&drain(&mut d));
            assert_eq!(got, want, "lead {lead}, layout {prefix}/{trailer}");
            assert_eq!(d.stats(), Default::default());
            assert!(d.duration_micros().is_some());

            // Index offsets are true source offsets, and seeking lands
            // on the indexed keyframe.
            let index = d.random_access_points().unwrap().to_vec();
            assert!(!index.is_empty());
            let psize = (188 + prefix + trailer) as u64;
            for rap in &index {
                assert_eq!((rap.byte_offset - lead as u64) % psize, 0);
            }
            let landed = d.seek_to(0, 90_000 + 12 * 3_600).unwrap();
            assert_eq!(landed, 90_000 + 10 * 3_600);
            let first = d.next_packet().unwrap();
            assert!(first.flags.keyframe);
            assert_eq!(first.pts, Some(landed));
        }
    }
}

#[test]
fn probe_scores_a_grid_that_starts_mid_buffer() {
    let clean = sample(8).bytes;
    let mut bytes = vec![0x21u8; 77];
    bytes.extend_from_slice(&clean);
    let score = |buf: &[u8]| crate::demuxer::probe(&oxideav_core::ProbeData { buf, ext: None });
    assert_eq!(score(&clean), 100);
    assert_eq!(score(&bytes), 50);
    assert_eq!(score(&vec![0x21u8; 4096]), 0);
}

#[test]
fn inserted_and_deleted_bytes_shift_the_grid_without_ending_the_stream() {
    let clean = sample(60).bytes;
    let want = shape(&drain(&mut open(clean.clone())));
    let packets = clean.len() / TS_PACKET_LEN;

    // Insert 13 bytes a third of the way in; delete 5 two thirds in.
    let ins = (packets / 3) * TS_PACKET_LEN + 40;
    let del = (2 * packets / 3) * TS_PACKET_LEN + 90;
    let mut bytes = clean.clone();
    bytes.drain(del..del + 5);
    for k in 0..13 {
        bytes.insert(ins, 0x30 + k);
    }
    let mut d = open(bytes);
    let got = drain(&mut d);
    let stats = d.stats();
    assert!(
        stats.resync_bytes > 0 && stats.resync_bytes < 3 * 188,
        "{stats:?}"
    );
    assert!(stats.continuity_errors >= 1, "{stats:?}");
    // Each defect costs at most the PES packets it touches.
    assert!(
        got.len() >= want.len() - 4,
        "{} of {}",
        got.len(),
        want.len()
    );
    // The stream's last packets come through untouched.
    let got = shape(&got);
    assert_eq!(got[got.len() - 10..], want[want.len() - 10..]);
    assert_eq!(got[..10], want[..10]);
}

#[test]
fn a_tail_cut_mid_packet_is_a_clean_end_of_stream() {
    let clean = sample(20).bytes;
    let want = shape(&drain(&mut open(clean.clone())));
    for cut in [1usize, 50, 187] {
        let mut d = open(clean[..clean.len() - cut].to_vec());
        let got = shape(&drain(&mut d));
        // Only the PES packet whose last TS packet was cut can differ.
        assert_eq!(got.len(), want.len());
        assert_eq!(got[..got.len() - 1], want[..want.len() - 1], "cut {cut}");
    }
    // A tail of bytes that are not packets at all.
    let mut bytes = clean.clone();
    bytes.extend(std::iter::repeat_n(0x21u8, 5000));
    let mut d = open(bytes);
    assert_eq!(shape(&drain(&mut d)), want);
    assert_eq!(d.stats().resync_bytes, 5000);
}

#[test]
fn long_garbage_run_is_reported_then_demux_carries_on() {
    let a = sample(10).bytes;
    let mut b = Ts::default();
    for k in 0..10u32 {
        b.pes(VIDEO, 500_000 + u64::from(k) * 3_600, &frame(k, 500), true);
    }
    let mut bytes = a;
    bytes.extend(std::iter::repeat_n(0x21u8, 300 * 188 + 31));
    bytes.extend_from_slice(&b.bytes);
    let mut d = open(bytes);
    let mut errors = 0;
    let mut pts = Vec::new();
    loop {
        match d.next_packet() {
            Ok(p) => pts.push(p.pts.unwrap()),
            Err(CoreError::Eof) => break,
            Err(_) => errors += 1,
        }
        assert!(errors < 10, "resync must make progress");
    }
    assert!(errors >= 1, "a corruption this long is reported");
    assert!(pts.contains(&(500_000 + 9 * 3_600)));
}

#[test]
fn unparseable_and_error_flagged_packets_are_skipped() {
    let mut ts = sample(6);
    // adaptation_field_length running past the packet on the video
    // PID, and a transport_error_indicator packet on the audio PID.
    let mut bad_af = [0x00u8; TS_PACKET_LEN];
    bad_af[..5].copy_from_slice(&[TS_SYNC_BYTE, (VIDEO >> 8) as u8, VIDEO as u8, 0x20, 200]);
    let mut tei = [0x00u8; TS_PACKET_LEN];
    tei[..4].copy_from_slice(&[TS_SYNC_BYTE, 0x80 | (AUDIO >> 8) as u8, AUDIO as u8, 0x1F]);
    // A PCR flag with no room for the PCR.
    let mut short_pcr = [0xFFu8; TS_PACKET_LEN];
    short_pcr[..6].copy_from_slice(&[TS_SYNC_BYTE, (VIDEO >> 8) as u8, VIDEO as u8, 0x20, 1, 0x10]);
    let clean_len = ts.bytes.len();
    ts.bytes.extend_from_slice(&bad_af);
    ts.bytes.extend_from_slice(&tei);
    ts.bytes.extend_from_slice(&short_pcr);
    for k in 6..12u32 {
        let pts = 90_000 + u64::from(k) * 3_600;
        ts.pes(VIDEO, pts, &frame(k, 700), k % 5 == 0);
        ts.pes(AUDIO, pts, &frame(1000 + k, 200), false);
    }
    let mut reference = ts.bytes.clone();
    reference.drain(clean_len..clean_len + 3 * TS_PACKET_LEN);
    let want = shape(&drain(&mut open(reference)));

    let mut d = open(ts.bytes);
    let got = drain(&mut d);
    assert_eq!(shape(&got), want);
    assert!(got.iter().all(|p| !p.flags.corrupt));
    let stats = d.stats();
    assert_eq!(stats.malformed_packets, 2, "{stats:?}");
    assert_eq!(stats.transport_errors, 1, "{stats:?}");
    assert_eq!(stats.continuity_errors, 0, "{stats:?}");
}

#[test]
fn duplicate_packets_are_consumed_once() {
    let clean = sample(12).bytes;
    let want = shape(&drain(&mut open(clean.clone())));
    // Send every payload packet of the two elementary PIDs twice
    // (§2.4.3.3 duplicate packets).
    let mut bytes = Vec::new();
    let mut dups = 0u64;
    for pkt in clean.chunks(TS_PACKET_LEN) {
        bytes.extend_from_slice(pkt);
        let pid = (u16::from(pkt[1] & 0x1F) << 8) | u16::from(pkt[2]);
        if pid == VIDEO || pid == AUDIO {
            bytes.extend_from_slice(pkt);
            dups += 1;
        }
    }
    let mut d = open(bytes);
    let got = drain(&mut d);
    assert_eq!(shape(&got), want);
    assert!(got.iter().all(|p| !p.flags.corrupt));
    assert_eq!(d.stats().duplicate_packets, dups);
    assert_eq!(d.stats().continuity_errors, 0);
}

#[test]
fn lost_packets_flag_the_affected_pes_corrupt() {
    let mut ts = Ts::default();
    ts.tables();
    for k in 0..8u32 {
        ts.pes(
            VIDEO,
            90_000 + u64::from(k) * 3_600,
            &frame(k, 1500),
            k == 0,
        );
    }
    // Frame 3 spans several packets; drop its third.
    let per_frame = (ts.bytes.len() / TS_PACKET_LEN - 2) / 8;
    assert!(per_frame >= 4);
    let victim = (2 + 3 * per_frame + 2) * TS_PACKET_LEN;
    ts.bytes.drain(victim..victim + TS_PACKET_LEN);

    let mut d = open(ts.bytes);
    let got = drain(&mut d);
    assert_eq!(got.len(), 8);
    for (k, p) in got.iter().enumerate() {
        assert_eq!(p.flags.corrupt, k == 3, "frame {k}");
        assert_eq!(p.pts, Some(90_000 + k as i64 * 3_600));
    }
    assert!(got[3].data.len() < 1500);
    assert_eq!(got[4].data.to_vec(), frame(4, 1500));
    assert_eq!(d.stats().continuity_errors, 1);
}

#[test]
fn a_broken_pes_header_costs_one_packet() {
    let mut ts = Ts::default();
    ts.tables();
    let mut starts = Vec::new();
    for k in 0..6u32 {
        starts.push(ts.bytes.len());
        ts.pes(VIDEO, 90_000 + u64::from(k) * 3_600, &frame(k, 300), true);
    }
    // Break the start-code prefix of frame 2 (payload follows the
    // 4-byte header and the adaptation field).
    let pkt = starts[2];
    let af = ts.bytes[pkt + 4] as usize;
    ts.bytes[pkt + 4 + 1 + af + 2] = 0x02;

    let mut d = open(ts.bytes);
    let got = drain(&mut d);
    let pts: Vec<i64> = got.iter().map(|p| p.pts.unwrap()).collect();
    let want: Vec<i64> = [0, 1, 3, 4, 5].iter().map(|k| 90_000 + k * 3_600).collect();
    assert_eq!(pts, want);
    assert_eq!(d.stats().damaged_pes, 1);
    assert_eq!(d.buffered_bytes(), 0);
}

#[test]
fn reordered_presentation_times_stay_on_one_axis_across_a_wrap() {
    let m = crate::TIMESTAMP_MODULUS_90KHZ as i64;
    // Decode order I P B B P B B …, 3600-tick pictures, starting 0.5 s
    // before the 33-bit wrap.
    let start = m - 45_000;
    let mut order: Vec<i64> = vec![0];
    for g in 0..12i64 {
        order.extend([3 * g + 3, 3 * g + 1, 3 * g + 2]);
    }
    let mut ts = Ts::default();
    ts.tables();
    for (k, &disp) in order.iter().enumerate() {
        let pts = start + disp * 3_600;
        let dts = start + (k as i64 - 2) * 3_600;
        let spec = PesHeaderSpec::with_timestamps(
            0xE0,
            (pts & (m - 1)) as u64,
            Some((dts & (m - 1)) as u64),
        );
        let pes = spec.encode(&frame(k as u32, 100)).unwrap();
        ts.pes_bytes(VIDEO, &pes, k == 0, Some((dts.max(0) & (m - 1)) as u64));
    }
    let got = drain(&mut open(ts.bytes));
    assert_eq!(got.len(), order.len());
    for (k, (p, &disp)) in got.iter().zip(&order).enumerate() {
        assert_eq!(p.pts, Some(start + disp * 3_600), "pts of packet {k}");
        assert_eq!(
            p.dts,
            Some(start + (k as i64 - 2) * 3_600),
            "dts of packet {k}"
        );
    }
    assert!(got.last().unwrap().pts.unwrap() > m);
}

#[test]
fn pmt_pid_shared_by_two_programs_selects_by_program_number() {
    let mut ts = Ts::default();
    ts.psi(PAT, &build_pat(1, 0, &[(1, PMT), (2, PMT)]));
    // Program 2's section comes first on the shared PID.
    let pmt2 = build_pmt(
        2,
        0,
        AUDIO,
        &[],
        &[PmtStreamEntry::new(0x83, AUDIO, Vec::new())],
    );
    let pmt1 = build_pmt(
        1,
        0,
        VIDEO,
        &[],
        &[PmtStreamEntry::new(0x1B, VIDEO, Vec::new())],
    );
    ts.psi(PMT, &pmt2);
    ts.psi(PMT, &pmt1);
    for k in 0..4u32 {
        ts.pes(VIDEO, 90_000 + u64::from(k) * 3_600, &frame(k, 100), true);
        ts.pes(AUDIO, 90_000 + u64::from(k) * 3_600, &frame(k, 50), false);
    }
    for (program, codec, len) in [(1u16, "h264", 100usize), (2, "truehd", 50)] {
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(ts.bytes.clone()));
        let mut d = MpegTsDemuxer::open_program(input, program).unwrap();
        assert_eq!(d.streams().len(), 1);
        assert_eq!(
            d.streams()[0].params.codec_id.as_str(),
            codec,
            "program {program}"
        );
        let got = drain(&mut d);
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|p| p.data.len() == len));
    }
}

#[test]
fn multi_section_pat_lists_every_program_in_order() {
    // Two PAT sections; the stream shows section 1 first.
    let mut s0 = build_pat(1, 0, &[(1, PMT)]);
    let mut s1 = build_pat(1, 0, &[(2, 0x0200)]);
    for (s, number) in [(&mut s0, 0u8), (&mut s1, 1)] {
        s[6] = number;
        s[7] = 1; // last_section_number
        let n = s.len();
        let crc = crate::psi::mpeg2_crc32(&s[..n - 4]);
        s[n - 4..].copy_from_slice(&crc.to_be_bytes());
    }
    let mut ts = Ts::default();
    ts.psi(PAT, &s1);
    ts.psi(PAT, &s0);
    let pmt1 = build_pmt(
        1,
        0,
        VIDEO,
        &[],
        &[PmtStreamEntry::new(0x1B, VIDEO, Vec::new())],
    );
    let pmt2 = build_pmt(
        2,
        0,
        AUDIO,
        &[],
        &[PmtStreamEntry::new(0x83, AUDIO, Vec::new())],
    );
    ts.psi(PMT, &pmt1);
    ts.psi(0x0200, &pmt2);
    ts.pes(VIDEO, 90_000, &frame(0, 100), true);
    ts.pes(AUDIO, 90_000, &frame(1, 50), false);

    let d = open(ts.bytes.clone());
    let listed: Vec<u16> = d.programs().iter().map(|p| p.program_number).collect();
    assert_eq!(listed, vec![1, 2]);
    assert_eq!(d.selected_program(), 1);
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(ts.bytes));
    let d2 = MpegTsDemuxer::open_program(input, 2).unwrap();
    assert_eq!(d2.streams()[0].params.codec_id.as_str(), "truehd");
}

#[test]
fn tables_survive_garbage_on_their_pids() {
    let mut ts = Ts::default();
    // A PAT-PID packet claiming an overlong section, then one whose
    // CRC is wrong, ahead of the real tables.
    let mut overlong = vec![0x00u8, 0xB4, 0x00];
    overlong.resize(100, 0x11);
    ts.psi(PAT, &overlong);
    let mut bad_crc = build_pat(1, 0, &[(9, 0x0900)]);
    let n = bad_crc.len();
    bad_crc[n - 1] ^= 0xFF;
    ts.psi(PAT, &bad_crc);
    let clean = sample(5);
    ts.bytes.extend_from_slice(&clean.bytes);
    let mut d = open(ts.bytes);
    assert_eq!(d.programs().len(), 1);
    assert_eq!(drain(&mut d).len(), 10);
}

#[test]
fn an_endless_pes_packet_is_bounded_and_lossless() {
    let mut ts = Ts::default();
    ts.tables();
    // One unbounded video PES packet of 600 kB and no second start.
    let payload = frame(7, 600_000);
    ts.pes(VIDEO, 90_000, &payload, true);
    let mut d = open(ts.bytes);
    d.set_max_pes_bytes(50_000);
    let mut got = Vec::new();
    loop {
        match d.next_packet() {
            Ok(p) => got.push(p),
            Err(CoreError::Eof) => break,
            Err(e) => panic!("{e}"),
        }
        assert!(d.buffered_bytes() <= 50_000);
    }
    assert!(got.len() >= 12);
    assert_eq!(got[0].pts, Some(90_000));
    assert!(got[0].flags.keyframe);
    assert!(
        got[1..]
            .iter()
            .all(|p| p.pts.is_none() && !p.flags.keyframe)
    );
    let joined: Vec<u8> = got.iter().flat_map(|p| p.data.to_vec()).collect();
    assert_eq!(joined, payload);
}

#[test]
fn a_refused_seek_leaves_the_streaming_position_alone() {
    // No PCR and no access-point signalling at all: every seek path
    // refuses, and the packets keep coming in order afterwards.
    let mut ts = Ts::default();
    ts.tables();
    for k in 0..30u32 {
        ts.pes(AUDIO, 90_000 + u64::from(k) * 1_800, &frame(k, 400), false);
    }
    let want = shape(&drain(&mut open(ts.bytes.clone())));
    let mut d = open(ts.bytes);
    let mut got = Vec::new();
    for _ in 0..7 {
        got.push(d.next_packet().unwrap());
    }
    assert!(d.seek_to(1, 200_000).is_err());
    assert!(d.seek_to_random_access(None, 200_000).is_err());
    got.extend(drain(&mut d));
    assert_eq!(shape(&got), want);
}
