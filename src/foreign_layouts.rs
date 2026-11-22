//! Pins for the layouts other multiplexers produce and this crate's
//! own writer does not: time stamps coded as a PTS alone, access
//! points without the adaptation-field indicator, codecs named by
//! descriptors or by nothing at all, elementary-stream packets ahead
//! of the first program tables, audio in the LATM and DTS framings.

use std::io::Cursor;

use oxideav_core::{Demuxer, MediaType, Packet, ReadSeek};

use crate::build::{PmtStreamEntry, build_pat, build_pmt};
use crate::demuxer::MpegTsDemuxer;
use crate::pes::PesHeaderSpec;
use crate::{TS_PACKET_LEN, TS_SYNC_BYTE};

/// MSB-first bit writer for the small headers below.
#[derive(Default)]
pub(crate) struct BitWriter {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    pub(crate) fn put(&mut self, value: u32, width: u32) -> &mut Self {
        for k in (0..width).rev() {
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit = ((value >> k) & 1) as u8;
            *self.bytes.last_mut().unwrap() |= bit << (7 - self.bits % 8);
            self.bits += 1;
        }
        self
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

/// A LOAS frame of `total` bytes. With `config`, its `AudioMuxElement()`
/// opens with a `StreamMuxConfig()` for AAC-LC, 48 kHz, stereo, 1024
/// samples; without, it refers to the previous one.
pub(crate) fn loas_frame(total: usize, config: bool, fill: u8) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.put(0x2B7, 11).put(total as u32 - 3, 13);
    if config {
        // useSameStreamMux audioMuxVersion allStreamsSameTimeFraming
        // numSubFrames numProgram numLayer
        w.put(0, 1)
            .put(0, 1)
            .put(1, 1)
            .put(0, 6)
            .put(0, 4)
            .put(0, 3);
        // AudioSpecificConfig: object type 2, samplingFrequencyIndex 3,
        // channelConfiguration 2; GASpecificConfig: frameLengthFlag 0,
        // dependsOnCoreCoder 0, extensionFlag 0.
        w.put(2, 5).put(3, 4).put(2, 4).put(0, 3);
        // frameLengthType 0, latmBufferFullness.
        w.put(0, 3).put(0xFF, 8);
    } else {
        w.put(1, 1).put(0, 7);
    }
    let mut out = w.finish();
    out.resize(total, fill);
    out
}

/// A DTS core frame of `total` bytes: 512 samples, stereo, 48 kHz.
pub(crate) fn dts_core_frame(total: usize, fill: u8) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.put(0x7FFE_8001, 32);
    // FTYPE SHORT CPF NBLKS FSIZE AMODE SFREQ RATE
    w.put(1, 1).put(31, 5).put(0, 1).put(15, 7);
    w.put(total as u32 - 1, 14).put(2, 6).put(13, 4).put(15, 5);
    // FixedBit DYNF TIMEF AUXF HDCD EXT_AUDIO_ID EXT_AUDIO ASPF LFF
    w.put(0, 10).put(0, 2);
    let mut out = w.finish();
    out.resize(total, fill);
    out
}

/// A DTS extension substream of `total` bytes (short header form).
pub(crate) fn dts_extension(total: usize, fill: u8) -> Vec<u8> {
    let mut w = BitWriter::default();
    w.put(0x6458_2025, 32).put(0, 8).put(0, 2).put(0, 1);
    w.put(15, 8).put(total as u32 - 1, 16);
    let mut out = w.finish();
    out.resize(total, fill);
    out
}

/// An MPEG-1 Layer II frame: 48 kHz, 192 kbit/s, 576 bytes.
pub(crate) fn mp2_frame(fill: u8) -> Vec<u8> {
    let mut f = vec![0xFF, 0xFD, 0xA4, 0x00];
    f.resize(576, fill);
    f
}

/// Transport stream assembled packet by packet.
#[derive(Default)]
pub(crate) struct TsBuilder {
    pub(crate) out: Vec<u8>,
    counters: std::collections::HashMap<u16, u8>,
}

impl TsBuilder {
    fn header(&mut self, pid: u16, start: bool, adaptation: bool) -> [u8; 4] {
        let cc = self.counters.entry(pid).or_insert(0);
        let h = [
            TS_SYNC_BYTE,
            (u8::from(start) << 6) | (pid >> 8) as u8 & 0x1F,
            pid as u8,
            if adaptation { 0x30 } else { 0x10 } | *cc,
        ];
        *cc = (*cc + 1) & 0x0F;
        h
    }

    /// One section in one packet.
    pub(crate) fn section(&mut self, pid: u16, section: &[u8]) {
        let h = self.header(pid, true, false);
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[..4].copy_from_slice(&h);
        pkt[4] = 0;
        pkt[5..5 + section.len()].copy_from_slice(section);
        self.out.extend_from_slice(&pkt);
    }

    /// PAT for program 1 on PID 0x1000 and its PMT (PCR on the first
    /// entry's PID).
    pub(crate) fn tables(&mut self, entries: &[PmtStreamEntry]) {
        self.section(0, &build_pat(1, 0, &[(1, 0x1000)]));
        let pcr_pid = entries[0].elementary_pid;
        self.section(0x1000, &build_pmt(1, 0, pcr_pid, &[], entries));
    }

    /// One PES packet, split over as many transport packets as needed.
    /// `indicator` sets the `random_access_indicator` on the first.
    pub(crate) fn pes(
        &mut self,
        pid: u16,
        stream_id: u8,
        pts: Option<u64>,
        dts: Option<u64>,
        payload: &[u8],
        indicator: bool,
    ) {
        let mut spec = PesHeaderSpec::default().with_stream_id(stream_id);
        spec.pts_90k = pts;
        spec.dts_90k = dts;
        spec.unbounded_length = (0xE0..=0xEF).contains(&stream_id);
        let pes = spec.encode(payload).expect("PES header");
        let mut rest = &pes[..];
        let mut first = true;
        while !rest.is_empty() {
            let flag = first && indicator;
            let room = if flag { 182 } else { 184 };
            let take = rest.len().min(room);
            let stuffing = take < 184;
            let h = self.header(pid, first, stuffing);
            self.out.extend_from_slice(&h);
            if stuffing {
                let af_len = 183 - take;
                self.out.push(af_len as u8);
                if af_len > 0 {
                    self.out.push(if flag { 0x40 } else { 0x00 });
                    self.out
                        .extend(std::iter::repeat_n(0xFF, af_len.saturating_sub(1)));
                }
            }
            self.out.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            first = false;
        }
    }
}

fn open(bytes: Vec<u8>) -> MpegTsDemuxer {
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
    MpegTsDemuxer::open_program(input, 1).expect("open")
}

fn drain(d: &mut MpegTsDemuxer) -> Vec<Packet> {
    let mut out = Vec::new();
    while let Ok(p) = d.next_packet() {
        out.push(p);
    }
    out
}

fn entry(stream_type: u8, pid: u16, es_info: &[u8]) -> PmtStreamEntry {
    PmtStreamEntry::new(stream_type, pid, es_info.to_vec())
}

/// §2.4.3.7: a PES packet with a PTS and no DTS decodes at its PTS.
#[test]
fn pts_only_packet_decodes_at_its_pts() {
    let mut ts = TsBuilder::default();
    ts.tables(&[entry(0x1B, 0x100, &[])]);
    ts.pes(0x100, 0xE0, Some(9000), None, &[0xAA; 40], true);
    ts.pes(0x100, 0xE0, Some(16_200), Some(12_600), &[0xBB; 40], false);
    let pk = drain(&mut open(ts.out));
    assert_eq!((pk[0].pts, pk[0].dts), (Some(9000), Some(9000)));
    assert_eq!((pk[1].pts, pk[1].dts), (Some(16_200), Some(12_600)));
}

/// Every audio access unit is an entry point; a picture is one when the
/// multiplexer said so or when its own headers do.
#[test]
fn access_points_without_the_indicator() {
    let idr = [0, 0, 0, 1, 0x09, 0xF0, 0, 0, 1, 0x65, 0x88, 0x80, 0x10];
    let non_idr = [0, 0, 0, 1, 0x09, 0xF0, 0, 0, 1, 0x41, 0x9A, 0x00, 0x10];
    let mut ts = TsBuilder::default();
    ts.tables(&[entry(0x1B, 0x100, &[]), entry(0x03, 0x101, &[])]);
    ts.pes(0x100, 0xE0, Some(9000), None, &idr, false);
    ts.pes(0x101, 0xC0, Some(9000), None, &mp2_frame(1), false);
    ts.pes(0x100, 0xE0, Some(12_600), None, &non_idr, false);
    ts.pes(0x101, 0xC0, Some(11_160), None, &mp2_frame(2), false);
    ts.pes(0x100, 0xE0, Some(16_200), None, &non_idr, true);
    let pk = drain(&mut open(ts.out));
    let video: Vec<bool> = pk
        .iter()
        .filter(|p| p.stream_index == 0)
        .map(|p| p.flags.keyframe)
        .collect();
    assert_eq!(video, [true, false, true]);
    assert!(
        pk.iter()
            .filter(|p| p.stream_index == 1)
            .all(|p| p.flags.keyframe)
    );
}

#[test]
fn first_coded_picture_decides_the_keyframe() {
    use crate::es_params::es_starts_with_keyframe as key;
    // H.264: AUD, SPS, then an IDR slice / a non-IDR slice.
    assert!(key(
        "h264",
        &[0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x67, 1, 0, 0, 1, 0x65, 0x88]
    ));
    assert!(!key(
        "h264",
        &[0, 0, 1, 0x09, 0x10, 0, 0, 1, 0x41, 0x9A, 0, 0, 1, 0x65, 0]
    ));
    // H.265: nal_unit_type in bits 1..=6 — VPS (32), then IDR_W_RADL
    // (19) / TRAIL_R (1).
    assert!(key(
        "h265",
        &[0, 0, 1, 0x40, 1, 0xC, 0, 0, 1, 0x26, 1, 0xAF]
    ));
    assert!(!key(
        "h265",
        &[0, 0, 1, 0x40, 1, 0xC, 0, 0, 1, 0x02, 1, 0xAF]
    ));
    // H.266: nal_unit_type in the top five bits of the second byte —
    // AUD (20), then IDR_N_LP (8) / TRAIL (0).
    assert!(key("h266", &[0, 0, 1, 0, 0xA1, 0, 0, 0, 1, 0, 0x41, 0x80]));
    assert!(!key("h266", &[0, 0, 1, 0, 0xA1, 0, 0, 0, 1, 0, 0x01, 0x80]));
    // MPEG-2: sequence header, then picture_coding_type 1 / 2.
    let mut m2 = vec![0, 0, 1, 0xB3, 0x14, 0, 0xB4, 0x13, 0xFF, 0xFF, 0xE0, 0x18];
    m2.extend_from_slice(&[0, 0, 1, 0x00, 0x00, 1 << 3, 0xFF, 0xF8]);
    assert!(key("mpeg2video", &m2));
    assert!(!key(
        "mpeg2video",
        &[0, 0, 1, 0x00, 0x00, 2 << 3, 0xFF, 0xF8]
    ));
    // MPEG-4 Visual: vop_coding_type in the two bits behind the VOP
    // start code.
    assert!(key(
        "mpeg4video",
        &[0, 0, 1, 0xB0, 1, 0, 0, 1, 0xB6, 0x10, 0]
    ));
    assert!(!key("mpeg4video", &[0, 0, 1, 0xB6, 0x50, 0]));
    // Nothing recognisable, an unknown codec, an empty payload.
    assert!(!key("h264", &[0xAA; 64]));
    assert!(!key("vc1", &[0, 0, 1, 0x65, 0x88]));
    assert!(!key("h264", &[]));
}

/// Table 2-34 values and the descriptors that name a private-data PES
/// stream.
#[test]
fn codecs_named_by_stream_type_and_descriptors() {
    let subtitling = [0x59, 8, b'e', b'n', b'g', 0x10, 0, 1, 0, 1];
    let teletext = [0x56, 5, b'e', b'n', b'g', 0x09, 0x00];
    let mut ts = TsBuilder::default();
    ts.tables(&[
        entry(0x10, 0x100, &[]),
        entry(0x24, 0x101, &[]),
        entry(0x33, 0x102, &[]),
        entry(0x87, 0x103, &[]),
        entry(0x11, 0x104, &[]),
        entry(0x06, 0x105, &[0x7B, 5, 0, 0, 0, 0, 0]),
        entry(0x06, 0x106, &[0x05, 4, b'D', b'T', b'S', b'2']),
        entry(0x06, 0x107, &subtitling),
        entry(0x06, 0x108, &teletext),
        entry(0x06, 0x109, &[0x05, 4, b'E', b'A', b'C', b'3']),
        // No descriptor and no payload: not surfaced.
        entry(0x06, 0x10A, &[]),
    ]);
    ts.pes(0x100, 0xE0, Some(9000), None, &[0; 8], false);
    let d = open(ts.out);
    let got: Vec<(&str, MediaType)> = d
        .streams()
        .iter()
        .map(|s| (s.params.codec_id.as_str(), s.params.media_type))
        .collect();
    assert_eq!(
        got,
        [
            ("mpeg4video", MediaType::Video),
            ("h265", MediaType::Video),
            ("h266", MediaType::Video),
            ("eac3", MediaType::Audio),
            ("aac_latm", MediaType::Audio),
            ("dts", MediaType::Audio),
            ("dts", MediaType::Audio),
            ("dvb_subtitle", MediaType::Subtitle),
            ("dvb_teletext", MediaType::Subtitle),
            ("eac3", MediaType::Audio),
        ]
    );
    assert_eq!(d.streams()[7].params.language.as_deref(), None);
}

/// A private-data PES stream no descriptor names is identified by its
/// payload when that frames as audio.
#[test]
fn undescribed_private_stream_is_identified_by_its_payload() {
    let mut ts = TsBuilder::default();
    ts.tables(&[entry(0x1B, 0x100, &[]), entry(0x06, 0x101, &[])]);
    ts.pes(0x100, 0xE0, Some(9000), None, &[0; 8], true);
    for k in 0..3u64 {
        let mut two = mp2_frame(k as u8);
        two.extend(mp2_frame(0x80 | k as u8));
        ts.pes(0x101, 0xBD, Some(9000 + k * 4320), None, &two, false);
    }
    let mut d = open(ts.out);
    assert_eq!(d.streams()[1].params.codec_id.as_str(), "mp2");
    assert_eq!(d.streams()[1].params.sample_rate, Some(48_000));
    let audio: Vec<Packet> = drain(&mut d)
        .into_iter()
        .filter(|p| p.stream_index == 1)
        .collect();
    assert_eq!(audio.len(), 6);
    assert_eq!(audio[1].pts, Some(9000 + 2160));
    assert_eq!(audio[5].data, mp2_frame(0x82));
}

/// A capture cut mid-stream: the elementary-stream packets ahead of
/// the first PAT / PMT are delivered too, and what is left of a PES
/// packet whose start was cut off is not.
#[test]
fn packets_ahead_of_the_first_tables_are_delivered() {
    let mut ts = TsBuilder::default();
    let entries = [entry(0x1B, 0x100, &[])];
    ts.pes(0x100, 0xE0, Some(1000), None, &[1; 400], true);
    let cut = ts.out.len() - 2 * TS_PACKET_LEN;
    ts.pes(0x100, 0xE0, Some(4600), None, &[2; 30], false);
    ts.pes(0x100, 0xE0, Some(8200), None, &[3; 30], false);
    ts.tables(&entries);
    ts.pes(0x100, 0xE0, Some(11_800), None, &[4; 30], false);
    let pk = drain(&mut open(ts.out[cut..].to_vec()));
    let pts: Vec<Option<i64>> = pk.iter().map(|p| p.pts).collect();
    assert_eq!(pts, [Some(4600), Some(8200), Some(11_800)]);
    assert_eq!(pk[0].data, [2; 30]);
}

/// `stream_type` 0x02 also carries ISO/IEC 11172-2 video; the
/// sequence_extension tells the two apart. The headers are found even
/// when the stream is a single PES packet.
#[test]
fn single_picture_stream_is_probed_and_mpeg1_is_told_from_mpeg2() {
    let sequence = [
        0, 0, 1, 0xB3, 0x14, 0x00, 0xB4, 0x13, 0xFF, 0xFF, 0xE0, 0x18,
    ];
    let extension = [0, 0, 1, 0xB5, 0x14, 0x8A, 0x00, 0x01, 0x00, 0x00];
    let picture = [0, 0, 1, 0x00, 0x00, 0x08, 0xFF, 0xF8, 0, 0, 1, 0x01, 0x12];
    for (with_extension, want) in [(false, "mpeg1video"), (true, "mpeg2video")] {
        let mut es = sequence.to_vec();
        if with_extension {
            es.extend_from_slice(&extension);
        }
        es.extend_from_slice(&picture);
        let mut ts = TsBuilder::default();
        ts.tables(&[entry(0x02, 0x100, &[])]);
        ts.pes(0x100, 0xE0, Some(9000), None, &es, false);
        let mut d = open(ts.out);
        let p = &d.streams()[0].params;
        assert_eq!(p.codec_id.as_str(), want);
        assert_eq!((p.width, p.height), (Some(320), Some(180)));
        let pk = drain(&mut d);
        assert_eq!(pk.len(), 1);
        assert!(pk[0].flags.keyframe, "an intra picture without indicator");
    }
}

/// LATM audio: one packet per `AudioSyncStream()` frame, timed from the
/// `StreamMuxConfig()` — also the frames that only refer to it.
#[test]
fn latm_audio_is_split_into_frames() {
    let frames = [
        loas_frame(200, true, 0x11),
        loas_frame(150, false, 0x22),
        loas_frame(170, false, 0x33),
    ];
    let mut ts = TsBuilder::default();
    ts.tables(&[entry(0x11, 0x100, &[])]);
    ts.pes(0x100, 0xC0, Some(90_000), None, &frames.concat(), false);
    ts.pes(0x100, 0xC0, Some(95_760), None, &frames[1], false);
    let mut d = open(ts.out);
    let p = &d.streams()[0].params;
    assert_eq!(p.codec_id.as_str(), "aac_latm");
    assert_eq!((p.sample_rate, p.channels), (Some(48_000), Some(2)));
    let pk = drain(&mut d);
    let got: Vec<(Option<i64>, usize)> = pk.iter().map(|p| (p.pts, p.data.len())).collect();
    assert_eq!(
        got,
        [
            (Some(90_000), 200),
            (Some(91_920), 150),
            (Some(93_840), 170),
            (Some(95_760), 150),
        ]
    );
    assert_eq!(pk[2].data, frames[2]);
    assert_eq!(pk[2].duration, Some(1920));
}

/// DTS: a core frame and the extension substream behind it are one
/// access unit (ETSI TS 102 114 Annex F.3.3).
#[test]
fn dts_core_and_extension_form_one_access_unit() {
    let core = dts_core_frame(120, 0x44);
    let ext = dts_extension(60, 0x55);
    let unit = [core.clone(), ext.clone()].concat();
    let mut ts = TsBuilder::default();
    ts.tables(&[entry(0x06, 0x100, &[0x05, 4, b'D', b'T', b'S', b'H'])]);
    ts.pes(
        0x100,
        0xBD,
        Some(90_000),
        None,
        &[unit.clone(), core.clone()].concat(),
        false,
    );
    ts.pes(0x100, 0xBD, Some(91_920), None, &unit, false);
    let mut d = open(ts.out);
    let p = &d.streams()[0].params;
    assert_eq!(p.codec_id.as_str(), "dts");
    assert_eq!((p.sample_rate, p.channels), (Some(48_000), Some(2)));
    assert_eq!(p.bit_rate, Some(768_000));
    let pk = drain(&mut d);
    let got: Vec<(Option<i64>, usize)> = pk.iter().map(|p| (p.pts, p.data.len())).collect();
    assert_eq!(
        got,
        [
            (Some(90_000), 180),
            (Some(90_960), 120),
            (Some(91_920), 180)
        ]
    );
    assert_eq!(pk[0].data, unit);
}

#[test]
fn dts_and_loas_headers_reject_what_the_tables_forbid() {
    // NBLKS below 5, FSIZE below 95, an invalid SFREQ.
    let good = dts_core_frame(120, 0);
    assert!(crate::parse_dts_header(&good).is_some());
    let mut nblks = good.clone();
    nblks[4] &= 0xFE;
    nblks[5] = 0x0C | (nblks[5] & 0x03);
    assert!(crate::parse_dts_header(&nblks).is_none());
    assert!(crate::parse_dts_header(&dts_core_frame(90, 0)).is_none());
    assert!(crate::parse_dts_header(&good[..10]).is_none());
    assert!(crate::parse_loas_header(&[0x56, 0xE0]).is_none());
    assert!(crate::parse_loas_header(&[0x57, 0xE0, 0x10]).is_none());
    // A frame cut right behind its length field still sizes.
    let head = crate::parse_loas_header(&[0x56, 0xE0, 0x10]).unwrap();
    assert_eq!((head.frame_len, head.sample_rate), (19, 0));
}
