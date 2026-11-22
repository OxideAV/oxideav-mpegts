//! MPEG-2 **program stream** demuxer (ISO/IEC 13818-1 §2.5) —
//! the `.mpg` / `.vob` / `.m2p` multiplex: packs (`pack_header()`,
//! Table 2-33, start code `0x000001BA`), optional system headers
//! (Table 2-34, `0x000001BB`), PES packets (§2.5.3.7 → the §2.4.3.6
//! PES layer, Table 2-17), the program stream map (§2.5.4, Table 2-35,
//! `stream_id` 0xBC) and the `MPEG_program_end_code` (`0x000001B9`).
//!
//! ## Streams
//!
//! Elementary streams are keyed by `stream_id` (Table 2-18): `0xE0..=0xEF`
//! video, `0xC0..=0xDF` audio, and `0xBD` private_stream_1. A program
//! stream map, when present, names each `elementary_stream_id`'s
//! `stream_type` (Table 2-29 — the same codec map the transport-stream
//! demuxer uses); otherwise the codec is recognised from the first
//! payload bytes (MPEG-1/2 `sequence_header_code`, an H.264 SPS / access
//! unit delimiter, an MPEG audio or ADTS frame header).
//!
//! private_stream_1 follows the DVD-Video convention staged under
//! `docs/container/dvd/application/` (`dvd-substream-ids-and-copy-protection.md`
//! §1, `stnsoft-ass-hdr.html`, `mpucoder-lpcm.html`): the first payload
//! byte is a sub-stream number — `0x80..=0x87` AC-3, `0x88..=0x8F` DTS,
//! `0xA0..=0xA7` LPCM, `0x20..=0x3F` sub-picture — followed (audio only)
//! by the 3-byte `FrmCnt` + `FirstAccUnit` prefix, which LPCM extends by
//! three bytes of quantisation / sample-rate / channel fields.
//!
//! ## Access units
//!
//! Program-stream PES packets are sized by the multiplex (a DVD pack is
//! 2048 bytes), not by the elementary stream, so the demuxer re-frames:
//!
//! * audio with staged framing (AC-3 / E-AC-3, MPEG-1/2 audio, ADTS) is
//!   cut one syncframe per packet by [`crate::AudioFrameSplitter`];
//! * MPEG-1/2 video is cut at the `sequence_header` / `group_start` /
//!   `picture_start` code that follows a coded picture (H.262 §6.2.2 —
//!   a picture's slices run until the next non-slice start code), with
//!   the `picture_coding_type` of an I-picture flagging the keyframe;
//! * H.264 is cut at the first NAL unit of the next access unit
//!   (H.264 §7.4.1.2.3: an access unit delimiter, SPS, PPS, SEI, prefix
//!   or reserved 14..=18 NAL after a VCL NAL, or a VCL NAL whose
//!   `first_mb_in_slice` is 0), with IDR slices flagging the keyframe;
//! * DTS, LPCM and sub-pictures stay one packet per PES payload.
//!
//! A PES PTS belongs to the first access unit that commences in that
//! PES (§2.7.5); the splitters carry that rule across PES boundaries.
//!
//! ## Not supported
//!
//! ISO/IEC 11172-1 (MPEG-1 Systems) streams — whose pack header begins
//! `'0010'` instead of `'01'` — are rejected at open: §2.8 requires a
//! program-stream decoder to accept them, but the 11172-1 pack and
//! packet header syntax is not staged under `docs/`.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, SeekFrom};

use oxideav_core::{
    CodecId, CodecParameters, CodecResolver, Demuxer, Error as CoreError, Packet, ReadSeek,
    Result as CoreResult, StreamInfo, TimeBase,
};

use crate::clock::NearestEpochUnwrap;
use crate::{AudioFrameSplitter, AudioSyntax, PesPacket};

/// `pack_start_code` (§2.5.3.4).
const PACK_START: u8 = 0xBA;
/// `system_header_start_code` (§2.5.3.6).
const SYSTEM_HEADER_START: u8 = 0xBB;
/// `MPEG_program_end_code` (§2.5.3.2).
const PROGRAM_END: u8 = 0xB9;
/// `program_stream_map` stream_id (Table 2-18).
const PSM_STREAM_ID: u8 = 0xBC;
/// `private_stream_1` stream_id (Table 2-18).
const PRIVATE_STREAM_1: u8 = 0xBD;

/// Bytes the open-time discovery pass reads to enumerate streams and
/// lift their parameters.
const DISCOVERY_BYTES: u64 = 4 << 20;
/// Read granularity of the internal buffer.
const READ_CHUNK: usize = 64 << 10;

/// Open factory matching `oxideav_core::OpenDemuxerFn`, registered
/// under the `"mpegps"` container name.
pub fn open(input: Box<dyn ReadSeek>, codecs: &dyn CodecResolver) -> CoreResult<Box<dyn Demuxer>> {
    let _ = codecs;
    MpegPsDemuxer::new(input).map(|d| Box::new(d) as Box<dyn Demuxer>)
}

/// Probe for an MPEG-2 program stream: a `pack_header()` with the
/// `'01'` marker at offset 0 (Table 2-33) whose `pack_stuffing_length`
/// lands on another start-code prefix scores 100; the pack header
/// alone 75. ISO/IEC 11172-1 packs (`'0010'`) score 0 — see the module
/// docs.
pub fn probe(p: &oxideav_core::ProbeData) -> oxideav_core::ProbeScore {
    let b = p.buf;
    if b.len() < 14 || b[..4] != [0, 0, 1, PACK_START] || b[4] & 0xC0 != 0x40 {
        return 0;
    }
    let next = 14 + (b[13] & 0x07) as usize;
    if b.len() >= next + 3 && b[next..next + 3] == [0, 0, 1] {
        100
    } else {
        75
    }
}

/// Key of one elementary stream: `stream_id`, plus the DVD sub-stream
/// number for private_stream_1.
type StreamKey = (u8, Option<u8>);

/// How a stream's PES payloads become packets.
#[derive(Debug)]
enum Framing {
    /// One packet per complete audio access unit.
    Audio(AudioFrameSplitter),
    /// One packet per video access unit.
    Video(VideoAuSplitter),
    /// One packet per PES payload.
    Whole,
}

#[derive(Debug)]
struct EsState {
    /// Payload bytes to drop at the head of every PES (DVD sub-stream
    /// prefix).
    strip: usize,
    framing: Framing,
    pts: NearestEpochUnwrap,
    dts: NearestEpochUnwrap,
    /// For a 16-bit LPCM stream: bytes per second, and the
    /// presentation time the next packet starts at when its PES packet
    /// codes none (the samples are contiguous).
    pcm_rate: Option<i64>,
    pcm_next: Option<i64>,
}

/// MPEG-2 program stream demuxer.
pub struct MpegPsDemuxer {
    input: Box<dyn ReadSeek>,
    buf: Vec<u8>,
    pos: usize,
    /// Input bytes already compacted out of `buf`: the absolute offset
    /// of `buf[0]`.
    drained: u64,
    eof: bool,
    streams: Vec<StreamInfo>,
    keys: HashMap<StreamKey, u32>,
    states: Vec<EsState>,
    pending: VecDeque<Packet>,
    flushed: bool,
    duration_micros: Option<i64>,
}

impl std::fmt::Debug for MpegPsDemuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpegPsDemuxer")
            .field("streams", &self.streams.len())
            .field("pending", &self.pending.len())
            .finish()
    }
}

/// One unit the byte walk produced.
enum Unit {
    /// A PES packet (header + payload): its byte range in the read
    /// buffer, valid until the next unit is read.
    Pes(std::ops::Range<usize>),
    /// Anything else (pack header, system header, end code, resync).
    Other,
}

impl MpegPsDemuxer {
    fn new(mut input: Box<dyn ReadSeek>) -> CoreResult<Self> {
        input.seek(SeekFrom::Start(0)).map_err(CoreError::Io)?;
        let mut d = Self {
            input,
            buf: Vec::new(),
            pos: 0,
            drained: 0,
            eof: false,
            streams: Vec::new(),
            keys: HashMap::new(),
            states: Vec::new(),
            pending: VecDeque::new(),
            flushed: false,
            duration_micros: None,
        };
        d.fill(14)?;
        let head = &d.buf[d.pos..];
        if head.len() < 5 || head[..4] != [0, 0, 1, PACK_START] {
            return Err(CoreError::invalid(
                "mpegps: stream does not start with a pack_header (0x000001BA)",
            ));
        }
        if head[4] & 0xF0 == 0x20 {
            return Err(CoreError::unsupported(
                "mpegps: ISO/IEC 11172-1 (MPEG-1 Systems) pack header — the 11172-1 \
                 pack/packet syntax is not staged; only ISO/IEC 13818-1 program streams \
                 are demuxed",
            ));
        }
        if head[4] & 0xC0 != 0x40 {
            return Err(CoreError::invalid(
                "mpegps: pack_header lacks the '01' marker",
            ));
        }
        d.discover()?;
        d.duration_micros = d.scr_duration();
        if let Some(total) = d.duration_micros {
            let ticks = (total as i128 * 90_000 / 1_000_000) as i64;
            for s in &mut d.streams {
                s.duration = Some(ticks);
            }
        }
        d.input.seek(SeekFrom::Start(0)).map_err(CoreError::Io)?;
        d.buf.clear();
        d.pos = 0;
        d.drained = 0;
        d.eof = false;
        if d.streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegps: no elementary stream found in the first packs",
            ));
        }
        Ok(d)
    }

    /// Make sure at least `n` bytes are buffered past `pos` (fewer at
    /// end of input).
    fn fill(&mut self, n: usize) -> CoreResult<()> {
        while self.buf.len().saturating_sub(self.pos) < n && !self.eof {
            if self.pos > 0 && self.pos >= self.buf.len() / 2 {
                self.buf.drain(..self.pos);
                self.drained += self.pos as u64;
                self.pos = 0;
            }
            let old = self.buf.len();
            self.buf.resize(old + READ_CHUNK, 0);
            let got = loop {
                match self.input.read(&mut self.buf[old..]) {
                    Ok(g) => break g,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        self.buf.truncate(old);
                        return Err(CoreError::Io(e));
                    }
                }
            };
            self.buf.truncate(old + got);
            if got == 0 {
                self.eof = true;
            }
        }
        Ok(())
    }

    /// Walk to the next unit. `None` at end of input.
    fn next_unit(&mut self) -> CoreResult<Option<Unit>> {
        // Find a start-code prefix.
        loop {
            self.fill(4)?;
            let avail = &self.buf[self.pos..];
            if avail.len() < 4 {
                self.pos = self.buf.len();
                return Ok(None);
            }
            if avail[..3] == [0, 0, 1] {
                break;
            }
            // Skip to the next candidate prefix in the buffered window.
            match avail.windows(3).position(|w| w == [0, 0, 1]) {
                Some(i) => self.pos += i,
                None => self.pos += avail.len() - 2,
            }
        }
        let code = self.buf[self.pos + 3];
        match code {
            PACK_START => {
                self.fill(14)?;
                let b = &self.buf[self.pos..];
                if b.len() < 14 || b[4] & 0xC0 != 0x40 {
                    // Not a 13818-1 pack header (or truncated): resync
                    // past the start code.
                    self.pos += 4.min(b.len());
                    return Ok(Some(Unit::Other));
                }
                // pack_stuffing_length (Table 2-39) may claim stuffing
                // bytes the input does not hold: buffer them, and never
                // step the cursor past the buffered window.
                let total = 14 + (b[13] & 0x07) as usize;
                self.fill(total)?;
                self.pos = (self.pos + total).min(self.buf.len());
                Ok(Some(Unit::Other))
            }
            PROGRAM_END => {
                self.pos += 4;
                Ok(Some(Unit::Other))
            }
            0xBB..=0xFF => {
                self.fill(6)?;
                let b = &self.buf[self.pos..];
                if b.len() < 6 {
                    self.pos = self.buf.len();
                    return Ok(None);
                }
                let len = u16::from_be_bytes([b[4], b[5]]) as usize;
                let total = 6 + len;
                if code == SYSTEM_HEADER_START {
                    self.fill(total)?;
                    self.pos = (self.pos + total).min(self.buf.len());
                    return Ok(Some(Unit::Other));
                }
                if len == 0 {
                    // §2.4.3.7: an unbounded PES_packet_length is only
                    // permitted for video in transport streams.
                    self.pos += 4;
                    return Ok(Some(Unit::Other));
                }
                self.fill(total)?;
                let end = (self.pos + total).min(self.buf.len());
                let pes = self.pos..end;
                self.pos = end;
                Ok(Some(Unit::Pes(pes)))
            }
            _ => {
                // An elementary-stream start code seen at the pack
                // layer (stray bytes): resync past it.
                self.pos += 3;
                Ok(Some(Unit::Other))
            }
        }
    }

    /// Open-time pass: read up to [`DISCOVERY_BYTES`], parse any
    /// program stream map, enumerate streams in order of first
    /// appearance and fill their parameters from the first payloads.
    fn discover(&mut self) -> CoreResult<()> {
        let mut psm: HashMap<u8, u8> = HashMap::new();
        let mut order: Vec<StreamKey> = Vec::new();
        let mut first_pts: HashMap<StreamKey, u64> = HashMap::new();
        let mut payloads: HashMap<StreamKey, Vec<u8>> = HashMap::new();
        let mut first_raw: HashMap<StreamKey, Vec<u8>> = HashMap::new();
        // Absolute input offsets, so a buffer compaction inside
        // `next_unit` cannot hide progress from the budget.
        let start = self.drained + self.pos as u64;
        while self.drained + self.pos as u64 - start < DISCOVERY_BYTES {
            let Some(unit) = self.next_unit()? else {
                break;
            };
            let Unit::Pes(range) = unit else {
                continue;
            };
            let bytes = self.buf[range].to_vec();
            let sid = bytes[3];
            if sid == PSM_STREAM_ID {
                parse_psm(&bytes, &mut psm);
                continue;
            }
            if !is_es_stream_id(sid) {
                continue;
            }
            let Ok(pes) = PesPacket::parse(&bytes) else {
                continue;
            };
            let key = stream_key(sid, &pes.payload);
            let Some(key) = key else {
                continue;
            };
            if !order.contains(&key) {
                order.push(key);
            }
            if let Some(p) = pes.pts_90k {
                first_pts.entry(key).or_insert(p);
            }
            first_raw.entry(key).or_insert_with(|| pes.payload.clone());
            let acc = payloads.entry(key).or_default();
            if acc.len() < (1 << 20) {
                acc.extend_from_slice(pes.payload.get(private_prefix(key.1)..).unwrap_or(&[]));
            }
        }
        // Video first, then audio, then the rest — stable within class.
        order.sort_by_key(|k| match k.0 {
            0xE0..=0xEF => 0,
            0xC0..=0xDF => 1,
            _ => 2 + u8::from(k.1.is_some_and(|s| (0x20..=0x3F).contains(&s))),
        });
        for key in order {
            let data = payloads.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            let raw = first_raw.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            let Some((params, framing)) = classify(key, psm.get(&key.0).copied(), data, raw) else {
                continue;
            };
            let idx = self.streams.len() as u32;
            let pcm_rate = match (
                params.codec_id.as_str(),
                params.sample_rate,
                params.channels,
            ) {
                ("pcm_s16be", Some(rate), Some(ch)) => Some(i64::from(rate) * i64::from(ch) * 2),
                _ => None,
            };
            self.streams.push(StreamInfo {
                index: idx,
                time_base: TimeBase::new(1, 90_000),
                duration: None,
                start_time: first_pts.get(&key).map(|&p| p as i64),
                params,
            });
            self.keys.insert(key, idx);
            self.states.push(EsState {
                strip: private_prefix(key.1),
                framing,
                pts: NearestEpochUnwrap::default(),
                dts: NearestEpochUnwrap::default(),
                pcm_rate,
                pcm_next: None,
            });
        }
        Ok(())
    }

    /// Duration from the head-to-tail SCR span (§2.5.3.4, 27 MHz
    /// `SCR_base × 300 + SCR_ext`), probed over the first and last
    /// 1 MiB. `None` when either end carries no 13818-1 pack header.
    fn scr_duration(&mut self) -> Option<i64> {
        const WINDOW: u64 = 1 << 20;
        let len = self.input.seek(SeekFrom::End(0)).ok()?;
        let mut head = vec![0u8; WINDOW.min(len) as usize];
        self.input.seek(SeekFrom::Start(0)).ok()?;
        self.input.read_exact(&mut head).ok()?;
        let first = find_scr(&head, false)?;
        let tail_start = len.saturating_sub(WINDOW);
        let mut tail = vec![0u8; (len - tail_start) as usize];
        self.input.seek(SeekFrom::Start(tail_start)).ok()?;
        self.input.read_exact(&mut tail).ok()?;
        let last = find_scr(&tail, true)?;
        (last > first).then(|| ((last - first) / 27) as i64)
    }

    /// Route one PES into the pending queue.
    fn handle_pes(&mut self, bytes: &[u8]) {
        let sid = bytes[3];
        if !is_es_stream_id(sid) {
            return;
        }
        let Ok((pes, body_at)) = PesPacket::parse_header(bytes) else {
            return;
        };
        let body = bytes.get(body_at..).unwrap_or(&[]);
        let Some(key) = stream_key(sid, body) else {
            return;
        };
        let Some(&idx) = self.keys.get(&key) else {
            return;
        };
        let st = &mut self.states[idx as usize];
        let payload = body.get(st.strip..).unwrap_or(&[]);
        // 33-bit unwrap onto one 64-bit axis, tolerant of the backward
        // steps B-picture reordering puts into presentation times.
        let pts = pes.pts_90k.map(|raw| st.pts.extend(raw) as i64);
        let dts = pes.dts_90k.map(|raw| {
            if !st.dts.is_anchored()
                && let Some(p) = pts
            {
                st.dts.seed(p as u64);
            }
            st.dts.extend(raw) as i64
        });
        let tb = TimeBase::new(1, 90_000);
        match &mut st.framing {
            Framing::Audio(sp) => {
                let was_locked = sp.is_locked();
                let frames = sp.push(payload, pts);
                if frames.is_empty() && !was_locked {
                    sp.unlock();
                    let mut p = Packet::new(idx, tb, payload.to_vec()).with_keyframe(true);
                    if let Some(t) = pts {
                        p = p.with_pts(t).with_dts(t);
                    }
                    self.pending.push_back(p);
                    return;
                }
                for f in frames {
                    self.pending.push_back(audio_packet(idx, f));
                }
            }
            Framing::Video(v) => {
                for au in v.push(payload, pts, dts) {
                    self.pending.push_back(au.into_packet(idx));
                }
            }
            Framing::Whole => {
                // Audio and sub-picture units are each an entry point;
                // a video stream passed through whole has no known
                // picture boundaries.
                let key =
                    self.streams[idx as usize].params.media_type != oxideav_core::MediaType::Video;
                let pts = pts.or(st.pcm_next);
                if let (Some(t), Some(rate)) = (pts, st.pcm_rate) {
                    st.pcm_next = Some(t.saturating_add(payload.len() as i64 * 90_000 / rate));
                }
                let mut p = Packet::new(idx, tb, payload.to_vec()).with_keyframe(key);
                if let Some(t) = pts {
                    p = p.with_pts(t);
                }
                if let Some(t) = dts.or(pts) {
                    p = p.with_dts(t);
                }
                self.pending.push_back(p);
            }
        }
    }

    /// Drain every splitter at end of stream.
    fn flush_all(&mut self) {
        for (idx, st) in self.states.iter_mut().enumerate() {
            match &mut st.framing {
                Framing::Audio(sp) => {
                    if let Some(f) = sp.flush() {
                        self.pending.push_back(audio_packet(idx as u32, f));
                    }
                }
                Framing::Video(v) => {
                    if let Some(au) = v.flush() {
                        self.pending.push_back(au.into_packet(idx as u32));
                    }
                }
                Framing::Whole => {}
            }
        }
    }
}

fn audio_packet(idx: u32, f: crate::AudioFrame) -> Packet {
    let dur = f.info.duration_90k() as i64;
    let mut p = Packet::new(idx, TimeBase::new(1, 90_000), f.data).with_keyframe(true);
    if let Some(t) = f.pts {
        p = p.with_pts(t).with_dts(t);
    }
    if dur > 0 {
        p = p.with_duration(dur);
    }
    p
}

/// Bytes read around a probe offset while looking for a pack header.
const SEEK_PROBE_BYTES: usize = 256 << 10;

/// How far ahead of its presentation a seek first looks for a key
/// frame, in 90 kHz ticks: the §2.5.2.3 P-STD delay bound (one second)
/// plus half a second of pictures. Doubled while nothing is found.
const SEEK_LEAD_90K: i64 = 135_000;

impl MpegPsDemuxer {
    /// Offset and SCR base (90 kHz) of the first pack header at or
    /// after `from`.
    fn pack_from(&mut self, from: u64) -> Option<(u64, i64)> {
        self.input.seek(SeekFrom::Start(from)).ok()?;
        let mut window = vec![0u8; SEEK_PROBE_BYTES];
        let mut filled = 0;
        while filled < window.len() {
            match self.input.read(&mut window[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
        let window = &window[..filled];
        let at = (0..window.len().saturating_sub(13))
            .find(|&i| window[i..i + 4] == [0, 0, 1, PACK_START] && window[i + 4] & 0xC0 == 0x40)?;
        let scr = find_scr(&window[at..], false)?;
        Some((from + at as u64, (scr / 300) as i64))
    }

    /// Start reading at `offset` (a pack header, or 0) as if the stream
    /// began there, with every time stamp unwrapped next to `hint`.
    fn reposition(&mut self, offset: u64, hint: i64) -> CoreResult<()> {
        self.input
            .seek(SeekFrom::Start(offset))
            .map_err(CoreError::Io)?;
        self.buf.clear();
        self.pos = 0;
        self.drained = offset;
        self.eof = false;
        self.flushed = false;
        self.pending.clear();
        // Time stamps live on the 33-bit ring and are unwrapped next to
        // the hint: a target outside the stream's own span must not
        // move them to another turn of the ring.
        let first = self
            .streams
            .iter()
            .filter_map(|s| s.start_time)
            .min()
            .unwrap_or(0);
        let span = self
            .duration_micros
            .map_or(1 << 32, |us| (us as i128 * 9 / 100) as i64);
        let near = hint.clamp(first, first.saturating_add(span)).max(0) as u64;
        for st in &mut self.states {
            match &mut st.framing {
                Framing::Audio(sp) => sp.reset(),
                Framing::Video(v) => {
                    let mut fresh = VideoAuSplitter::new(v.kind);
                    fresh.period = v.period;
                    *v = fresh;
                }
                Framing::Whole => {}
            }
            st.pts.seed(near);
            st.dts.seed(near);
            st.pcm_next = None;
        }
        Ok(())
    }

    /// The next packet of stream `index`, others dropped. `None` at end
    /// of stream.
    fn next_of(&mut self, index: u32) -> CoreResult<Option<Packet>> {
        loop {
            match self.next_packet() {
                Ok(p) if p.stream_index == index => return Ok(Some(p)),
                Ok(_) => {}
                Err(CoreError::Eof) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
}

impl Demuxer for MpegPsDemuxer {
    fn format_name(&self) -> &str {
        "mpegps"
    }

    /// Land on the last key frame of `stream_index` at or before `pts`
    /// (the first one of the stream when `pts` precedes it): a bisection
    /// over the pack headers' SCR (§2.5.3.4) finds a pack far enough
    /// ahead, and the stream is read forward from there. The next
    /// packet of that stream is the key frame; other streams resume
    /// from the same point in the multiplex.
    fn seek_to(&mut self, stream_index: u32, pts: i64) -> CoreResult<i64> {
        if stream_index as usize >= self.streams.len() {
            return Err(CoreError::invalid(format!(
                "mpegps: no stream {stream_index}"
            )));
        }
        let len = self.input.seek(SeekFrom::End(0)).map_err(CoreError::Io)?;
        let mut lead = SEEK_LEAD_90K;
        loop {
            // The last pack whose SCR is at or before `pts - lead`.
            let want = pts.saturating_sub(lead);
            let (mut lo, mut hi) = (0u64, len);
            while hi - lo > SEEK_PROBE_BYTES as u64 / 2 {
                let mid = lo + (hi - lo) / 2;
                match self.pack_from(mid) {
                    Some((at, scr)) if scr <= want && at < hi => lo = at.max(lo + 1),
                    _ => hi = mid,
                }
            }
            // A lead beyond any 33-bit time span means the whole
            // stream.
            let offset = match self.pack_from(lo) {
                Some((at, scr)) if scr <= want && lead < 1 << 34 => at,
                _ => 0,
            };
            // First pass: which key frame.
            self.reposition(offset, pts)?;
            let mut before = None;
            let mut after = None;
            while let Some(p) = self.next_of(stream_index)? {
                let Some(t) = p.pts.or(p.dts) else { continue };
                if !p.flags.keyframe {
                    continue;
                }
                if t <= pts {
                    before = Some(t);
                } else {
                    after = Some(t);
                    break;
                }
            }
            if before.is_none() && offset > 0 {
                // A long group of pictures: start further back.
                lead = lead.saturating_mul(2);
                continue;
            }
            let Some(landing) = before.or(after) else {
                return Err(CoreError::unsupported(
                    "mpegps: the stream has no time-stamped key frame to seek to",
                ));
            };
            // Second pass: stop on it.
            self.reposition(offset, pts)?;
            while let Some(p) = self.next_of(stream_index)? {
                if p.flags.keyframe && p.pts.or(p.dts) == Some(landing) {
                    self.pending.push_front(p);
                    return Ok(landing);
                }
            }
            return Err(CoreError::invalid(
                "mpegps: key frame vanished between passes",
            ));
        }
    }

    fn streams(&self) -> &[StreamInfo] {
        &self.streams
    }

    fn duration_micros(&self) -> Option<i64> {
        self.duration_micros
    }

    fn next_packet(&mut self) -> CoreResult<Packet> {
        loop {
            if let Some(p) = self.pending.pop_front() {
                return Ok(p);
            }
            if self.flushed {
                return Err(CoreError::Eof);
            }
            match self.next_unit()? {
                Some(Unit::Pes(range)) => {
                    // The packet is parsed where it was read.
                    let buf = std::mem::take(&mut self.buf);
                    self.handle_pes(&buf[range]);
                    self.buf = buf;
                }
                Some(Unit::Other) => {}
                None => {
                    self.flush_all();
                    self.flushed = true;
                }
            }
        }
    }
}

/// Table 2-18 elementary-stream ids this demuxer routes.
fn is_es_stream_id(sid: u8) -> bool {
    matches!(sid, 0xC0..=0xEF | PRIVATE_STREAM_1)
}

/// The stream key of a PES: private_stream_1 adds its sub-stream byte.
fn stream_key(sid: u8, payload: &[u8]) -> Option<StreamKey> {
    if sid == PRIVATE_STREAM_1 {
        let sub = *payload.first()?;
        matches!(sub, 0x20..=0x3F | 0x80..=0x8F | 0xA0..=0xA7).then_some((sid, Some(sub)))
    } else {
        Some((sid, None))
    }
}

/// DVD private_stream_1 prefix length for a sub-stream number:
/// sub-picture 1 (the number), AC-3 / DTS 4 (number + FrmCnt +
/// FirstAccUnit), LPCM 7 (plus the three LPCM header bytes).
fn private_prefix(sub: Option<u8>) -> usize {
    match sub {
        None => 0,
        Some(0x20..=0x3F) => 1,
        Some(0x80..=0x8F) => 4,
        Some(0xA0..=0xA7) => 7,
        Some(_) => 0,
    }
}

/// §2.5.4.1 Table 2-35: record `elementary_stream_id → stream_type`.
fn parse_psm(b: &[u8], out: &mut HashMap<u8, u8>) {
    // start(3) id(1) length(2) cni/version(1) marker(1) info_len(2)
    if b.len() < 10 {
        return;
    }
    let info_len = u16::from_be_bytes([b[8], b[9]]) as usize;
    let mut i = 10 + info_len;
    let Some(map_len) = b
        .get(i..i + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]) as usize)
    else {
        return;
    };
    i += 2;
    let end = (i + map_len).min(b.len().saturating_sub(4));
    while i + 4 <= end {
        let st = b[i];
        let es_id = b[i + 1];
        let es_info = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        out.insert(es_id, st);
        i += 4 + es_info;
    }
}

/// Codec + framing for one stream key.
fn classify(
    key: StreamKey,
    psm_type: Option<u8>,
    data: &[u8],
    raw: &[u8],
) -> Option<(CodecParameters, Framing)> {
    use crate::es_params::{apply_audio, apply_video, h264_params, looks_like_h264, mpeg12_params};
    let (sid, sub) = key;
    if let Some(sub) = sub {
        return Some(match sub {
            0x80..=0x87 => {
                let mut p = CodecParameters::audio(CodecId::new("ac3"));
                let sp = AudioFrameSplitter::new(AudioSyntax::Ac3);
                if let Some(i) = crate::parse_ac3_frame(data) {
                    apply_audio(&mut p, &i);
                }
                (p, Framing::Audio(sp))
            }
            0x88..=0x8F => {
                let mut p = CodecParameters::audio(CodecId::new("dts"));
                let sp = AudioFrameSplitter::new(AudioSyntax::Dts);
                if let Some(i) = crate::parse_dts_header(data) {
                    apply_audio(&mut p, &i);
                }
                (p, Framing::Audio(sp))
            }
            0xA0..=0xA7 => {
                // mpucoder-lpcm.html byte 5: quantisation_word_length(2)
                // audio_sample_frequency(2) reserved(1)
                // number_of_audio_channels(3, X + 1). Only the 16-bit
                // word length is plain big-endian interleaved PCM; the
                // 20/24-bit DVD packing is a separate layout.
                let b5 = *raw.get(5)?;
                if b5 >> 6 != 0 {
                    return None;
                }
                let mut p = CodecParameters::audio(CodecId::new("pcm_s16be"));
                p.sample_rate = match (b5 >> 4) & 0x03 {
                    0 => Some(48_000),
                    1 => Some(96_000),
                    _ => None,
                };
                p.channels = Some((b5 & 0x07) as u16 + 1);
                (p, Framing::Whole)
            }
            _ => (
                CodecParameters::subtitle(CodecId::new("dvd_subtitle")),
                Framing::Whole,
            ),
        });
    }
    match sid {
        0xE0..=0xEF => {
            let from_psm = psm_type
                .and_then(crate::demuxer::codec_params_for_stream_type)
                .filter(|p| p.media_type == oxideav_core::MediaType::Video);
            let mut p = match from_psm {
                Some(p) => p,
                None => {
                    // An MPEG-1/2 sequence header wins: its slice start
                    // codes (0x01..=0xAF) overlap H.264 NAL header bytes.
                    // An ISO/IEC 14496-2 stream is told by how it opens:
                    // its group_of_vop_start_code shares the value of
                    // the MPEG-1/2 sequence_header_code.
                    let id = match mpeg12_params(data) {
                        _ if crate::es_params::looks_like_mpeg4_visual(data) => "mpeg4video",
                        Some(v) if !v.mpeg2 => "mpeg1video",
                        Some(_) => "mpeg2video",
                        None if looks_like_h264(data) => "h264",
                        None => "mpeg2video",
                    };
                    CodecParameters::video(CodecId::new(id))
                }
            };
            let kind = match p.codec_id.as_str() {
                "h264" => VideoKind::H264,
                "mpeg1video" | "mpeg2video" => VideoKind::Mpeg12,
                "mpeg4video" => VideoKind::Mpeg4,
                _ => return Some((p, Framing::Whole)),
            };
            let v = match kind {
                VideoKind::H264 => h264_params(data),
                VideoKind::Mpeg12 => mpeg12_params(data),
                VideoKind::Mpeg4 => None,
            };
            if let Some(v) = v {
                apply_video(&mut p, &v);
            }
            let mut splitter = VideoAuSplitter::new(kind);
            if let Some(r) = p.frame_rate
                && r.num > 0
                && r.den > 0
            {
                splitter.period = Some((90_000 * r.den + r.num / 2) / r.num);
            }
            Some((p, Framing::Video(splitter)))
        }
        0xC0..=0xDF => {
            let from_psm = psm_type
                .and_then(crate::demuxer::codec_params_for_stream_type)
                .filter(|p| p.media_type == oxideav_core::MediaType::Audio);
            let adts = psm_type == Some(0x0F)
                || (psm_type.is_none() && crate::parse_adts_header(data).is_some());
            let mut p = from_psm.unwrap_or_else(|| {
                CodecParameters::audio(CodecId::new(if adts { "aac" } else { "mp2" }))
            });
            let syntax = if adts {
                AudioSyntax::AacAdts
            } else if p.codec_id.as_str() == "aac" {
                return Some((p, Framing::Whole));
            } else {
                AudioSyntax::MpegAudio
            };
            if let Some(i) = syntax.parse(data) {
                apply_audio(&mut p, &i);
            }
            Some((p, Framing::Audio(AudioFrameSplitter::new(syntax))))
        }
        _ => None,
    }
}

/// First (`last = false`) or last SCR in `buf`, in 27 MHz ticks.
fn find_scr(buf: &[u8], last: bool) -> Option<u64> {
    let mut found = None;
    let mut i = 0;
    while i + 10 <= buf.len() {
        if buf[i..i + 4] == [0, 0, 1, PACK_START] && buf[i + 4] & 0xC0 == 0x40 {
            let b = &buf[i + 4..i + 10];
            // Table 2-33: '01' base[32..30] m base[29..15] m base[14..0]
            // m ext(9) m.
            let base = ((b[0] as u64 >> 3) & 0x07) << 30
                | ((b[0] as u64) & 0x03) << 28
                | (b[1] as u64) << 20
                | ((b[2] as u64) >> 3) << 15
                | ((b[2] as u64) & 0x03) << 13
                | (b[3] as u64) << 5
                | (b[4] as u64) >> 3;
            let ext = ((b[4] as u64) & 0x03) << 7 | (b[5] as u64) >> 1;
            found = Some(base * 300 + ext);
            if !last {
                return found;
            }
            i += 14;
        } else {
            i += 1;
        }
    }
    found
}

/// Ceiling on the elementary-stream bytes one video stream buffers
/// while waiting for an access-unit boundary.
const MAX_AU_BYTES: usize = 16 << 20;

/// Ceiling on the PES timestamps waiting for their access unit.
const MAX_ANCHORS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VideoKind {
    Mpeg12,
    H264,
    Mpeg4,
}

/// One cut video access unit.
#[derive(Debug)]
struct VideoAu {
    data: Vec<u8>,
    pts: Option<i64>,
    dts: Option<i64>,
    key: bool,
}

impl VideoAu {
    fn into_packet(self, idx: u32) -> Packet {
        let mut p = Packet::new(idx, TimeBase::new(1, 90_000), self.data).with_keyframe(self.key);
        if let Some(t) = self.pts {
            p = p.with_pts(t);
        }
        if let Some(t) = self.dts {
            p = p.with_dts(t);
        }
        p
    }
}

/// Re-frames a video elementary stream into access units (see the
/// module docs for the boundary rules) and attaches each PES's PTS /
/// DTS to the first access unit commencing in it.
#[derive(Debug)]
struct VideoAuSplitter {
    kind: VideoKind,
    /// Buffered elementary-stream bytes; `buf[0]` sits at absolute
    /// offset `base`.
    buf: Vec<u8>,
    base: u64,
    /// Bytes of `buf` already scanned for start codes.
    scanned: usize,
    /// Start of the access unit being accumulated (relative to `buf`),
    /// once its first byte has been seen.
    au_start: Option<usize>,
    /// Whether the current access unit holds a coded picture / VCL NAL.
    has_picture: bool,
    /// Whether the current access unit is a keyframe.
    key: bool,
    /// Whether the current access unit is a bidirectionally predicted
    /// picture (presented when decoded).
    bidirectional: bool,
    /// `(absolute payload offset, pts, dts)` of PES packets awaiting
    /// their access unit.
    anchors: VecDeque<(u64, Option<i64>, Option<i64>)>,
    /// Decoding-time step between successive access units in 90 kHz
    /// ticks: the frame period of the stream's headers, else the
    /// spacing measured between coded timestamps.
    period: Option<i64>,
    /// Decoding time of the access unit handed out last.
    last_dts: Option<i64>,
    /// The last coded decoding time and the access units handed out
    /// since, for measuring `period`.
    coded: Option<(i64, i64)>,
    /// MPEG-1/2 `temporal_reference` of the current access unit's
    /// picture.
    temporal_reference: Option<u16>,
    /// The current access unit holds a group_of_pictures header, which
    /// restarts the `temporal_reference` count.
    group_start: bool,
    /// `(temporal_reference, pts)` of the last picture of the current
    /// group whose presentation time was coded.
    display_anchor: Option<(u16, i64)>,
    /// Latest presentation time handed out.
    display_end: Option<i64>,
}

impl VideoAuSplitter {
    fn new(kind: VideoKind) -> Self {
        Self {
            kind,
            buf: Vec::new(),
            base: 0,
            scanned: 0,
            au_start: None,
            has_picture: false,
            key: false,
            bidirectional: false,
            anchors: VecDeque::new(),
            period: None,
            last_dts: None,
            coded: None,
            temporal_reference: None,
            group_start: false,
            display_anchor: None,
            display_end: None,
        }
    }

    fn push(&mut self, payload: &[u8], pts: Option<i64>, dts: Option<i64>) -> Vec<VideoAu> {
        if pts.is_some() {
            let at = self.base + self.buf.len() as u64;
            self.anchors.push_back((at, pts, dts));
        }
        self.buf.extend_from_slice(payload);
        let mut out = Vec::new();
        // Scan start codes; a code is examined once 6 bytes of it (two
        // header bytes past the code) are buffered, so a prefix that
        // straddles payloads is picked up on the next push.
        let mut i = self.scanned;
        while i + 6 <= self.buf.len() {
            // Looking for 00 00 01 at `i`: the third byte decides how
            // far the search may jump. Above 1, no prefix can start at
            // any of the three positions it covers; equal to 1 without
            // two zeros ahead, likewise; a zero may open a prefix one
            // byte on.
            match self.buf[i + 2] {
                1 if self.buf[i] == 0 && self.buf[i + 1] == 0 => {}
                0 => {
                    i += 1;
                    continue;
                }
                _ => {
                    i += 3;
                    continue;
                }
            }
            let code = self.buf[i + 3];
            let next = self.buf[i + 4];
            let starts_au = self.classify(code, next);
            // H.264 Annex B: the zero_byte ahead of a start code prefix
            // belongs to the unit it introduces. H.262 §5.2.3 /
            // ISO/IEC 14496-2 next_start_code(): stuffing zero bytes
            // end the element before the start code.
            let at = if self.kind == VideoKind::H264 && i > 0 && self.buf[i - 1] == 0 {
                i - 1
            } else {
                i
            };
            if starts_au {
                if let Some(s) = self.au_start
                    && self.has_picture
                {
                    let cut = at.max(s);
                    out.push(self.cut(s, cut));
                    // `cut` is relative offset 0 after compaction.
                    self.au_start = Some(0);
                    self.has_picture = false;
                    self.key = false;
                    self.bidirectional = false;
                    i -= cut;
                    self.note_picture(code, i);
                    i += 4;
                    continue;
                }
                if self.au_start.is_none() {
                    self.au_start = Some(at);
                }
            }
            self.note_picture(code, i);
            i += 4;
        }
        // Every position before `i` has been classified exactly once.
        self.scanned = i;
        self.bound(&mut out);
        out
    }

    /// Keep the buffered bytes and the timestamp anchors bounded
    /// whatever the input: bytes that precede any access-unit start are
    /// dropped once scanned, and an access unit that outgrows
    /// [`MAX_AU_BYTES`] without meeting a boundary is handed out in
    /// pieces.
    fn bound(&mut self, out: &mut Vec<VideoAu>) {
        match self.au_start {
            None => {
                // One byte stays: it may be the leading zero of a
                // 4-byte start code still to be classified.
                let drop = self.scanned.saturating_sub(1);
                if drop > 0 {
                    self.buf.drain(..drop);
                    self.base += drop as u64;
                    self.scanned -= drop;
                    // The newest timestamp at or before the new front
                    // still belongs to the next access unit to start.
                    let mut last = None;
                    while let Some(&a) = self.anchors.front() {
                        if a.0 > self.base {
                            break;
                        }
                        last = self.anchors.pop_front();
                    }
                    if let Some((_, p, d)) = last {
                        self.anchors.push_front((self.base, p, d));
                    }
                }
            }
            Some(s) if self.buf.len() > MAX_AU_BYTES && self.scanned > s => {
                let piece = self.cut(s, self.scanned);
                out.push(piece);
                self.au_start = Some(0);
                self.key = false;
            }
            Some(_) => {}
        }
        while self.anchors.len() > MAX_ANCHORS {
            self.anchors.pop_front();
        }
    }

    /// Is the unit starting with start code `code` (next byte `next`,
    /// at `at`) the first of a new access unit — given what the current
    /// one already holds?
    fn classify(&self, code: u8, next: u8) -> bool {
        match self.kind {
            // sequence_header / group_start / picture_start.
            VideoKind::Mpeg12 => matches!(code, 0xB3 | 0xB8 | 0x00),
            // ISO/IEC 14496-2 Table 6-3: visual_object_sequence /
            // visual_object / video_object / video_object_layer /
            // group_of_vop / vop start codes.
            VideoKind::Mpeg4 => matches!(code, 0xB0 | 0xB5 | 0x00..=0x2F | 0xB3 | 0xB6),
            VideoKind::H264 => {
                let t = code & 0x1F;
                match t {
                    6..=9 | 14..=18 => true,
                    // first_mb_in_slice == 0 ⇔ its ue(v) is the 1-bit '1'.
                    1 | 5 => next & 0x80 != 0,
                    _ => false,
                }
            }
        }
    }

    /// Track picture presence / keyframe-ness for the unit at `at`.
    fn note_picture(&mut self, code: u8, at: usize) {
        match self.kind {
            VideoKind::Mpeg12 => {
                if code == 0xB8 {
                    self.group_start = true;
                }
                if code == 0x00 {
                    self.has_picture = true;
                    if let Some(b) = self.buf.get(at + 4..at + 6) {
                        self.temporal_reference =
                            Some((u16::from(b[0]) << 2) | u16::from(b[1] >> 6));
                    }
                    // picture_header: temporal_reference(10)
                    // picture_coding_type(3) — 1 = I (H.262 Table 6-12).
                    if let Some(b) = self.buf.get(at + 5) {
                        let pct = (b >> 3) & 0x07;
                        if pct == 1 {
                            self.key = true;
                        }
                        self.bidirectional = pct == 3;
                    }
                }
            }
            VideoKind::Mpeg4 => {
                if code == 0xB6 {
                    self.has_picture = true;
                    // vop_coding_type(2): '00' = intra (Table 6-20).
                    if let Some(b) = self.buf.get(at + 4) {
                        if b >> 6 == 0 {
                            self.key = true;
                        }
                        self.bidirectional = b >> 6 == 2;
                    }
                }
            }
            VideoKind::H264 => {
                let t = code & 0x1F;
                if (1..=5).contains(&t) {
                    self.has_picture = true;
                }
                if t == 5 {
                    self.key = true;
                }
            }
        }
    }

    /// Emit `buf[s..e]` as an access unit and compact the buffer so `e`
    /// becomes offset 0.
    fn cut(&mut self, s: usize, e: usize) -> VideoAu {
        let abs_start = self.base + s as u64;
        let data = self.buf[s..e].to_vec();
        let mut pts = None;
        let mut dts = None;
        while let Some(&(o, p, d)) = self.anchors.front() {
            if o <= abs_start {
                pts = p;
                dts = d;
                self.anchors.pop_front();
            } else {
                break;
            }
        }
        // §2.4.3.7: an access unit with a PTS and no DTS decodes at
        // its PTS.
        let mut dts = dts.or(pts);
        match dts {
            Some(t) => {
                // Measure the access-unit spacing between two coded
                // decoding times when the headers did not give one.
                if let Some((at, units)) = self.coded
                    && units > 0
                    && t > at
                    && self.period.is_none()
                {
                    self.period = Some(t.saturating_sub(at) / units);
                }
                self.coded = Some((t, 0));
            }
            None => {
                // Annex D (timing model): an access unit following one
                // with a coded time stamp decodes one period later.
                if let (Some(prev), Some(step)) = (self.last_dts, self.period) {
                    dts = Some(prev.saturating_add(step));
                }
            }
        }
        // H.262 §6.3.9: temporal_reference counts coded frames in
        // display order within a group of pictures, so a picture
        // without a coded PTS is presented that many frame periods
        // from one of its group that has one.
        if std::mem::take(&mut self.group_start) {
            // The frame a new group displays first (temporal_reference
            // 0) follows the last frame displayed so far.
            self.display_anchor = match (self.display_end, self.period) {
                (Some(end), Some(step)) => Some((0, end.saturating_add(step))),
                _ => None,
            };
        }
        if let Some(tr) = self.temporal_reference.take() {
            match (pts, self.display_anchor, self.period) {
                (Some(t), _, _) => self.display_anchor = Some((tr, t)),
                (None, Some((at, t)), Some(step)) => {
                    // Modulo-1024 difference, taken as the nearer way
                    // round.
                    let d = (i64::from(tr) - i64::from(at) + 512).rem_euclid(1024) - 512;
                    pts = Some(t.saturating_add(d.saturating_mul(step)));
                }
                _ => {}
            }
        }
        // A bidirectional picture is presented as it is decoded.
        if pts.is_none() && self.bidirectional {
            pts = dts;
        }
        if let Some(t) = pts {
            self.display_end = Some(self.display_end.map_or(t, |e| e.max(t)));
        }
        if let Some((_, units)) = &mut self.coded {
            *units += 1;
        }
        self.last_dts = dts;
        let au = VideoAu {
            data,
            pts,
            dts,
            key: self.key,
        };
        self.buf.drain(..e);
        self.base += e as u64;
        self.scanned = self.scanned.saturating_sub(e);
        au
    }

    fn flush(&mut self) -> Option<VideoAu> {
        let s = self.au_start.take()?;
        if s >= self.buf.len() {
            return None;
        }
        let e = self.buf.len();
        let au = self.cut(s, e);
        self.has_picture = false;
        self.key = false;
        self.bidirectional = false;
        Some(au)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn pts5(pts: u64, marker: u8) -> [u8; 5] {
        [
            (marker << 4) | (((pts >> 30) as u8 & 0x07) << 1) | 1,
            (pts >> 22) as u8,
            ((((pts >> 15) & 0x7F) as u8) << 1) | 1,
            (pts >> 7) as u8,
            (((pts & 0x7F) as u8) << 1) | 1,
        ]
    }

    fn pes(sid: u8, pts: Option<u64>, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0x80, if pts.is_some() { 0x80 } else { 0 }];
        let opt: Vec<u8> = pts.map(|p| pts5(p, 0b0010).to_vec()).unwrap_or_default();
        h.push(opt.len() as u8);
        h.extend_from_slice(&opt);
        let len = h.len() + payload.len();
        let mut out = vec![0, 0, 1, sid, (len >> 8) as u8, len as u8];
        out.extend_from_slice(&h);
        out.extend_from_slice(payload);
        out
    }

    fn pack_header(scr_base: u64) -> Vec<u8> {
        let b = scr_base;
        vec![
            0,
            0,
            1,
            0xBA,
            0x44 | (((b >> 30) as u8 & 0x07) << 3) | ((b >> 28) as u8 & 0x03),
            (b >> 20) as u8,
            ((((b >> 15) & 0x1F) as u8) << 3) | 0x04 | ((b >> 13) as u8 & 0x03),
            (b >> 5) as u8,
            (((b & 0x1F) as u8) << 3) | 0x04,
            0x01,
            0x01,
            0x89,
            0xC3,
            0xF8,
        ]
    }

    fn mp2_frame(tag: u8) -> Vec<u8> {
        let mut f = vec![tag; 576];
        f[..4].copy_from_slice(&[0xFF, 0xFD, 0xA4, 0x00]);
        f
    }

    fn ac3_frame(tag: u8) -> Vec<u8> {
        let mut f = vec![tag; 768];
        f[..8].copy_from_slice(&[0x0B, 0x77, 0, 0, 20, 8 << 3, 0b0100_0000, 0]);
        f
    }

    /// MPEG-2 video: sequence header (+ extension) then pictures of the
    /// given coding types, each a picture header + one slice.
    fn mpeg2_es(types: &[u8]) -> (Vec<u8>, Vec<usize>) {
        // temporal_reference of each picture: the display position.
        let display: Vec<u16> = match types {
            [1, 3, 2, 2] => vec![1, 0, 2, 3],
            _ => (0..types.len() as u16).collect(),
        };
        let mut es = vec![
            0, 0, 1, 0xB3, 0x14, 0x00, 0xB4, 0x13, 0xFF, 0xFF, 0xE0, 0x18, // 320x180 25fps
            0, 0, 1, 0xB5, 0x14, 0x8A, 0x00, 0x01, 0x00, 0x00,
        ];
        let mut starts = vec![0];
        for (k, &t) in types.iter().enumerate() {
            if k > 0 {
                starts.push(es.len());
            }
            let tr = display[k];
            es.extend_from_slice(&[
                0,
                0,
                1,
                0x00,
                (tr >> 2) as u8,
                ((tr & 3) as u8) << 6 | t << 3,
                0xFF,
                0xF8,
            ]);
            es.extend_from_slice(&[0, 0, 1, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        }
        (es, starts)
    }

    fn build_ps() -> Vec<u8> {
        let (es, _) = mpeg2_es(&[1, 3, 2, 2]);
        let mut out = Vec::new();
        let mut audio = Vec::new();
        for k in 0..6u8 {
            audio.extend_from_slice(&mp2_frame(k));
        }
        let mut ac3 = Vec::new();
        for k in 0..3u8 {
            ac3.extend_from_slice(&ac3_frame(k));
        }
        // Video split mid-picture across two PES (only the first has a PTS).
        let cut = 40;
        out.extend(pack_header(0));
        out.extend([0, 0, 1, 0xBB, 0, 6, 0x80, 0, 1, 0x04, 0xE1, 0xFF]);
        out.extend(pes(0xE0, Some(9000), &es[..cut]));
        out.extend(pack_header(900));
        out.extend(pes(0xE0, None, &es[cut..]));
        // MP2 split across PES mid-frame.
        out.extend(pack_header(1800));
        out.extend(pes(0xC0, Some(9000), &audio[..1000]));
        out.extend(pes(0xC0, Some(9000 + 2 * 2160), &audio[1000..]));
        // DVD AC-3 sub-stream: number + FrmCnt + FirstAccUnit prefix.
        let mut p1 = vec![0x80, 2, 0, 1];
        p1.extend_from_slice(&ac3[..1000]);
        let mut p2 = vec![0x80, 1, 0, 0x01];
        p2.extend_from_slice(&ac3[1000..]);
        out.extend(pack_header(2700));
        out.extend(pes(0xBD, Some(9000), &p1));
        out.extend(pes(0xBD, Some(9000 + 2 * 2880), &p2));
        out.extend(pack_header(90_000));
        out.extend([0, 0, 1, 0xB9]);
        out
    }

    /// 40 half-second groups — an intra picture and a predicted one,
    /// 8 KiB each — with two audio frames per group.
    fn build_long_ps() -> Vec<u8> {
        let mut out = Vec::new();
        for g in 0..40u64 {
            let t = 90_000 + g * 45_000;
            let mut es = vec![
                0, 0, 1, 0xB3, 0x14, 0x00, 0xB4, 0x13, 0xFF, 0xFF, 0xE0, 0x18, //
                0, 0, 1, 0xB8, 0, 0x08, 0, 0,
            ];
            for (tr, kind) in [(0u8, 1u8), (1, 2)] {
                es.extend_from_slice(&[0, 0, 1, 0x00, 0x00, tr << 6 | kind << 3, 0xFF, 0xF8]);
                es.extend_from_slice(&[0, 0, 1, 0x01]);
                es.extend(std::iter::repeat_n(0x55 + g as u8, 8000));
            }
            out.extend(pack_header(t - 30_000));
            out.extend(pes(0xE0, Some(t), &es));
            out.extend(pack_header(t - 29_000));
            let audio = [mp2_frame(g as u8), mp2_frame(g as u8 + 100)].concat();
            out.extend(pes(0xC0, Some(t), &audio));
        }
        out.extend([0, 0, 1, 0xB9]);
        out
    }

    #[test]
    fn seek_lands_on_the_key_frame_at_or_before_the_target() {
        let mut d = MpegPsDemuxer::new(Box::new(Cursor::new(build_long_ps()))).unwrap();
        let key = |g: i64| 90_000 + g * 45_000;
        for (target, group) in [
            (key(17) + 1, 17),
            (key(17), 17),
            (key(17) - 1, 16),
            (key(39) + 900_000, 39),
            (0, 0),
            (key(3) + 22_500, 3),
            (key(30) + 44_999, 30),
        ] {
            assert_eq!(d.seek_to(0, target).unwrap(), key(group), "target {target}");
            let first = d.next_packet().unwrap();
            assert_eq!(first.stream_index, 0);
            assert!(first.is_keyframe());
            assert_eq!(first.pts, Some(key(group)));
            assert_eq!(first.data[40], 0x55 + group as u8);
            // The group's audio follows, then its predicted picture
            // (complete once the next group begins).
            let mut rest = Vec::new();
            while let Ok(p) = d.next_packet() {
                rest.push(p);
                if rest.len() == 3 {
                    break;
                }
            }
            assert_eq!(rest[0].stream_index, 1);
            assert_eq!(rest[0].pts, Some(key(group)));
            assert_eq!(rest[0].data, mp2_frame(group as u8));
            assert_eq!(rest[1].pts, Some(key(group) + 2160));
            if group < 39 {
                assert_eq!(rest[2].stream_index, 0);
                assert_eq!(rest[2].pts, Some(key(group) + 3600));
            }
        }
        // A target beyond any time stamp (found by the demux fuzz
        // target: the interpolated times overflowed).
        assert_eq!(d.seek_to(0, i64::MAX).unwrap(), key(39));
        while d.next_packet().is_ok() {}
        assert_eq!(d.seek_to(0, i64::MIN).unwrap(), key(0));
        // Audio: every frame is an entry point.
        assert_eq!(d.seek_to(1, key(20) + 2160).unwrap(), key(20) + 2160);
        let first = loop {
            let p = d.next_packet().unwrap();
            if p.stream_index == 1 {
                break p;
            }
        };
        assert_eq!(first.data, mp2_frame(120));
        assert!(d.seek_to(7, 0).is_err());
    }

    #[test]
    fn probe_scores_13818_pack_headers_only() {
        let ps = build_ps();
        fn pd(b: &[u8]) -> oxideav_core::ProbeData<'_> {
            oxideav_core::ProbeData { buf: b, ext: None }
        }
        assert_eq!(probe(&pd(&ps)), 100);
        // ISO/IEC 11172-1 pack ('0010' marker) is not claimed.
        let mut m1 = ps.clone();
        m1[4] = 0x21;
        assert_eq!(probe(&pd(&m1)), 0);
        assert_eq!(probe(&pd(&[0x47; 400])), 0);
    }

    #[test]
    fn mpeg1_systems_stream_is_rejected_with_a_named_gap() {
        let mut m1 = build_ps();
        m1[4] = 0x21;
        let err = MpegPsDemuxer::new(Box::new(Cursor::new(m1))).unwrap_err();
        assert!(format!("{err}").contains("11172-1"));
    }

    #[test]
    fn demuxes_video_access_units_audio_frames_and_dvd_substreams() {
        let mut d = MpegPsDemuxer::new(Box::new(Cursor::new(build_ps()))).unwrap();
        let s = d.streams();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].params.codec_id.as_str(), "mpeg2video");
        assert_eq!(
            (s[0].params.width, s[0].params.height),
            (Some(320), Some(180))
        );
        assert_eq!(s[1].params.codec_id.as_str(), "mp2");
        assert_eq!(s[1].params.sample_rate, Some(48_000));
        assert_eq!(s[2].params.codec_id.as_str(), "ac3");
        assert_eq!(s[2].params.channels, Some(2));
        assert_eq!(d.duration_micros(), Some(1_000_000));
        let mut pk: Vec<Packet> = Vec::new();
        while let Ok(p) = d.next_packet() {
            pk.push(p);
        }
        let (es, starts) = mpeg2_es(&[1, 3, 2, 2]);
        let v: Vec<&Packet> = pk.iter().filter(|p| p.stream_index == 0).collect();
        assert_eq!(v.len(), 4);
        for (k, p) in v.iter().enumerate() {
            let end = starts.get(k + 1).copied().unwrap_or(es.len());
            assert_eq!(p.data, es[starts[k]..end], "AU {k}");
        }
        assert!(v[0].is_keyframe() && !v[1].is_keyframe());
        assert_eq!((v[0].pts, v[0].dts), (Some(9000), Some(9000)));
        // The pictures behind the first carry no time stamp of their
        // own: decoding times step by the 25 Hz frame period, and
        // presentation times follow temporal_reference.
        assert_eq!((v[1].pts, v[1].dts), (Some(5400), Some(12_600)));
        assert_eq!((v[2].pts, v[2].dts), (Some(12_600), Some(16_200)));
        assert_eq!((v[3].pts, v[3].dts), (Some(16_200), Some(19_800)));
        let a: Vec<&Packet> = pk.iter().filter(|p| p.stream_index == 1).collect();
        assert_eq!(a.len(), 6);
        for (k, p) in a.iter().enumerate() {
            assert_eq!(p.data, mp2_frame(k as u8));
            assert_eq!(p.pts, Some(9000 + k as i64 * 2160));
        }
        let c: Vec<&Packet> = pk.iter().filter(|p| p.stream_index == 2).collect();
        assert_eq!(c.len(), 3);
        for (k, p) in c.iter().enumerate() {
            assert_eq!(p.data, ac3_frame(k as u8));
            assert_eq!(p.pts, Some(9000 + k as i64 * 2880));
        }
    }

    #[test]
    fn psm_stream_type_overrides_the_sniff() {
        // A PSM mapping 0xE0 to H.264 (stream_type 0x1B).
        let mut psm = vec![
            0, 0, 1, 0xBC, 0, 0, 0x80, 0x01, 0, 0, 0, 4, 0x1B, 0xE0, 0, 0,
        ];
        psm.extend_from_slice(&[0, 0, 0, 0]); // CRC (not verified here)
        let len = psm.len() - 6;
        psm[4] = (len >> 8) as u8;
        psm[5] = len as u8;
        let mut es = vec![0, 0, 0, 1, 0x09, 0xF0];
        es.extend_from_slice(&[
            0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x0c, 0xac, 0xd9, 0x41, 0x41, 0x9f, 0x9f, 0x01,
            0x10, 0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0x20, 0xf1, 0x42, 0x99,
            0x60,
        ]);
        es.extend_from_slice(&[0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x10]);
        es.extend_from_slice(&[0, 0, 0, 1, 0x09, 0xF0, 0, 0, 1, 0x41, 0x9A, 0x22]);
        let mut ps = pack_header(0);
        ps.extend(psm);
        ps.extend(pes(0xE0, Some(3000), &es));
        ps.extend([0, 0, 1, 0xB9]);
        let mut d = MpegPsDemuxer::new(Box::new(Cursor::new(ps))).unwrap();
        assert_eq!(d.streams()[0].params.codec_id.as_str(), "h264");
        assert_eq!(d.streams()[0].params.width, Some(320));
        let mut v = Vec::new();
        while let Ok(p) = d.next_packet() {
            v.push(p);
        }
        assert_eq!(v.len(), 2);
        assert!(v[0].is_keyframe());
        assert!(!v[1].is_keyframe());
        assert_eq!(v[0].pts, Some(3000));
    }

    #[test]
    fn truncated_and_garbage_inputs_never_panic() {
        let ps = build_ps();
        for cut in [0, 3, 13, 20, 60, 700, 1500, ps.len() - 3] {
            if let Ok(mut d) = MpegPsDemuxer::new(Box::new(Cursor::new(ps[..cut].to_vec()))) {
                while d.next_packet().is_ok() {}
            }
        }
        let mut junk = pack_header(0);
        junk.extend((0..5000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        if let Ok(mut d) = MpegPsDemuxer::new(Box::new(Cursor::new(junk))) {
            while d.next_packet().is_ok() {}
        }
    }

    /// Minimised input from the scheduled fuzz run: a pack header whose
    /// `pack_stuffing_length` claims 7 stuffing bytes when only three
    /// bytes follow. The cursor must stop at the end of the buffered
    /// window instead of stepping past it.
    #[test]
    fn pack_stuffing_past_end_of_input_is_bounded() {
        let crash: [u8; 17] = [
            0x00, 0x00, 0x01, 0xBA, 0x47, 0x40, 0x00, 0x10, 0xFF, 0xFF, 0xFF, 0xFC, 0xF4, 0x0E,
            0x59, 0x47, 0x00,
        ];
        assert!(MpegPsDemuxer::new(Box::new(Cursor::new(crash.to_vec()))).is_err());
        // Every stuffing claim against every truncation of a stream
        // that does carry a PES packet.
        for stuffing in 0..8u8 {
            let mut ps = pack_header(0);
            ps[13] = 0xF8 | stuffing;
            let head = ps.len();
            ps.extend(pes(0xC0, Some(900), &mp2_frame(1)));
            for cut in head..ps.len() {
                if let Ok(mut d) = MpegPsDemuxer::new(Box::new(Cursor::new(ps[..cut].to_vec()))) {
                    while d.next_packet().is_ok() {}
                }
            }
        }
    }

    /// Memory stays bounded when the elementary stream never offers an
    /// access-unit boundary: unanchored bytes are dropped, timestamp
    /// anchors do not pile up, and an oversized unit leaves in pieces.
    #[test]
    fn video_splitter_buffers_are_bounded() {
        let mut v = VideoAuSplitter::new(VideoKind::Mpeg12);
        let junk = vec![0x55u8; 4096];
        for k in 0..4096i64 {
            assert!(v.push(&junk, Some(k), None).is_empty());
            assert!(v.buf.len() <= 2 * junk.len());
            assert!(v.anchors.len() <= 2);
        }
        // The newest timestamp still lands on the first unit to start.
        let mut pic = vec![0, 0, 1, 0x00, 0x00, 0x08, 0, 0];
        pic.extend(vec![0x55u8; 64]);
        assert!(v.push(&pic, None, None).is_empty());
        let aus = v.push(&[0, 0, 1, 0x00, 0x00, 0x08, 0, 0], None, None);
        assert_eq!(aus.len(), 1);
        assert_eq!(aus[0].pts, Some(4095));

        // One picture followed by an endless slice body.
        let mut v = VideoAuSplitter::new(VideoKind::Mpeg12);
        let mut total = v.push(&pic, Some(7), None).len();
        let body = vec![0x55u8; 1 << 20];
        let mut emitted = 0usize;
        for _ in 0..40 {
            for au in v.push(&body, None, None) {
                emitted += au.data.len();
                total += 1;
            }
            assert!(v.buf.len() <= MAX_AU_BYTES + body.len());
        }
        assert!(total >= 2, "oversized unit must be handed out in pieces");
        assert!(emitted >= 16 << 20);
    }
}
