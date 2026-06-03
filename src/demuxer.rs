//! Container [`Demuxer`] implementation reading 188-byte MPEG-TS
//! packets from a [`ReadSeek`] source.
//!
//! Wire layout per ISO/IEC 13818-1 — TS packet → PAT (PID 0) → PMT
//! (PID from PAT) → one elementary stream per `(elementary_pid,
//! stream_type)` pair → PES packets reassembled across TS packets
//! per PID → an [`oxideav_core::Packet`] per PES emitted to the
//! pipeline.
//!
//! ## Scope
//!
//! * Single-program transport streams (BD `.m2ts`, broadcast TS with
//!   one program). When a PAT advertises multiple programs the first
//!   one wins; multi-program selection is a [future hook](#future).
//! * Multi-TS-packet PAT / PMT via [`crate::PsiSectionAssembler`] —
//!   sections that overflow the ~184-byte per-TS payload budget
//!   (common for PMTs with rich descriptor blocks) are reassembled
//!   across as many same-PID continuation packets as the section
//!   spans, per §2.4.4. Multi-section tables (`last_section_number >
//!   0`) still pick the first section — the table-level cross-section
//!   join is a separate follow-up.
//! * Per-PID streams. Streams whose [`StreamType`] maps to an audio /
//!   video / subtitle [`CodecParameters`] surface as
//!   [`StreamInfo`]s the muxer can write; streams whose type we don't
//!   handle (interactive graphics, private data) are silently
//!   dropped — their PES packets never reach `next_packet`.
//!
//! ## Time base
//!
//! TS PTS / DTS are in 90 kHz units. Each [`StreamInfo`] uses
//! `TimeBase::new(1, 90_000)` and packet timestamps are the raw
//! 33-bit values without rescaling — downstream muxers do their own
//! base conversion.

use std::collections::{HashMap, VecDeque};

use oxideav_core::{
    CodecId, CodecParameters, CodecResolver, Demuxer, Error as CoreError, Packet, ReadSeek,
    Result as CoreResult, StreamInfo, TimeBase,
};

use crate::{
    PesPacket, PesReassembler, ProgramAssociationTable, ProgramMapTable, PsiSectionAssembler,
    StreamType, TsPacket, PAT_PID, TS_PACKET_LEN, TS_SYNC_BYTE,
};

/// Open factory matching `oxideav_core::OpenDemuxerFn`. Registered
/// under the `"mpegts"` container name.
pub fn open(input: Box<dyn ReadSeek>, codecs: &dyn CodecResolver) -> CoreResult<Box<dyn Demuxer>> {
    let _ = codecs; // stream_type → CodecId is hard-coded for MPEG-TS
    MpegTsDemuxer::new(input).map(|d| Box::new(d) as Box<dyn Demuxer>)
}

/// MPEG-TS demuxer state — reads 188-byte packets from a `ReadSeek`,
/// reassembles PES per PID, hands one [`Packet`] per PES back through
/// `next_packet`.
pub struct MpegTsDemuxer {
    input: Box<dyn ReadSeek>,
    streams: Vec<StreamInfo>,
    /// `elementary_pid` → `streams[index]` lookup.
    pid_to_stream: HashMap<u16, u32>,
    /// `elementary_pid` → in-flight PES reassembler.
    reassemblers: HashMap<u16, PesReassembler>,
    /// Already-reassembled packets waiting to be handed out.
    pending: VecDeque<Packet>,
    /// `true` once `read_one_packet` has returned `Eof` and every
    /// reassembler has been flushed.
    eof_reached: bool,
    /// Input bytes consumed so far — for diagnostic error messages.
    bytes_read: u64,
    /// Tiny look-ahead buffer used by the resync path: we may peek a
    /// "probe" byte to validate a candidate sync, and need to feed it
    /// to the next `read_one_packet` rather than discard it (which
    /// would leave the input cursor 1 byte misaligned and force every
    /// subsequent read through another resync). Holds at most a few
    /// bytes in practice.
    putback: VecDeque<u8>,
}

impl std::fmt::Debug for MpegTsDemuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpegTsDemuxer")
            .field("streams", &self.streams.len())
            .field("pending", &self.pending.len())
            .field("eof", &self.eof_reached)
            .finish()
    }
}

impl MpegTsDemuxer {
    fn new(mut input: Box<dyn ReadSeek>) -> CoreResult<Self> {
        // Step 1: scan for the first PAT, reassembling its section
        // across as many same-PID TS packets as the spec permits per
        // §2.4.4. A PUSI=1 packet starts a fresh section; subsequent
        // same-PID packets with PUSI=0 continue it. Real BD `.m2ts`
        // fits the PAT in one TS packet; broadcast TS with many
        // programs needs the assembler.
        let mut pmt_pid: Option<u16> = None;
        let mut programs_found: Option<ProgramAssociationTable> = None;
        let mut probe_bytes: u64 = 0;
        let mut probe_putback: VecDeque<u8> = VecDeque::new();
        let mut pat_assembler = PsiSectionAssembler::new();
        loop {
            probe_bytes += TS_PACKET_LEN as u64;
            let buf = match read_one_packet(
                &mut input,
                &mut probe_putback,
                probe_bytes - TS_PACKET_LEN as u64,
            )? {
                Some(b) => b,
                None => {
                    return Err(CoreError::invalid(
                        "mpegts: stream ended before a PAT was seen",
                    ))
                }
            };
            let pkt = TsPacket::parse(&buf).map_err(map_ts_err)?;
            if pkt.pid != PAT_PID || pkt.payload.is_empty() {
                continue;
            }
            let sections = pat_assembler
                .feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
                .map_err(map_ts_err)?;
            for section in &sections {
                if let Ok(pat) = ProgramAssociationTable::parse(section) {
                    for (prog, pid) in &pat.programs {
                        if *prog != 0 {
                            pmt_pid = Some(*pid);
                            break;
                        }
                    }
                    programs_found = Some(pat);
                    if pmt_pid.is_some() {
                        break;
                    }
                }
            }
            if pmt_pid.is_some() {
                break;
            }
        }
        let pmt_pid = pmt_pid
            .ok_or_else(|| CoreError::invalid("mpegts: PAT carried no program with a PMT PID"))?;
        let _ = programs_found; // retained for future multi-program selection

        // Step 2: scan for the matching PMT, again reassembling
        // multi-TS-packet sections. PMTs with rich descriptor blocks
        // routinely overflow the ~184-byte single-TS payload budget;
        // a Blu-ray title's PMT with multi-language PGS + multi-codec
        // audio is the canonical case.
        let mut pmt_assembler = PsiSectionAssembler::new();
        let pmt = loop {
            probe_bytes += TS_PACKET_LEN as u64;
            let buf = match read_one_packet(
                &mut input,
                &mut probe_putback,
                probe_bytes - TS_PACKET_LEN as u64,
            )? {
                Some(b) => b,
                None => {
                    return Err(CoreError::invalid(
                        "mpegts: stream ended before the PMT was seen",
                    ))
                }
            };
            let pkt = TsPacket::parse(&buf).map_err(map_ts_err)?;
            if pkt.pid != pmt_pid || pkt.payload.is_empty() {
                continue;
            }
            let sections = pmt_assembler
                .feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
                .map_err(map_ts_err)?;
            let mut got: Option<ProgramMapTable> = None;
            for section in &sections {
                if let Ok(pmt) = ProgramMapTable::parse(section) {
                    got = Some(pmt);
                    break;
                }
            }
            if let Some(pmt) = got {
                break pmt;
            }
        };

        // Step 3: map PMT streams → CodecParameters → StreamInfo. PIDs
        // whose stream_type we don't have a CodecId for are silently
        // dropped (we won't open a reassembler for them and their PES
        // bytes never reach the caller).
        let tb = TimeBase::new(1, 90_000);
        let mut streams: Vec<StreamInfo> = Vec::new();
        let mut pid_to_stream: HashMap<u16, u32> = HashMap::new();
        let mut reassemblers: HashMap<u16, PesReassembler> = HashMap::new();
        for pmt_stream in &pmt.streams {
            let params = match codec_params_for_stream_type(pmt_stream.stream_type) {
                Some(p) => p,
                None => continue,
            };
            let idx = streams.len() as u32;
            streams.push(StreamInfo {
                index: idx,
                time_base: tb,
                duration: None,
                start_time: None,
                params,
            });
            pid_to_stream.insert(pmt_stream.elementary_pid, idx);
            reassemblers.insert(pmt_stream.elementary_pid, PesReassembler::new());
        }
        if streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegts: PMT advertised no streams we recognise (BD-relevant types: \
                 0x02/0x1B/0x24/0xEA video, 0x80-0x86 audio, 0x90/0x92 subtitle)",
            ));
        }

        Ok(Self {
            input,
            streams,
            pid_to_stream,
            reassemblers,
            pending: VecDeque::new(),
            eof_reached: false,
            bytes_read: probe_bytes,
            putback: probe_putback,
        })
    }

    /// Pull one TS packet from the input and, if it's for a stream we
    /// track, feed the per-PID reassembler. Returns the number of
    /// `Packet`s pushed into `self.pending` by this call.
    fn read_one_into_pending(&mut self) -> CoreResult<usize> {
        let buf = match read_one_packet(&mut self.input, &mut self.putback, self.bytes_read)? {
            Some(b) => b,
            None => return Ok(0),
        };
        self.bytes_read += TS_PACKET_LEN as u64;
        let pkt = TsPacket::parse(&buf).map_err(map_ts_err)?;
        let stream_idx = match self.pid_to_stream.get(&pkt.pid).copied() {
            Some(i) => i,
            None => return Ok(0),
        };
        let reassembler = self
            .reassemblers
            .get_mut(&pkt.pid)
            .expect("pid_to_stream and reassemblers are kept in sync");
        let emitted = reassembler.feed(&pkt).map_err(map_ts_err)?;
        let pushed = if let Some(pes) = emitted {
            self.pending.push_back(pes_to_packet(stream_idx, pes));
            1
        } else {
            0
        };
        Ok(pushed)
    }

    /// Flush every per-PID reassembler — used once the input runs
    /// dry. Pushes a final `Packet` per stream that had a buffered
    /// in-flight PES at end-of-stream.
    fn flush_reassemblers(&mut self) {
        let pids: Vec<u16> = self.reassemblers.keys().copied().collect();
        for pid in pids {
            let stream_idx = self.pid_to_stream[&pid];
            if let Some(reassembler) = self.reassemblers.get_mut(&pid) {
                if let Ok(Some(pes)) = reassembler.flush() {
                    self.pending.push_back(pes_to_packet(stream_idx, pes));
                }
            }
        }
    }
}

impl Demuxer for MpegTsDemuxer {
    fn format_name(&self) -> &str {
        "mpegts"
    }

    fn streams(&self) -> &[StreamInfo] {
        &self.streams
    }

    fn next_packet(&mut self) -> CoreResult<Packet> {
        loop {
            if let Some(pkt) = self.pending.pop_front() {
                return Ok(pkt);
            }
            if self.eof_reached {
                return Err(CoreError::Eof);
            }
            let pushed = self.read_one_into_pending()?;
            if pushed == 0 {
                // Check eof directly: read_one_packet returns Ok(None)
                // when there are no more 188-byte chunks. We need a
                // signal here without re-reading; do a single
                // try-read and on `None` set eof + flush.
                match read_one_packet(&mut self.input, &mut self.putback, self.bytes_read)? {
                    None => {
                        self.eof_reached = true;
                        self.flush_reassemblers();
                    }
                    Some(buf) => {
                        self.bytes_read += TS_PACKET_LEN as u64;
                        // We've already advanced past an EOF earlier
                        // when this branch was taken with pushed=0 but
                        // there ARE more bytes — that means the prior
                        // packet was a non-stream PID (silently
                        // dropped). Re-parse + feed and loop.
                        let pkt = TsPacket::parse(&buf).map_err(map_ts_err)?;
                        if let Some(stream_idx) = self.pid_to_stream.get(&pkt.pid).copied() {
                            if let Some(reassembler) = self.reassemblers.get_mut(&pkt.pid) {
                                if let Some(pes) = reassembler.feed(&pkt).map_err(map_ts_err)? {
                                    self.pending.push_back(pes_to_packet(stream_idx, pes));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Maximum 188-byte packets we'll skip while resyncing after a bad
/// sync byte. We've observed real BD M2TS streams with ~2 AACS units
/// (~12 KB ≈ 64 TS packets) of undecryptable bytes at chapter
/// boundaries — `libaacs` reproduces the same garbage bytes there,
/// so the bytes are part of the protected variant-key area, not a
/// flaw in our decryption. 256 packets gives a comfortable ceiling
/// without silently swallowing a longer corruption that the caller
/// should know about.
const RESYNC_PACKET_LIMIT: usize = 256;

/// Read exactly one 188-byte TS packet from the input.
///
/// Drains from `putback` first (used by the resync path to feed peeked
/// bytes back to the caller) and then from `input`.
///
/// Returns `Ok(None)` cleanly when fewer than 188 bytes remain — the
/// caller treats that as end-of-stream. A short read mid-packet (e.g.
/// the stream is truncated) surfaces as `Err`.
///
/// On a sync-byte mismatch we **resync** by discarding 188-byte chunks
/// until we find one whose first byte is `0x47` AND whose immediately-
/// following byte is also `0x47` (the next packet's sync). The probe
/// byte is buffered in `putback` so the next call to `read_one_packet`
/// sees it as the first byte of a fresh packet — without that, every
/// subsequent read would land 1 byte off and re-trigger resync.
fn read_one_packet(
    input: &mut Box<dyn ReadSeek>,
    putback: &mut VecDeque<u8>,
    bytes_read: u64,
) -> CoreResult<Option<[u8; TS_PACKET_LEN]>> {
    use std::io::Read;
    let mut buf = [0u8; TS_PACKET_LEN];
    let mut filled = 0;
    // Drain putback first.
    while filled < TS_PACKET_LEN {
        match putback.pop_front() {
            Some(b) => {
                buf[filled] = b;
                filled += 1;
            }
            None => break,
        }
    }
    while filled < TS_PACKET_LEN {
        match input.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(CoreError::invalid(format!(
                    "mpegts: short read at packet boundary ({filled}/{TS_PACKET_LEN} bytes, offset {bytes_read})"
                )));
            }
            Ok(n) => filled += n,
            Err(e) => return Err(CoreError::Io(e)),
        }
    }
    if buf[0] != TS_SYNC_BYTE {
        return resync(input, putback, buf, bytes_read).map(Some);
    }
    Ok(Some(buf))
}

/// Resync after a bad sync byte. Read 188 new bytes; if they start
/// with `0x47`, accept them as the recovered packet — but **only**
/// after confirming the byte 188 positions later is also `0x47` (the
/// next packet's sync). The double-sync check is what rejects random
/// `0x47` bytes inside garbage data.
///
/// We don't try to recover the failing packet itself; we just skip it
/// (and any further failing 188-byte chunks) until a clean packet
/// boundary appears. After at most [`RESYNC_PACKET_LIMIT`] failed
/// chunks, surface as `Err`.
///
/// `initial` is the 188-byte slice that just failed the sync check;
/// we don't need its contents, just the failing byte for diagnostics.
fn resync(
    input: &mut Box<dyn ReadSeek>,
    putback: &mut VecDeque<u8>,
    initial: [u8; TS_PACKET_LEN],
    bytes_read: u64,
) -> CoreResult<[u8; TS_PACKET_LEN]> {
    use std::io::Read;
    let mut buf = [0u8; TS_PACKET_LEN];
    let mut probe = [0u8; 1];
    for _ in 0..RESYNC_PACKET_LIMIT {
        // Read 188 fresh bytes.
        let mut filled = 0;
        while filled < TS_PACKET_LEN {
            match input.read(&mut buf[filled..]) {
                Ok(0) => {
                    return Err(CoreError::invalid(format!(
                        "mpegts: bad sync byte 0x{:02X} at offset {bytes_read} \
                         and EOF reached during resync",
                        initial[0]
                    )));
                }
                Ok(n) => filled += n,
                Err(e) => return Err(CoreError::Io(e)),
            }
        }
        if buf[0] != TS_SYNC_BYTE {
            continue;
        }
        // Candidate passes single-sync; probe the next byte for a
        // double-sync. If probe is also 0x47, we're aligned.
        match input.read(&mut probe) {
            Ok(0) => {
                // EOF immediately after a clean candidate. Trust the
                // single sync byte; if we can't probe, we can't
                // double-check, but the packet itself parsed.
                return Ok(buf);
            }
            Ok(_) => {}
            Err(e) => return Err(CoreError::Io(e)),
        }
        if probe[0] == TS_SYNC_BYTE {
            // Push the probe byte back so the next call sees it as
            // the start of a fresh packet.
            putback.push_back(probe[0]);
            return Ok(buf);
        }
        // Single 0x47 not followed by another at +188; treat as
        // coincidence inside garbage data and keep scanning.  The
        // probe byte is also part of the corrupt span — drop it.
    }
    Err(CoreError::invalid(format!(
        "mpegts: bad sync byte 0x{:02X} at offset {bytes_read} (packet {}), \
         resync failed after {RESYNC_PACKET_LIMIT} 188-byte chunks",
        initial[0],
        bytes_read / TS_PACKET_LEN as u64,
    )))
}

fn map_ts_err(e: crate::TsError) -> CoreError {
    CoreError::invalid(format!("mpegts: {e}"))
}

fn pes_to_packet(stream_index: u32, pes: PesPacket) -> Packet {
    let tb = TimeBase::new(1, 90_000);
    let mut pkt = Packet::new(stream_index, tb, pes.payload);
    if let Some(p) = pes.pts_90k {
        pkt = pkt.with_pts(p as i64);
    }
    if let Some(d) = pes.dts_90k {
        pkt = pkt.with_dts(d as i64);
    }
    pkt
}

/// Map an MPEG-TS `stream_type` byte to a [`CodecParameters`] the
/// muxer registry understands. `None` means "drop this stream" —
/// interactive graphics, DSM-CC sections, vendor-private codes, etc.
fn codec_params_for_stream_type(st: u8) -> Option<CodecParameters> {
    let s = StreamType::from_raw(st);
    let cid: &'static str = match s {
        StreamType::Mpeg2Video => "mpeg2video",
        StreamType::AvcVideo => "h264",
        StreamType::HevcVideo => "hevc",
        StreamType::Vc1Video => "vc1",
        StreamType::LpcmAudio => "pcm_s16be",
        StreamType::Ac3Audio | StreamType::EAc3SecondaryAudio => "ac3",
        StreamType::EAc3Audio => "eac3",
        StreamType::TruehdAudio => "truehd",
        StreamType::DtsAudio
        | StreamType::DtsHdAudio
        | StreamType::DtsHdMaAudio
        | StreamType::DtsHdSecondaryAudio => "dts",
        StreamType::PgsSubtitle => "hdmv_pgs_subtitle",
        StreamType::TextSubtitle => "hdmv_textst_subtitle",
        StreamType::IgsInteractive => return None,
        StreamType::Other(_) => return None,
    };
    let codec_id = CodecId::new(cid);
    Some(match s {
        StreamType::Mpeg2Video
        | StreamType::AvcVideo
        | StreamType::HevcVideo
        | StreamType::Vc1Video => CodecParameters::video(codec_id),
        StreamType::PgsSubtitle | StreamType::TextSubtitle => CodecParameters::subtitle(codec_id),
        StreamType::IgsInteractive | StreamType::Other(_) => unreachable!(),
        _ => CodecParameters::audio(codec_id),
    })
}

/// Probe an MPEG-TS byte stream — the canonical heuristic checks for
/// the `0x47` sync byte at offsets `0`, `188`, `376` (and ideally
/// further). Real-world transport streams are sync-aligned at the
/// start; a hit at 3+ offsets is unambiguous.
///
/// Scores follow the convention in
/// [`oxideav_core::ContainerProbeFn`]:
/// * `100` — sync byte present at offsets 0, 188, 376, 564.
/// * `80`  — sync byte present at 0, 188, 376.
/// * `60`  — sync byte present at 0, 188.
/// * `0`   — otherwise.
pub fn probe(p: &oxideav_core::ProbeData) -> oxideav_core::ProbeScore {
    let mut hits = 0u8;
    for off in [0, 188, 376, 564] {
        if p.buf.get(off).copied() == Some(TS_SYNC_BYTE) {
            hits += 1;
        }
    }
    match hits {
        4 => 100,
        3 => 80,
        2 => 60,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal in-memory MPEG-TS byte stream with:
    /// * PAT pointing at PMT_PID = 0x100
    /// * PMT with one H.264 video stream on PID 0x101
    /// * One PES packet on PID 0x101 with PTS=12345, payload b"hello"
    ///
    /// Hand-rolled bytes — uses the same `iter_packets` / `iter_sections`
    /// primitives the demuxer consumes, so a passing test round-trips
    /// the wire format.
    fn synth_minimal_ts() -> Vec<u8> {
        // PSI CRC-32/MPEG-2.
        fn crc32_mpeg2(data: &[u8]) -> u32 {
            let mut c: u32 = 0xFFFF_FFFF;
            for &b in data {
                c ^= (b as u32) << 24;
                for _ in 0..8 {
                    c = if c & 0x8000_0000 != 0 {
                        (c << 1) ^ 0x04C1_1DB7
                    } else {
                        c << 1
                    };
                }
            }
            c
        }
        fn ts_packet(
            pid: u16,
            pusi: bool,
            cc: u8,
            payload: &[u8],
            is_psi: bool,
        ) -> [u8; TS_PACKET_LEN] {
            let mut pkt = [0u8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            let pusi_bit = if pusi { 0b0100_0000 } else { 0 };
            pkt[1] = pusi_bit | ((pid >> 8) as u8 & 0b0001_1111);
            pkt[2] = pid as u8;
            // adaptation_field_control = 0b01 (payload only); CC = cc
            pkt[3] = 0b0001_0000 | (cc & 0x0F);
            // For PSI PUSI=1 the payload starts with a pointer_field=0
            // pointing at the section. For PES, the payload begins
            // directly with the packet_start_code_prefix.
            let mut off = 4;
            if pusi && is_psi {
                pkt[off] = 0; // pointer_field
                off += 1;
            }
            let take = (TS_PACKET_LEN - off).min(payload.len());
            pkt[off..off + take].copy_from_slice(&payload[..take]);
            // Stuffing already zero.
            pkt
        }
        // PAT body: tsid=1, program 1 → pmt_pid 0x100.
        let mut pat = vec![
            0x00, // table_id
            0xB0,
            0x0D, // section_syntax_indicator=1, '0', reserved, section_length=0x00D (13)
            0x00, 0x01, // tsid
            0xC1, // reserved + version_number=0 + current_next_indicator=1
            0x00, 0x00, // section_number + last_section_number
            0x00, 0x01, // program_number=1
            0xE1, 0x00, // reserved + pmt_pid=0x0100
        ];
        let pat_crc = crc32_mpeg2(&pat);
        pat.extend_from_slice(&pat_crc.to_be_bytes());

        // PMT body: pcr_pid = 0x101, no program_info, one stream:
        // stream_type=0x1B (AVC), elementary_pid=0x101, ES_info_length=0.
        let mut pmt = vec![
            0x02, // table_id
            0xB0, 0x12, // section_length = 18
            0x00, 0x01, // program_number=1
            0xC1, // reserved + version + current/next
            0x00, 0x00, 0xE1, 0x01, // reserved + pcr_pid=0x101
            0xF0, 0x00, // reserved + program_info_length=0
            // stream entry
            0x1B, // stream_type AVC
            0xE1, 0x01, // reserved + elementary_pid=0x101
            0xF0, 0x00, // reserved + ES_info_length=0
        ];
        let pmt_crc = crc32_mpeg2(&pmt);
        pmt.extend_from_slice(&pmt_crc.to_be_bytes());

        // Single ES PES packet, stream_id=0xE0 (video stream 0), PTS=12345.
        // PTS encoding per ISO/IEC 13818-1 Table 2-22 ('0010').
        fn encode_pts(pts: u64, marker_nibble: u8) -> [u8; 5] {
            let mut b = [0u8; 5];
            b[0] = (marker_nibble << 4) | (((pts >> 29) & 0x0E) as u8) | 1;
            b[1] = ((pts >> 22) & 0xFF) as u8;
            b[2] = (((pts >> 14) & 0xFE) as u8) | 1;
            b[3] = ((pts >> 7) & 0xFF) as u8;
            b[4] = (((pts << 1) & 0xFE) as u8) | 1;
            b
        }
        let pts_bytes = encode_pts(12345, 0b0010);
        let pes_payload = b"hello";
        // Optional PES header length includes the 5 PTS bytes.
        let opt_hdr_len: u8 = 5;
        let pes_packet_length: u16 = 3 + opt_hdr_len as u16 + pes_payload.len() as u16; // 3 = flags + flags + hdr_len
        let mut pes = vec![
            0x00,
            0x00,
            0x01, // packet_start_code_prefix
            0xE0, // stream_id
            (pes_packet_length >> 8) as u8,
            pes_packet_length as u8,
            0b1000_0000, // '10' marker + zero scrambling/priority/...
            0b1000_0000, // PTS_DTS_flags = 0b10 (PTS only)
            opt_hdr_len,
        ];
        pes.extend_from_slice(&pts_bytes);
        pes.extend_from_slice(pes_payload);

        let mut buf = Vec::new();
        buf.extend_from_slice(&ts_packet(0x0000, true, 0, &pat, true));
        buf.extend_from_slice(&ts_packet(0x0100, true, 0, &pmt, true));
        buf.extend_from_slice(&ts_packet(0x0101, true, 0, &pes, false));
        buf
    }

    #[test]
    fn demux_synth_ts_yields_one_avc_stream_with_pts() {
        let bytes = synth_minimal_ts();
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        assert_eq!(dmx.streams().len(), 1);
        assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "h264");
        let pkt = dmx.next_packet().expect("first PES");
        assert_eq!(pkt.pts, Some(12345));
        // EOF after flush — single packet stream.
        let next = dmx.next_packet();
        assert!(matches!(next, Err(CoreError::Eof)));
    }

    /// Build a sequence of TS packets carrying `section` on `pid`,
    /// spanning as many packets as needed. The first packet has
    /// PUSI=1 + pointer_field=0; subsequent packets have PUSI=0 and
    /// carry continuation bytes. `cc_start` is the continuity_counter
    /// for the first packet (subsequent CCs increment mod 16).
    fn ts_packets_for_section(pid: u16, section: &[u8], cc_start: u8) -> Vec<[u8; TS_PACKET_LEN]> {
        let mut out = Vec::new();
        let mut consumed = 0usize;
        let mut cc = cc_start & 0x0F;
        let mut first = true;
        while consumed < section.len() {
            let mut pkt = [0u8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            let pusi_bit = if first { 0b0100_0000 } else { 0 };
            pkt[1] = pusi_bit | ((pid >> 8) as u8 & 0b0001_1111);
            pkt[2] = pid as u8;
            pkt[3] = 0b0001_0000 | cc;
            let mut off = 4;
            if first {
                pkt[off] = 0; // pointer_field = 0
                off += 1;
                first = false;
            }
            let room = TS_PACKET_LEN - off;
            let take = room.min(section.len() - consumed);
            pkt[off..off + take].copy_from_slice(&section[consumed..consumed + take]);
            // Pad remainder with 0xFF stuffing.
            for b in &mut pkt[off + take..] {
                *b = 0xFF;
            }
            consumed += take;
            cc = (cc + 1) & 0x0F;
            out.push(pkt);
        }
        out
    }

    #[test]
    fn demux_handles_pmt_spanning_two_ts_packets() {
        // PSI CRC-32/MPEG-2 — local copy.
        fn crc32_mpeg2(data: &[u8]) -> u32 {
            let mut c: u32 = 0xFFFF_FFFF;
            for &b in data {
                c ^= (b as u32) << 24;
                for _ in 0..8 {
                    c = if c & 0x8000_0000 != 0 {
                        (c << 1) ^ 0x04C1_1DB7
                    } else {
                        c << 1
                    };
                }
            }
            c
        }
        // PAT — same as before.
        let mut pat = vec![
            0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xE1, 0x00,
        ];
        let pat_crc = crc32_mpeg2(&pat);
        pat.extend_from_slice(&pat_crc.to_be_bytes());

        // PMT: PCR_PID=0x101, program_info empty, one AVC stream on
        // 0x101 with a 200-byte ES_info descriptor blob (user-private
        // tag 0xC0). Section size: 3 + (5 header + 4 PCR/PI hdr + 5
        // stream hdr + 202 descr + 4 CRC) = ~223 bytes, which
        // overflows a single 184-byte TS payload.
        let descr: Vec<u8> = {
            let mut d = vec![0xC0u8, 200u8]; // tag + length
            d.extend(std::iter::repeat(0xAA).take(200));
            d
        };
        let es_info_len = descr.len() as u16; // = 202
        let section_body_len = 4 + 5 + descr.len(); // PCR/PI(4) + stream hdr(5) + descr
        let section_length = 5 + section_body_len + 4; // 5 = rest of common header, +4 CRC
        let mut pmt = vec![
            0x02,
            (0xB0 | ((section_length >> 8) & 0x0F) as u8),
            (section_length & 0xFF) as u8,
            0x00,
            0x01,
            0xC1,
            0x00,
            0x00,
            0xE1,
            0x01, // PCR_PID = 0x101
            0xF0,
            0x00, // program_info_length = 0
            0x1B, // stream_type AVC
            0xE1,
            0x01, // elementary_pid = 0x101
            (0xF0 | ((es_info_len >> 8) & 0x0F) as u8),
            (es_info_len & 0xFF) as u8,
        ];
        pmt.extend_from_slice(&descr);
        let pmt_crc = crc32_mpeg2(&pmt);
        pmt.extend_from_slice(&pmt_crc.to_be_bytes());
        assert!(
            pmt.len() > 184,
            "PMT must overflow a single TS payload to exercise the assembler"
        );

        // PES — short, fits in one TS packet.
        fn encode_pts(pts: u64, marker_nibble: u8) -> [u8; 5] {
            let mut b = [0u8; 5];
            b[0] = (marker_nibble << 4) | (((pts >> 29) & 0x0E) as u8) | 1;
            b[1] = ((pts >> 22) & 0xFF) as u8;
            b[2] = (((pts >> 14) & 0xFE) as u8) | 1;
            b[3] = ((pts >> 7) & 0xFF) as u8;
            b[4] = (((pts << 1) & 0xFE) as u8) | 1;
            b
        }
        let pts_bytes = encode_pts(7777, 0b0010);
        let pes_payload = b"spans-pmt";
        let opt_hdr_len: u8 = 5;
        let pes_packet_length: u16 = 3 + opt_hdr_len as u16 + pes_payload.len() as u16;
        let mut pes = vec![
            0x00,
            0x00,
            0x01,
            0xE0,
            (pes_packet_length >> 8) as u8,
            pes_packet_length as u8,
            0b1000_0000,
            0b1000_0000,
            opt_hdr_len,
        ];
        pes.extend_from_slice(&pts_bytes);
        pes.extend_from_slice(pes_payload);

        let mut buf = Vec::new();
        for p in ts_packets_for_section(0x0000, &pat, 0) {
            buf.extend_from_slice(&p);
        }
        for p in ts_packets_for_section(0x0100, &pmt, 0) {
            buf.extend_from_slice(&p);
        }
        // PES on PID 0x101.
        let mut pes_pkt = [0u8; TS_PACKET_LEN];
        pes_pkt[0] = TS_SYNC_BYTE;
        pes_pkt[1] = 0b0100_0000 | ((0x0101 >> 8) as u8 & 0b0001_1111);
        pes_pkt[2] = 0x01;
        pes_pkt[3] = 0b0001_0000;
        let take = (TS_PACKET_LEN - 4).min(pes.len());
        pes_pkt[4..4 + take].copy_from_slice(&pes[..take]);
        buf.extend_from_slice(&pes_pkt);

        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open with multi-TS-packet PMT");
        assert_eq!(dmx.streams().len(), 1);
        assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "h264");
        let pkt = dmx.next_packet().expect("first PES across multi-PMT path");
        assert_eq!(pkt.pts, Some(7777));
    }

    #[test]
    fn probe_recognises_sync_aligned_ts() {
        let mut buf = vec![0u8; 800];
        for off in [0, 188, 376, 564] {
            buf[off] = TS_SYNC_BYTE;
        }
        let p = oxideav_core::ProbeData {
            buf: &buf,
            ext: None,
        };
        assert_eq!(probe(&p), 100);
    }

    #[test]
    fn resync_recovers_after_short_garbage_run() {
        // Direct test of read_one_packet → resync, without going
        // through the PES reassembler (which would need a multi-PES
        // synthetic stream to flush mid-recovery).
        //
        // Layout: [valid 188-byte TS packet][2 KB garbage]
        //         [valid 188-byte TS packet][valid 188-byte TS packet].
        // Call read_one_packet 3 times: the first returns the leading
        // valid packet, the second hits garbage and resyncs to the
        // second valid packet, the third returns the third valid packet
        // (with no resync needed because the input cursor is already
        // aligned by the double-sync probe).
        fn make_pkt(cc: u8) -> [u8; TS_PACKET_LEN] {
            let mut p = [0xFFu8; TS_PACKET_LEN];
            p[0] = TS_SYNC_BYTE;
            p[1] = 0x10; // pid 0x1000 high byte (no PUSI)
            p[2] = 0x00;
            p[3] = 0x10 | (cc & 0x0F);
            p
        }
        let p0 = make_pkt(0);
        let p1 = make_pkt(1);
        let p2 = make_pkt(2);
        let mut buf = Vec::new();
        buf.extend_from_slice(&p0);
        // 11 packets' worth of garbage — 188-aligned to match real-
        // world BD layout (AACS units are exactly 32 × 188-byte TS
        // packets, so any failure region is a multiple of 188).
        buf.extend_from_slice(&vec![0xAAu8; 11 * TS_PACKET_LEN]);
        buf.extend_from_slice(&p1);
        buf.extend_from_slice(&p2);
        let mut cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut putback = VecDeque::new();
        // First read: clean.
        let r0 = read_one_packet(&mut cursor, &mut putback, 0)
            .expect("first")
            .expect("Some");
        assert_eq!(r0[3] & 0x0F, 0);
        // Second read: bytes start at offset 188 (inside garbage), so
        // resync triggers. It should land on p1.
        let r1 = read_one_packet(&mut cursor, &mut putback, 188)
            .expect("resync")
            .expect("Some");
        assert_eq!(r1[3] & 0x0F, 1, "expected CC=1, got CC={}", r1[3] & 0x0F);
        // Third read: should pick up p2 thanks to the probe-byte
        // putback — no second resync needed.
        let r2 = read_one_packet(&mut cursor, &mut putback, 376)
            .expect("p2")
            .expect("Some");
        assert_eq!(r2[3] & 0x0F, 2, "expected CC=2, got CC={}", r2[3] & 0x0F);
    }

    #[test]
    fn probe_rejects_random_bytes() {
        let buf = vec![0u8; 800];
        let p = oxideav_core::ProbeData {
            buf: &buf,
            ext: None,
        };
        assert_eq!(probe(&p), 0);
    }
}
