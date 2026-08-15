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
//! * Multi-program transport streams. The PAT's full program list is
//!   enumerated as [`TsProgram`] records ([`MpegTsDemuxer::programs`]);
//!   the default [`open`] path demuxes the first program, and
//!   [`MpegTsDemuxer::open_program`] selects any other by its
//!   `program_number` (§2.4.4.5).
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
    Pcr, PcrTracker, PesPacket, PesReassembler, ProgramAssociationTable, ProgramMapTable,
    PsiSectionAssembler, PtsTracker, StreamType, TsPacket, PAT_PID, TS_PACKET_LEN, TS_SYNC_BYTE,
};

/// PID value the PMT's `PCR_PID` field carries when no PCR is
/// associated with the program (§2.4.4.9 / Table 2-3 null PID).
const NULL_PID: u16 = 0x1FFF;

/// Open factory matching `oxideav_core::OpenDemuxerFn`. Registered
/// under the `"mpegts"` container name.
pub fn open(input: Box<dyn ReadSeek>, codecs: &dyn CodecResolver) -> CoreResult<Box<dyn Demuxer>> {
    let _ = codecs; // stream_type → CodecId is hard-coded for MPEG-TS
    MpegTsDemuxer::new(input).map(|d| Box::new(d) as Box<dyn Demuxer>)
}

/// One program advertised by a transport stream's PAT — the
/// `program_number` label and the `program_map_PID` carrying its PMT
/// (§2.4.4.5). A `program_number` of `0` (the network PID) is filtered
/// out before this list is built; every entry here names a real
/// program whose PMT can be selected via
/// [`MpegTsDemuxer::open_program`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsProgram {
    /// 16-bit program label, unique within the transport stream.
    pub program_number: u16,
    /// 13-bit PID of the TS packets carrying this program's PMT.
    pub pmt_pid: u16,
}

/// MPEG-TS demuxer state — reads 188-byte packets from a `ReadSeek`,
/// reassembles PES per PID, hands one [`Packet`] per PES back through
/// `next_packet`.
pub struct MpegTsDemuxer {
    input: Box<dyn ReadSeek>,
    /// Every non-network program the PAT advertised, in PAT order. The
    /// first entry is the default selection; [`Self::open_program`]
    /// targets any other by `program_number`.
    programs: Vec<TsProgram>,
    /// `program_number` of the program this demuxer is currently
    /// demuxing (its PMT drove `streams`).
    selected_program: u16,
    /// `PCR_PID` for the selected program (§2.4.4.9), or
    /// [`NULL_PID`] when the program carries no PCR.
    pcr_pid: u16,
    /// 27 MHz clock recovery on the selected program's `PCR_PID`. Fed
    /// every adaptation field that carries a PCR; supplies the absolute
    /// clock anchor a remux uses to align the PES timeline.
    pcr_tracker: PcrTracker,
    streams: Vec<StreamInfo>,
    /// `elementary_pid` → `streams[index]` lookup.
    pid_to_stream: HashMap<u16, u32>,
    /// `elementary_pid` → in-flight PES reassembler.
    reassemblers: HashMap<u16, PesReassembler>,
    /// `elementary_pid` → 33-bit PTS unwrapper (§2.4.3.7). Turns the
    /// raw PES timestamps that wrap every ~26.5 h into a monotonic
    /// 64-bit extended timeline.
    pts_trackers: HashMap<u16, PtsTracker>,
    /// `elementary_pid` → 33-bit DTS unwrapper — DTS advances
    /// independently of PTS so it needs its own ring tracker.
    dts_trackers: HashMap<u16, PtsTracker>,
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
    /// Container duration in microseconds, probed once at open from the
    /// first and last PCR on the selected program's `PCR_PID`
    /// (§2.4.2.2). `None` when the program declares no PCR_PID, the
    /// stream carries fewer than two PCR samples, or the source is not
    /// seekable to its end.
    duration_micros: Option<i64>,
    /// Head-anchor PCR and its byte offset, captured by the same
    /// open-time probe that filled `duration_micros`. Reused as the
    /// lower bracket of the [`Self::seek_to`] binary search. `None`
    /// when no PCR was found (an unseekable / PCR-less stream — seeking
    /// is then unsupported).
    first_pcr: Option<(Pcr, u64)>,
    /// Tail-anchor PCR and its byte offset; the upper bracket of the
    /// seek search.
    last_pcr: Option<(Pcr, u64)>,
    /// Random-access index built lazily by
    /// [`Self::random_access_points`] from the §2.4.3.5
    /// `random_access_indicator` packets on the tracked PIDs. `None`
    /// until the first index request.
    rap_index: Option<Vec<RandomAccessPoint>>,
    /// Physical packet framing detected at open — plain 188-byte,
    /// 4-byte-prefixed 192-byte, or 16-byte-trailer 204-byte packets.
    /// Every read strips the framing down to the logical 188-byte
    /// window.
    layout: crate::packet::TsPacketLayout,
}

/// How an access point announced itself on the wire — the two
/// container-level signals ISO/IEC 13818-1 offers, in decreasing
/// strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessPointKind {
    /// Adaptation-field `random_access_indicator` (§2.4.3.5): the next
    /// PES packet to start on the PID contains the first byte of a
    /// video sequence header (stream types 1/2) or an audio frame
    /// (types 3/4), with a presentation timestamp present — the
    /// container's full random-access guarantee.
    RandomAccessIndicator,
    /// PES `data_alignment_indicator` (§2.4.3.7) on a PES start whose
    /// packet carried no random-access indicator: the payload begins
    /// at the alignment the `data_stream_alignment_descriptor`
    /// (§2.6.10) names, or — absent the descriptor — at a slice /
    /// video access unit or audio sync word (alignment_type '01',
    /// Tables 2-47/2-48). A decodable *parse* point; for video it does
    /// **not** promise an intra-coded picture, so it is the fallback
    /// tier for streams that never set the §2.4.3.5 indicator.
    DataAligned,
}

/// One elementary-stream access point discovered by scanning the
/// stream on the selected program's elementary PIDs — a TS packet
/// whose adaptation field sets the `random_access_indicator`
/// (§2.4.3.5), or a data-aligned PES start (§2.4.3.7) on a PID; see
/// [`AccessPointKind`] for what each tier guarantees. Repositioning a
/// demuxer at `byte_offset` picks the access point up as its first
/// PES on the PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomAccessPoint {
    /// Byte offset of the TS packet that carried the indicator (for
    /// [`AccessPointKind::RandomAccessIndicator`]) or the PES-start
    /// packet (for [`AccessPointKind::DataAligned`]); packet-aligned.
    pub byte_offset: u64,
    /// PID the access point rode on.
    pub pid: u16,
    /// `StreamInfo.index` of the elementary stream on that PID.
    pub stream_index: u32,
    /// PTS of the announced PES packet on the **extended** 64-bit
    /// 90 kHz timeline (§2.4.3.7 unwrap — the same axis `next_packet`
    /// emits and `seek_to` accepts), so index entries stay ordered and
    /// addressable across a `2^33` wrap. §2.4.3.5 requires a PTS at a
    /// random-access point; `None` when the PES start could not be
    /// located or carried no decodable timestamp (a conformance
    /// violation this index tolerates).
    pub pts_90k: Option<u64>,
    /// Which container signal announced this point.
    pub kind: AccessPointKind,
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
    /// Open a demuxer on the **first** program the PAT advertises.
    fn new(input: Box<dyn ReadSeek>) -> CoreResult<Self> {
        Self::with_selector(input, None)
    }

    /// Open a demuxer on a **specific** program by its 16-bit
    /// `program_number` (§2.4.4.5). Use this when a multi-program
    /// transport stream carries more than one service and the caller
    /// wants a program other than the first the PAT lists. The
    /// available programs can be discovered by opening with [`open`]
    /// and reading [`Self::programs`], then
    /// re-opening a fresh source on the chosen `program_number`.
    ///
    /// Returns an error if the PAT advertises no program with that
    /// number.
    pub fn open_program(input: Box<dyn ReadSeek>, program_number: u16) -> CoreResult<Self> {
        Self::with_selector(input, Some(program_number))
    }

    /// Core constructor. `want` is `None` for "first program wins" or
    /// `Some(n)` to select the program whose `program_number == n`.
    fn with_selector(mut input: Box<dyn ReadSeek>, want: Option<u16>) -> CoreResult<Self> {
        // Step 0: detect the physical packet layout (188-byte plain,
        // 192-byte 4-byte-prefixed source packets, or 204-byte
        // trailer-appended packets) from the head of the stream, then
        // rewind. Everything downstream works on the logical 188-byte
        // window; the framing bytes are stripped at the read layer.
        let layout = {
            use std::io::Read;
            let mut head = [0u8; 204 * 8];
            let mut filled = 0usize;
            while filled < head.len() {
                match input.read(&mut head[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(CoreError::Io(e)),
                }
            }
            input
                .seek(std::io::SeekFrom::Start(0))
                .map_err(CoreError::Io)?;
            // A head too corrupt (or short) to classify falls back to
            // the plain layout; the streaming resync path takes over
            // from there.
            crate::packet::detect_packet_layout(&head[..filled])
                .unwrap_or(crate::packet::TsPacketLayout::STANDARD)
        };

        // Step 1: scan for the first PAT, reassembling its section
        // across as many same-PID TS packets as the spec permits per
        // §2.4.4. A PUSI=1 packet starts a fresh section; subsequent
        // same-PID packets with PUSI=0 continue it. Real BD `.m2ts`
        // fits the PAT in one TS packet; broadcast TS with many
        // programs needs the assembler.
        //
        // We collect *every* non-network program the PAT lists so a
        // caller can enumerate them and re-open on a chosen one
        // (§2.4.4.5: `program_number == 0` names the network PID, not a
        // program). The selected program drives the Step-2 PMT scan.
        let mut programs: Vec<TsProgram> = Vec::new();
        let mut probe_bytes: u64 = 0;
        let mut probe_putback: VecDeque<u8> = VecDeque::new();
        let mut pat_assembler = PsiSectionAssembler::new();
        loop {
            probe_bytes += layout.packet_size as u64;
            let buf = match read_one_packet(
                &mut input,
                &mut probe_putback,
                probe_bytes - layout.packet_size as u64,
                layout,
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
                        if *prog != 0 && !programs.iter().any(|p| p.program_number == *prog) {
                            programs.push(TsProgram {
                                program_number: *prog,
                                pmt_pid: *pid,
                            });
                        }
                    }
                }
            }
            if !programs.is_empty() {
                break;
            }
        }
        if programs.is_empty() {
            return Err(CoreError::invalid(
                "mpegts: PAT carried no program with a PMT PID",
            ));
        }
        let selected = match want {
            None => programs[0],
            Some(n) => *programs
                .iter()
                .find(|p| p.program_number == n)
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "mpegts: PAT advertises no program_number {n} \
                         (available: {})",
                        programs
                            .iter()
                            .map(|p| p.program_number.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?,
        };
        let pmt_pid = selected.pmt_pid;
        let selected_program = selected.program_number;

        // Step 2: scan for the matching PMT, again reassembling
        // multi-TS-packet sections. PMTs with rich descriptor blocks
        // routinely overflow the ~184-byte single-TS payload budget;
        // a Blu-ray title's PMT with multi-language PGS + multi-codec
        // audio is the canonical case.
        let mut pmt_assembler = PsiSectionAssembler::new();
        let pmt = loop {
            probe_bytes += layout.packet_size as u64;
            let buf = match read_one_packet(
                &mut input,
                &mut probe_putback,
                probe_bytes - layout.packet_size as u64,
                layout,
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
        let mut pts_trackers: HashMap<u16, PtsTracker> = HashMap::new();
        let mut dts_trackers: HashMap<u16, PtsTracker> = HashMap::new();
        for pmt_stream in &pmt.streams {
            let mut params = match codec_params_for_stream_type(pmt_stream.stream_type) {
                Some(p) => p,
                None => continue,
            };
            // Lift the ES_info ISO_639_language_descriptor (tag 0x0A,
            // §2.6.18) into the per-stream language tag so a demux →
            // remux path keeps each track's audio/subtitle language.
            // The first language entry wins (multi-language audio is
            // rare and a single tag is what the core surface holds).
            if params.language.is_none() {
                if let Some(code) = first_iso639_language(pmt_stream) {
                    params = params.with_language(code);
                }
            }
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
            pts_trackers.insert(pmt_stream.elementary_pid, PtsTracker::new());
            dts_trackers.insert(pmt_stream.elementary_pid, PtsTracker::new());
        }
        if streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegts: PMT advertised no streams we recognise (BD-relevant types: \
                 0x02/0x1B/0x24/0xEA video, 0x80-0x86 audio, 0x90/0x92 subtitle)",
            ));
        }

        let mut demuxer = Self {
            input,
            programs,
            selected_program,
            pcr_pid: pmt.pcr_pid,
            pcr_tracker: PcrTracker::new(),
            streams,
            pid_to_stream,
            reassemblers,
            pts_trackers,
            dts_trackers,
            pending: VecDeque::new(),
            eof_reached: false,
            bytes_read: probe_bytes,
            putback: probe_putback,
            duration_micros: None,
            first_pcr: None,
            last_pcr: None,
            rap_index: None,
            layout,
        };

        // Probe the container duration from the PCR span (§2.4.2.2).
        // This seeks the input to its end and back; restore the
        // streaming cursor afterwards so the first `next_packet`
        // resumes exactly where the header scan stopped. A
        // non-seekable source (or one too short to carry two PCRs)
        // leaves `duration_micros` at `None`.
        demuxer.duration_micros = demuxer.compute_duration_micros();
        let _ = demuxer
            .input
            .seek(std::io::SeekFrom::Start(demuxer.bytes_read));
        if let Some(total) = demuxer.duration_micros {
            // Surface the same figure per stream so a consumer reading
            // `StreamInfo.duration` (90 kHz units) sees it too.
            let ticks = (total as i128 * 90_000 / 1_000_000) as i64;
            for s in &mut demuxer.streams {
                if s.duration.is_none() {
                    s.duration = Some(ticks);
                }
            }
        }

        Ok(demuxer)
    }

    /// The list of programs the PAT advertised, in PAT order
    /// (§2.4.4.5). The network PID (`program_number == 0`) is excluded.
    /// The first entry is the one a default [`open`] demuxes; pass any
    /// other's `program_number` to [`Self::open_program`] on a fresh
    /// source to select it.
    pub fn programs(&self) -> &[TsProgram] {
        &self.programs
    }

    /// The `program_number` whose PMT this demuxer is currently
    /// reading streams from.
    pub fn selected_program(&self) -> u16 {
        self.selected_program
    }

    /// The selected program's `PCR_PID` (§2.4.4.9), or `None` when the
    /// PMT declared no PCR (the spec's `0x1FFF` null sentinel).
    pub fn pcr_pid(&self) -> Option<u16> {
        (self.pcr_pid != NULL_PID).then_some(self.pcr_pid)
    }

    /// The most recently recovered [`Pcr`] on the program's `PCR_PID`,
    /// or `None` before the first PCR has been demuxed. This is the
    /// 27 MHz wall-clock anchor a remux uses to place the PES timeline.
    pub fn last_pcr(&self) -> Option<Pcr> {
        self.pcr_tracker.last_pcr()
    }

    /// The physical packet framing detected at open — plain 188-byte
    /// packets, 192-byte (4-byte-prefixed) source packets, or 204-byte
    /// (16-byte-trailer) packets. All demux output is already stripped
    /// to the logical 188-byte units.
    pub fn packet_layout(&self) -> crate::packet::TsPacketLayout {
        self.layout
    }

    /// Probe the head and tail PCR anchors on the selected `PCR_PID`,
    /// recording them in `first_pcr` / `last_pcr` for reuse by
    /// [`Self::seek_to`], and return the container duration in
    /// microseconds from their 27 MHz span (§2.4.2.2).
    ///
    /// Returns `None` when the program declares no PCR_PID, the stream
    /// is so short it carries fewer than two PCR samples, or the input
    /// is not seekable to its end. The byte scans run once (at open).
    fn compute_duration_micros(&mut self) -> Option<i64> {
        if self.pcr_pid == NULL_PID {
            return None;
        }
        // Length of the input, for the tail scan. A non-seekable or
        // zero-length source gives up (no end to scan toward).
        let psize = self.layout.packet_size as u64;
        let len = self.input.seek(std::io::SeekFrom::End(0)).ok()?;
        if len < 2 * psize {
            return None;
        }
        let aligned_len = (len / psize) * psize;

        // First PCR from the head: align to a packet boundary and scan
        // forward. Real BD/broadcast streams carry a PCR within the
        // first handful of packets on the PCR_PID.
        let (first_pcr, first_off) = self.scan_pcr_forward(0, len)?;
        self.first_pcr = Some((first_pcr, first_off));

        // Last PCR from the tail: walk a trailing window backward in
        // packet-sized steps so we don't read the whole file. A 1 MiB
        // window (≈5500 packets) comfortably spans the longest realistic
        // inter-PCR gap (§2.7.2 caps it at 100 ms; even a 50 Mbit/s
        // stream fits dozens of PCRs in that window).
        const TAIL_WINDOW: u64 = 1 << 20;
        let mut window = TAIL_WINDOW;
        let (last_pcr, last_off) = loop {
            let start = aligned_len.saturating_sub(window);
            // Snap the window start to a packet boundary measured from
            // the aligned end so each candidate packet starts on `0x47`.
            let start = (start / psize) * psize;
            if let Some(found) = self.scan_pcr_backward(start, aligned_len) {
                break found;
            }
            if start == 0 {
                // Scanned the whole stream and found at most one PCR.
                return None;
            }
            window = window.saturating_mul(2);
        };

        if last_off <= first_off {
            return None;
        }
        self.last_pcr = Some((last_pcr, last_off));
        let span_ticks = pcr_span_27mhz(first_pcr, first_off, last_pcr, last_off)?;
        // 27 MHz ticks → microseconds: ticks × 1_000_000 / 27_000_000
        // = ticks / 27. Use 128-bit to avoid overflow on multi-hour
        // streams (span can exceed 2^33 × 300 ≈ 2.6e12 ticks).
        let micros = (span_ticks as i128 * 1_000_000) / 27_000_000;
        i64::try_from(micros).ok()
    }

    /// Extend a raw 33-bit PCR base onto the same 64-bit timeline the
    /// demuxed PTS/DTS use (§2.4.3.7 unwrap semantics), anchored at the
    /// stream's head PCR: `first_base + ((raw − first_base) mod 2^33)`.
    ///
    /// Every PCR in a stream shorter than one 33-bit wrap (~26.5 h,
    /// which also bounds the open-time duration probe) is at its exact
    /// zero-wrap modular delta from the head anchor, so this maps the
    /// whole file's PCRs onto one monotonic extended axis — the axis a
    /// caller's seek target (an extended PTS from `next_packet`) lives
    /// on, since the PTS unwrap counts the same `2^33` wraps from the
    /// same stream head. Without this, a bisection comparing raw bases
    /// breaks the moment the PCR crosses `2^33` mid-stream.
    fn pcr_ext_90k(&self, raw_base: u64) -> i64 {
        let m = crate::TIMESTAMP_MODULUS_90KHZ;
        match self.first_pcr {
            Some((first, _)) => {
                let fb = first.base_90khz();
                (fb + ((raw_base + m - fb) % m)) as i64
            }
            None => raw_base as i64,
        }
    }

    /// Locate the byte offset and **extended** 90 kHz time of the last
    /// PCR at or before `target_90k` by a PCR-anchored binary search
    /// over the byte stream (§2.4.2.2), without repositioning any demux
    /// state. Out-of-bracket targets clamp to the head / tail anchor.
    ///
    /// MPEG-TS has no in-container random-access index, so this brackets
    /// the target between the open-time head/tail PCR anchors and
    /// bisects the byte range, at each step scanning forward to the next
    /// PCR on the `PCR_PID` and steering the search by its base —
    /// extended past any `2^33` wrap via [`Self::pcr_ext_90k`] so the
    /// comparison axis matches the caller's extended-PTS target.
    fn locate_pcr_at_or_before(&mut self, target_90k: i64) -> CoreResult<(u64, i64)> {
        let (first_pcr, first_off) = self.first_pcr.ok_or_else(|| {
            CoreError::unsupported("mpegts: stream carries no PCR to seek against")
        })?;
        let (last_pcr, last_off) = self
            .last_pcr
            .ok_or_else(|| CoreError::unsupported("mpegts: stream carries only one PCR"))?;

        // The head anchor extends to its own raw base (zero delta); the
        // tail anchor extends across however many wraps the span holds.
        let first_ext = self.pcr_ext_90k(first_pcr.base_90khz());
        let last_ext = self.pcr_ext_90k(last_pcr.base_90khz());

        // Clamp the request to the bracket. A target at or before the
        // head lands on the first PCR; at or after the tail, the last.
        if target_90k <= first_ext {
            return Ok((first_off, first_ext));
        }
        if target_90k >= last_ext {
            return Ok((last_off, last_ext));
        }

        // Binary search the byte range [lo, hi) (packet-aligned) for the
        // last PCR with extended base ≤ target. `best` tracks the
        // closest landing found so far that does not overshoot.
        let psize = self.layout.packet_size as u64;
        let mut lo = first_off;
        let mut hi = last_off;
        let mut best = (first_off, first_ext);
        while hi - lo > psize {
            let mid_raw = lo + (hi - lo) / 2;
            let mid = (mid_raw / psize) * psize;
            let mid = mid.max(lo);
            // Find the next PCR at or after `mid`. If none lies before
            // `hi`, the target sits in this packet-sparse tail — shrink
            // `hi` to `mid` and keep bisecting the lower half.
            match self.scan_pcr_forward(mid, hi) {
                Some((pcr, off)) => {
                    let ext = self.pcr_ext_90k(pcr.base_90khz());
                    if ext <= target_90k {
                        best = (off, ext);
                        // Advance past this PCR's packet so we don't
                        // re-find the same one and stall.
                        lo = off + psize;
                    } else {
                        hi = off;
                    }
                }
                None => {
                    hi = mid;
                }
            }
        }
        Ok(best)
    }

    /// Seek the demux position to the PCR nearest `target_90k` (a
    /// presentation time on the stream's **extended** 90 kHz timeline —
    /// the same axis `next_packet` emits PTS on) via
    /// [`Self::locate_pcr_at_or_before`]. Lands on the packet boundary
    /// of the last PCR at or before the target, resets every per-PID
    /// reassembler and re-seeds the PTS/DTS trackers at the landing
    /// time (so post-seek packets continue the extended timeline), and
    /// returns the landed PCR's extended time.
    ///
    /// PCR carries the program *system* clock, whose epoch matches the
    /// PTS epoch up to the constant T-STD buffering delay (§2.4.2.2); a
    /// PCR-accurate landing is the random-access granularity an
    /// index-free TS demuxer can offer. The caller decodes forward to
    /// the first frame whose PTS reaches its exact request.
    fn seek_by_pcr(&mut self, target_90k: i64) -> CoreResult<i64> {
        let (off, landed) = self.locate_pcr_at_or_before(target_90k)?;
        self.reposition(off, Some(landed));
        Ok(landed)
    }

    /// The stream's access-point index, built on first call by a
    /// single forward scan of the selected program's elementary PIDs
    /// for `random_access_indicator` packets (§2.4.3.5) and — the
    /// fallback tier — data-aligned PES starts (§2.4.3.7).
    ///
    /// Each [`RandomAccessPoint`] records the anchor packet's byte
    /// offset, PID / stream index, tier ([`AccessPointKind`]), and the
    /// **extended** PTS of the PES packet the point announces ("the
    /// next PES packet to start in the payload of Transport Stream
    /// packets with the current PID") — resolved in the same pass, so
    /// an indicator riding a payload-less carrier packet still gets
    /// the following PES start's timestamp. A PES start that resolves
    /// a pending indicator is recorded once, as the indicator's point,
    /// not again as a data-aligned one. The scan reads the whole
    /// stream once and restores the demux cursor; the index is cached
    /// for reuse. Streams that signal neither tier yield an empty
    /// index.
    ///
    /// Returns an error only when the source cannot be walked (not
    /// seekable / short read at a packet boundary).
    pub fn random_access_points(&mut self) -> CoreResult<&[RandomAccessPoint]> {
        if self.rap_index.is_none() {
            let index = self.scan_random_access_points()?;
            self.rap_index = Some(index);
        }
        Ok(self.rap_index.as_deref().unwrap_or(&[]))
    }

    /// One-pass builder for [`Self::random_access_points`].
    fn scan_random_access_points(&mut self) -> CoreResult<Vec<RandomAccessPoint>> {
        use std::io::SeekFrom;
        // Remember the exact streaming cursor; the scan is an
        // out-of-band probe.
        let resume = {
            use std::io::Seek;
            self.input.stream_position().map_err(CoreError::Io)?
        };
        let psize = self.layout.packet_size as u64;
        let len = self.input.seek(SeekFrom::End(0)).map_err(CoreError::Io)?;
        let aligned_len = (len / psize) * psize;
        self.input.seek(SeekFrom::Start(0)).map_err(CoreError::Io)?;

        let mut out: Vec<RandomAccessPoint> = Vec::new();
        // Indices into `out` of RAPs on a PID whose announced PES
        // start (the next PUSI=1 packet on that PID) hasn't been seen
        // yet.
        let mut unresolved: HashMap<u16, Vec<usize>> = HashMap::new();
        // Per-PID reference time for the out-of-order-tolerant PTS
        // unwrap: each PES start's raw 33-bit PTS extends to the epoch
        // nearest the previous one on the PID (`extend_near`), exactly
        // tracking the wraps the streaming PtsTracker would count while
        // shrugging off B-picture reordering.
        let mut pts_ref: HashMap<u16, u64> = HashMap::new();
        let mut buf = [0u8; MAX_PHYSICAL_PACKET];
        let mut off = 0u64;
        while off + psize <= aligned_len {
            if read_exact_packet(&mut self.input, &mut buf[..psize as usize]).is_err() {
                break;
            }
            // A stray mid-stream corruption shouldn't abort the index;
            // skip unparseable packets (the streaming path has its own
            // resync story).
            if let Ok(pkt) = TsPacket::parse(self.layout.window(&buf)) {
                if let Some(&stream_index) = self.pid_to_stream.get(&pkt.pid) {
                    let rai = pkt
                        .adaptation_field
                        .as_ref()
                        .is_some_and(|af| af.random_access_indicator);
                    if rai {
                        unresolved.entry(pkt.pid).or_default().push(out.len());
                        out.push(RandomAccessPoint {
                            byte_offset: off,
                            pid: pkt.pid,
                            stream_index,
                            pts_90k: None,
                            kind: AccessPointKind::RandomAccessIndicator,
                        });
                    }
                    if pkt.payload_unit_start {
                        let pes = PesPacket::parse(pkt.payload).ok();
                        let pts = pes.as_ref().and_then(|p| p.pts_90k).map(|raw| {
                            let ext = match pts_ref.get(&pkt.pid) {
                                Some(&r) => crate::clock::extend_near(raw, r),
                                None => raw,
                            };
                            pts_ref.insert(pkt.pid, ext);
                            ext
                        });
                        if let Some(pending) = unresolved.remove(&pkt.pid) {
                            // This PES start is the one the pending
                            // indicator(s) announced; lift its PTS.
                            for i in pending {
                                out[i].pts_90k = pts;
                            }
                        } else if pes.is_some_and(|p| p.data_alignment_indicator) && pts.is_some() {
                            // No indicator announced this PES, but its
                            // payload starts data-aligned (§2.4.3.7) —
                            // the fallback access-point tier.
                            out.push(RandomAccessPoint {
                                byte_offset: off,
                                pid: pkt.pid,
                                stream_index,
                                pts_90k: pts,
                                kind: AccessPointKind::DataAligned,
                            });
                        }
                    }
                }
            }
            off += psize;
        }
        self.input
            .seek(SeekFrom::Start(resume))
            .map_err(CoreError::Io)?;
        Ok(out)
    }

    /// Seek to the last random-access point at or before `target_90k`
    /// (a PTS in the stream's 90 kHz time base), so the next demuxed
    /// PES on the point's PID is a keyframe / elementary-stream access
    /// point (§2.4.3.5). This is the keyframe-accurate companion to
    /// the PCR-granular [`oxideav_core::Demuxer::seek_to`]: where the
    /// PCR search lands on clock samples and relies on the caller to
    /// decode forward, this lands decoding directly on an access
    /// point.
    ///
    /// `stream_index` restricts the candidate points to one elementary
    /// stream — typically the video track, whose keyframes gate the
    /// whole program's decodability; `None` considers every indexed
    /// point.
    ///
    /// Builds (and caches) the [`Self::random_access_points`] index on
    /// first use — one full forward scan. Only
    /// [`AccessPointKind::RandomAccessIndicator`] points qualify (this
    /// surface is the full §2.4.3.5 guarantee; the tiered fallback is
    /// [`Self::seek_to_access_point`]). A target before the first
    /// indexed point clamps to that first point. `target_90k` and the
    /// returned landing are on the **extended** 90 kHz timeline.
    ///
    /// Errors with `Unsupported` when the stream carries no matching
    /// `random_access_indicator` with a resolvable PTS — the caller
    /// falls back to the PCR-based `seek_to`.
    pub fn seek_to_random_access(
        &mut self,
        stream_index: Option<u32>,
        target_90k: i64,
    ) -> CoreResult<i64> {
        self.random_access_points()?;
        let index = self.rap_index.as_deref().unwrap_or(&[]);
        // Last point with a known PTS at or before the target; else
        // the first known-PTS point (clamp-up for early targets).
        let mut best: Option<(u64, u64)> = None; // (byte_offset, pts)
        let mut first: Option<(u64, u64)> = None;
        for rap in index {
            // This surface is the §2.4.3.5 guarantee only; the tiered
            // fallback lives in `seek_to_access_point`.
            if rap.kind != AccessPointKind::RandomAccessIndicator {
                continue;
            }
            if stream_index.is_some_and(|want| rap.stream_index != want) {
                continue;
            }
            let pts = match rap.pts_90k {
                Some(p) => p,
                None => continue,
            };
            if first.is_none() {
                first = Some((rap.byte_offset, pts));
            }
            if pts as i64 <= target_90k {
                best = Some((rap.byte_offset, pts));
            }
        }
        let (offset, pts) = best.or(first).ok_or_else(|| {
            CoreError::unsupported(
                "mpegts: stream carries no random_access_indicator with a PTS to seek against",
            )
        })?;
        self.reposition(offset, Some(pts as i64));
        Ok(pts as i64)
    }

    /// Keyframe-aware seek — the [`oxideav_core::Demuxer::seek_to`]
    /// contract ("nearest keyframe at or before `pts`") realised over
    /// the two container-level access-point signals, without paying a
    /// full-stream scan on well-behaved inputs.
    ///
    /// Strategy, in order:
    /// 1. **PCR bisection + windowed scan.** Locate the last PCR at or
    ///    before the target (the same locator the plain PCR seek uses) and
    ///    walk forward from it collecting access points on the
    ///    stream's PID — `random_access_indicator` announcements
    ///    (§2.4.3.5, preferred) and data-aligned PES starts (§2.4.3.7,
    ///    fallback; see [`AccessPointKind`]) — until the PES timeline
    ///    passes the target. If the window holds no point at or before
    ///    the target (the keyframe interval outruns the ≤100 ms
    ///    §2.7.2 PCR spacing), re-bisect progressively further back
    ///    (1 s, 2 s, 4 s, …) until one is found or the stream head is
    ///    reached.
    /// 2. **Cached full index.** PCR-less streams — or targets with no
    ///    access point anywhere at or before them — fall back to the
    ///    [`Self::random_access_points`] index, which also handles the
    ///    clamp-up to the first point of an early target.
    ///
    /// The landing repositions the demux state at the access point's
    /// anchor packet (for an indicator point, the flagged packet — so
    /// the reassembler re-derives the keyframe flag on the emitted
    /// [`Packet`]) and re-seeds the timestamp trackers there. Returns
    /// the landed access point's **extended** PTS.
    ///
    /// Errors with `Unsupported` when the stream signals no access
    /// points for the stream at all — the caller degrades to the
    /// PCR-granular landing of the plain `Demuxer::seek_to` fallback.
    pub fn seek_to_access_point(&mut self, stream_index: u32, target_90k: i64) -> CoreResult<i64> {
        let pid = self
            .pid_to_stream
            .iter()
            .find_map(|(&pid, &idx)| (idx == stream_index).then_some(pid))
            .ok_or_else(|| {
                CoreError::invalid(format!("mpegts: no stream with index {stream_index}"))
            })?;

        // Once the full index exists it is definitive AND cheap —
        // prefer it over re-scanning windows on every subsequent seek.
        if self.rap_index.is_some() || self.first_pcr.is_none() || self.last_pcr.is_none() {
            return self.seek_via_index(stream_index, target_90k);
        }

        let first_off = self.first_pcr.map(|(_, off)| off).unwrap_or(0);
        // Backoff loop: each round bisects to an earlier landing and
        // rescans forward to the target. `back` doubles per round, so
        // a keyframe K seconds before the target is found after
        // O(log K) bisections of O(K) window bytes.
        let mut probe_target = target_90k;
        let mut back: i64 = 90_000; // 1 s
        loop {
            let (from_off, from_time) = self.locate_pcr_at_or_before(probe_target)?;
            let (best_rai, best_dai) =
                self.scan_access_points_window(pid, from_off, from_time, target_90k)?;
            if let Some((off, pts)) = best_rai {
                self.reposition(off, Some(pts));
                return Ok(pts);
            }
            if let Some((off, pts)) = best_dai {
                // Only the weak tier in the window. The §2.4.3.5
                // indicator is a per-stream mux property — if this PID
                // uses it anywhere, an indicator keyframe further back
                // must win over a nearby aligned-but-maybe-predicted
                // PES. That is a stream-global question, so answer it
                // with the (cached, one full scan) index.
                self.random_access_points()?;
                let pid_uses_rai = self
                    .rap_index
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|r| r.pid == pid && r.kind == AccessPointKind::RandomAccessIndicator);
                if pid_uses_rai {
                    return self.seek_via_index(stream_index, target_90k);
                }
                self.reposition(off, Some(pts));
                return Ok(pts);
            }
            if from_off <= first_off {
                // Window already started at the stream head — nothing
                // at or before the target exists.
                break;
            }
            probe_target = from_time.saturating_sub(back);
            back = back.saturating_mul(2);
        }

        // No access point at or before the target anywhere: the full
        // index decides (clamping up to the first point when the
        // target precedes them all).
        self.seek_via_index(stream_index, target_90k)
    }

    /// Scan forward from packet-aligned `from_off` (whose extended
    /// stream time is `from_time`) collecting access points on `pid`;
    /// return the last candidate at or before `target_90k` per tier as
    /// `(indicator_announced, data_aligned)`, each an
    /// `(anchor_byte_offset, extended_pts)` pair. The caller owns the
    /// tier arbitration.
    ///
    /// The scan stops once a PES start's extended PTS passes the
    /// target by a reorder-grace second (B-picture presentation times
    /// legitimately step backward around a keyframe, so the first
    /// PTS > target is not proof that none ≤ target follows) or the
    /// stream ends. The input cursor is left wherever the scan
    /// stopped; callers reposition afterwards.
    #[allow(clippy::type_complexity)]
    fn scan_access_points_window(
        &mut self,
        pid: u16,
        from_off: u64,
        from_time: i64,
        target_90k: i64,
    ) -> CoreResult<(Option<(u64, i64)>, Option<(u64, i64)>)> {
        /// Keep scanning until the PID's PES timeline is this far past
        /// the seek target — one second covers any realistic
        /// B-picture reorder window.
        const REORDER_GRACE_90K: i64 = 90_000;

        let psize = self.layout.packet_size as u64;
        self.input
            .seek(std::io::SeekFrom::Start(from_off))
            .map_err(CoreError::Io)?;

        let mut best_rai: Option<(u64, i64)> = None;
        let mut best_dai: Option<(u64, i64)> = None;
        // Anchor of an unresolved §2.4.3.5 indicator: the flagged
        // packet's offset, waiting for the next PES start on the PID.
        let mut pending_rai: Option<u64> = None;
        // Reference for the epoch-nearest PTS unwrap, advanced to each
        // resolved PES time; seeded by the PCR landing time.
        let mut pts_ref = from_time.max(0) as u64;

        let mut off = from_off;
        let mut buf = [0u8; MAX_PHYSICAL_PACKET];
        loop {
            if read_exact_packet(&mut self.input, &mut buf[..psize as usize]).is_err() {
                break; // end of stream — window exhausted
            }
            let pkt_off = off;
            off += psize;
            let Ok(pkt) = TsPacket::parse(self.layout.window(&buf)) else {
                continue; // stray corruption: skip, as the index scan does
            };
            if pkt.pid != pid {
                continue;
            }
            let rai = pkt
                .adaptation_field
                .as_ref()
                .is_some_and(|af| af.random_access_indicator);
            if rai && pending_rai.is_none() {
                pending_rai = Some(pkt_off);
            }
            if !pkt.payload_unit_start {
                continue;
            }
            let pes = match PesPacket::parse(pkt.payload) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let Some(raw_pts) = pes.pts_90k else {
                pending_rai = None; // consumed by a PTS-less PES start
                continue;
            };
            let ext = crate::clock::extend_near(raw_pts, pts_ref) as i64;
            pts_ref = ext.max(0) as u64;
            if let Some(anchor) = pending_rai.take() {
                if ext <= target_90k {
                    best_rai = Some((anchor, ext));
                }
            } else if pes.data_alignment_indicator && ext <= target_90k {
                best_dai = Some((pkt_off, ext));
            }
            if ext > target_90k.saturating_add(REORDER_GRACE_90K) {
                break;
            }
        }
        Ok((best_rai, best_dai))
    }

    /// Index-backed access-point seek: the definitive (whole-stream)
    /// fallback behind [`Self::seek_to_access_point`]. Uses the cached
    /// [`Self::random_access_points`] index, preferring
    /// indicator-announced points over data-aligned ones, the last at
    /// or before `target_90k` over the clamp-up first.
    fn seek_via_index(&mut self, stream_index: u32, target_90k: i64) -> CoreResult<i64> {
        self.random_access_points()?;
        let index = self.rap_index.as_deref().unwrap_or(&[]);
        // (byte_offset, pts) per tier: last at-or-before + first seen.
        let mut best: [Option<(u64, u64)>; 2] = [None, None];
        let mut first: [Option<(u64, u64)>; 2] = [None, None];
        for rap in index {
            if rap.stream_index != stream_index {
                continue;
            }
            let Some(pts) = rap.pts_90k else { continue };
            let tier = match rap.kind {
                AccessPointKind::RandomAccessIndicator => 0,
                AccessPointKind::DataAligned => 1,
            };
            if first[tier].is_none() {
                first[tier] = Some((rap.byte_offset, pts));
            }
            if pts as i64 <= target_90k {
                best[tier] = Some((rap.byte_offset, pts));
            }
        }
        let (offset, pts) = best[0]
            .or(best[1])
            .or(first[0])
            .or(first[1])
            .ok_or_else(|| {
                CoreError::unsupported(
                    "mpegts: stream signals no access point (random_access_indicator or \
                     data-aligned PES start) with a PTS to seek against",
                )
            })?;
        self.reposition(offset, Some(pts as i64));
        Ok(pts as i64)
    }

    /// Re-home the streaming state at byte `offset` (packet-aligned):
    /// seek the input cursor, drop every in-flight PES and the pending
    /// queue, and reset the PCR / PTS / DTS trackers so the timeline
    /// rebuilds from the landing point. Dropping the in-flight PES
    /// state means a landing that falls mid-PES simply discards
    /// continuation bytes until the next `payload_unit_start` — the
    /// continuity-counter history is void after a byte-position jump,
    /// exactly as after a signalled discontinuity (§2.4.3.4).
    ///
    /// `time_hint_90k` is the landing point's time on the **extended**
    /// 90 kHz timeline (the landed PCR / access-point PTS). When given,
    /// the PTS/DTS trackers are re-seeded with it instead of blindly
    /// reset, so the first post-seek timestamps re-enter the wrap epoch
    /// the caller seeked along rather than re-anchoring at their raw
    /// 33-bit values ([`PtsTracker::seed`]).
    fn reposition(&mut self, offset: u64, time_hint_90k: Option<i64>) {
        let _ = self.input.seek(std::io::SeekFrom::Start(offset));
        self.bytes_read = offset;
        self.putback.clear();
        self.pending.clear();
        self.eof_reached = false;
        self.pcr_tracker.reset();
        for r in self.reassemblers.values_mut() {
            *r = PesReassembler::new();
        }
        let hint = time_hint_90k.and_then(|t| u64::try_from(t).ok());
        for t in self
            .pts_trackers
            .values_mut()
            .chain(self.dts_trackers.values_mut())
        {
            match hint {
                Some(h) => t.seed(h),
                None => t.reset(),
            }
        }
    }

    /// Scan forward from byte offset `from` (must be packet-aligned)
    /// toward `len`, returning the first PCR on the selected `PCR_PID`
    /// and the byte offset of the packet that carried it. Restores the
    /// input cursor to where it found the match is *not* required — the
    /// caller treats this as an out-of-band probe.
    fn scan_pcr_forward(&mut self, from: u64, len: u64) -> Option<(Pcr, u64)> {
        let psize = self.layout.packet_size as u64;
        self.input.seek(std::io::SeekFrom::Start(from)).ok()?;
        let mut off = from;
        let mut buf = [0u8; MAX_PHYSICAL_PACKET];
        while off + psize <= len {
            if read_exact_packet(&mut self.input, &mut buf[..psize as usize]).is_err() {
                return None;
            }
            if let Some(pcr) = pcr_from_packet(self.layout.window(&buf), self.pcr_pid) {
                return Some((pcr, off));
            }
            off += psize;
        }
        None
    }

    /// Scan the half-open packet-aligned byte range `[from, to)` and
    /// return the **last** PCR on the selected `PCR_PID` together with
    /// its packet offset. `from` and `to` must be packet-aligned.
    fn scan_pcr_backward(&mut self, from: u64, to: u64) -> Option<(Pcr, u64)> {
        let psize = self.layout.packet_size as u64;
        self.input.seek(std::io::SeekFrom::Start(from)).ok()?;
        let mut off = from;
        let mut buf = [0u8; MAX_PHYSICAL_PACKET];
        let mut found: Option<(Pcr, u64)> = None;
        while off + psize <= to {
            if read_exact_packet(&mut self.input, &mut buf[..psize as usize]).is_err() {
                break;
            }
            if let Some(pcr) = pcr_from_packet(self.layout.window(&buf), self.pcr_pid) {
                found = Some((pcr, off));
            }
            off += psize;
        }
        found
    }

    /// Unwrap a freshly reassembled PES into a [`Packet`], carrying the
    /// monotonic 64-bit extended PTS/DTS (§2.4.3.7) rather than the raw
    /// 33-bit ring value, and record the stream's `start_time` on its
    /// first timestamped packet.
    fn finish_pes(&mut self, pid: u16, stream_idx: u32, pes: PesPacket) -> Packet {
        let tb = TimeBase::new(1, 90_000);
        let mut pkt = Packet::new(stream_idx, tb, pes.payload);
        // A TS-level random_access_indicator (§2.4.3.5) announced this
        // PES as beginning at an elementary-stream access point — the
        // container-level keyframe signal.
        if pes.random_access {
            pkt = pkt.with_keyframe(true);
        }
        let mut pts_ext: Option<u64> = None;
        if let Some(raw) = pes.pts_90k {
            let ext = if let Some(t) = self.pts_trackers.get_mut(&pid) {
                t.observe(raw);
                t.extended().unwrap_or(raw)
            } else {
                raw
            };
            pts_ext = Some(ext);
            pkt = pkt.with_pts(ext as i64);
            let info = &mut self.streams[stream_idx as usize];
            if info.start_time.is_none() {
                info.start_time = Some(ext as i64);
            }
        }
        if let Some(raw) = pes.dts_90k {
            let ext = if let Some(t) = self.dts_trackers.get_mut(&pid) {
                // §2.4.3.7: DTS and PTS share one time base. A stream
                // whose first coded DTS only appears after a 2^33 wrap
                // must not anchor an independent epoch at the raw ring
                // value — seed the tracker with this PES's extended
                // PTS so both fields stay on the same 64-bit axis
                // (found by the mux_roundtrip fuzz target on a
                // wrap-crossing timeline).
                if t.extended().is_none() {
                    if let Some(hint) = pts_ext {
                        t.seed(hint);
                    }
                }
                t.observe(raw);
                t.extended().unwrap_or(raw)
            } else {
                raw
            };
            pkt = pkt.with_dts(ext as i64);
        }
        pkt
    }

    /// Feed a TS packet's adaptation field into the PCR clock recovery
    /// when it lands on the selected program's `PCR_PID`.
    fn observe_pcr(&mut self, pkt: &TsPacket<'_>, byte_offset: u64) {
        if pkt.pid != self.pcr_pid {
            return;
        }
        if let Some(af) = &pkt.adaptation_field {
            self.pcr_tracker.observe(af, byte_offset);
        }
    }

    /// Pull one TS packet from the input and, if it's for a stream we
    /// track, feed the per-PID reassembler. Returns the number of
    /// `Packet`s pushed into `self.pending` by this call.
    fn read_one_into_pending(&mut self) -> CoreResult<usize> {
        let buf = match read_one_packet(
            &mut self.input,
            &mut self.putback,
            self.bytes_read,
            self.layout,
        )? {
            Some(b) => b,
            None => return Ok(0),
        };
        let pkt_offset = self.bytes_read;
        self.bytes_read += self.layout.packet_size as u64;
        let pkt = TsPacket::parse(&buf).map_err(map_ts_err)?;
        // PCR recovery runs on the PCR_PID regardless of whether that
        // PID also carries an elementary stream we track.
        self.observe_pcr(&pkt, pkt_offset);
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
            let packet = self.finish_pes(pkt.pid, stream_idx, pes);
            self.pending.push_back(packet);
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
            let flushed = self
                .reassemblers
                .get_mut(&pid)
                .and_then(|r| r.flush().ok().flatten());
            if let Some(pes) = flushed {
                let packet = self.finish_pes(pid, stream_idx, pes);
                self.pending.push_back(packet);
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

    fn duration_micros(&self) -> Option<i64> {
        self.duration_micros
    }

    fn seek_to(&mut self, stream_index: u32, pts: i64) -> CoreResult<i64> {
        // MPEG-TS time base is 90 kHz for every stream, and PTS / PCR
        // share that base, so the requested `pts` is already in the
        // units the access-point / PCR searches compare against — no
        // per-stream rescale is needed.
        //
        // Keyframe-accurate landing first (the trait contract); a
        // stream that signals no access points at all degrades to the
        // PCR-granular landing, which still positions at or before the
        // target so the caller can decode forward.
        match self.seek_to_access_point(stream_index, pts) {
            Ok(landed) => Ok(landed),
            Err(CoreError::Unsupported(_)) => self.seek_by_pcr(pts),
            Err(e) => Err(e),
        }
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
                match read_one_packet(
                    &mut self.input,
                    &mut self.putback,
                    self.bytes_read,
                    self.layout,
                )? {
                    None => {
                        self.eof_reached = true;
                        self.flush_reassemblers();
                    }
                    Some(buf) => {
                        let pkt_offset = self.bytes_read;
                        self.bytes_read += self.layout.packet_size as u64;
                        // We've already advanced past an EOF earlier
                        // when this branch was taken with pushed=0 but
                        // there ARE more bytes — that means the prior
                        // packet was a non-stream PID (silently
                        // dropped). Re-parse + feed and loop.
                        let pkt = TsPacket::parse(&buf).map_err(map_ts_err)?;
                        self.observe_pcr(&pkt, pkt_offset);
                        if let Some(stream_idx) = self.pid_to_stream.get(&pkt.pid).copied() {
                            let emitted = self
                                .reassemblers
                                .get_mut(&pkt.pid)
                                .and_then(|r| r.feed(&pkt).transpose())
                                .transpose()
                                .map_err(map_ts_err)?;
                            if let Some(pes) = emitted {
                                let packet = self.finish_pes(pkt.pid, stream_idx, pes);
                                self.pending.push_back(packet);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Maximum packet-sized chunks we'll skip while resyncing after a bad
/// sync byte. We've observed real BD M2TS streams with ~2 AACS units
/// (~12 KB ≈ 64 TS packets) of undecryptable bytes at chapter
/// boundaries — an independent decryption of the same disc reproduces
/// the same garbage bytes there, so the bytes are part of the
/// protected variant-key area, not a flaw in our decryption. 256
/// packets gives a comfortable ceiling without silently swallowing a
/// longer corruption that the caller should know about.
const RESYNC_PACKET_LIMIT: usize = 256;

/// Largest physical packet size the demuxer tolerates (the 204-byte
/// trailer-appended form; see [`crate::packet::TsPacketLayout`]).
const MAX_PHYSICAL_PACKET: usize = 204;

/// Read exactly one physical packet (per `layout`) from the input and
/// return its logical 188-byte TS window.
///
/// Drains from `putback` first (used by the resync path to feed peeked
/// bytes back to the caller) and then from `input`.
///
/// Returns `Ok(None)` cleanly when fewer than a packet's bytes remain —
/// the caller treats that as end-of-stream. A short read mid-packet
/// (e.g. the stream is truncated) surfaces as `Err`.
///
/// On a sync-byte mismatch we **resync** by discarding packet-sized
/// chunks until we find one with `0x47` at the layout's sync offset
/// AND another `0x47` one packet stride later (the next packet's
/// sync). The probed bytes are buffered in `putback` so the next call
/// sees them as the head of a fresh packet — without that, every
/// subsequent read would land misaligned and re-trigger resync.
fn read_one_packet(
    input: &mut Box<dyn ReadSeek>,
    putback: &mut VecDeque<u8>,
    bytes_read: u64,
    layout: crate::packet::TsPacketLayout,
) -> CoreResult<Option<[u8; TS_PACKET_LEN]>> {
    use std::io::Read;
    let psize = layout.packet_size;
    let mut buf = [0u8; MAX_PHYSICAL_PACKET];
    let mut filled = 0;
    // Drain putback first.
    while filled < psize {
        match putback.pop_front() {
            Some(b) => {
                buf[filled] = b;
                filled += 1;
            }
            None => break,
        }
    }
    while filled < psize {
        match input.read(&mut buf[filled..psize]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(CoreError::invalid(format!(
                    "mpegts: short read at packet boundary ({filled}/{psize} bytes, offset {bytes_read})"
                )));
            }
            Ok(n) => filled += n,
            Err(e) => return Err(CoreError::Io(e)),
        }
    }
    if buf[layout.sync_offset] != TS_SYNC_BYTE {
        return resync(input, putback, buf[layout.sync_offset], bytes_read, layout).map(Some);
    }
    let mut out = [0u8; TS_PACKET_LEN];
    out.copy_from_slice(layout.window(&buf));
    Ok(Some(out))
}

/// Resync after a bad sync byte. Read one fresh packet-sized chunk; if
/// it carries `0x47` at the layout's sync offset, accept it as the
/// recovered packet — but **only** after confirming the byte one
/// packet stride later is also `0x47` (the next packet's sync). The
/// double-sync check is what rejects random `0x47` bytes inside
/// garbage data.
///
/// We don't try to recover the failing packet itself; we just skip it
/// (and any further failing chunks) until a clean packet boundary
/// appears. After at most [`RESYNC_PACKET_LIMIT`] failed chunks,
/// surface as `Err`.
///
/// `bad_byte` is the byte that failed the sync check, kept for
/// diagnostics.
fn resync(
    input: &mut Box<dyn ReadSeek>,
    putback: &mut VecDeque<u8>,
    bad_byte: u8,
    bytes_read: u64,
    layout: crate::packet::TsPacketLayout,
) -> CoreResult<[u8; TS_PACKET_LEN]> {
    use std::io::Read;
    let psize = layout.packet_size;
    let mut buf = [0u8; MAX_PHYSICAL_PACKET];
    // To verify the NEXT packet's sync we must read past its framing
    // prefix: `sync_offset + 1` probe bytes.
    let probe_len = layout.sync_offset + 1;
    let mut probe = [0u8; MAX_PHYSICAL_PACKET];
    for _ in 0..RESYNC_PACKET_LIMIT {
        // Read one fresh packet-sized chunk.
        let mut filled = 0;
        while filled < psize {
            match input.read(&mut buf[filled..psize]) {
                Ok(0) => {
                    return Err(CoreError::invalid(format!(
                        "mpegts: bad sync byte 0x{bad_byte:02X} at offset {bytes_read} \
                         and EOF reached during resync"
                    )));
                }
                Ok(n) => filled += n,
                Err(e) => return Err(CoreError::Io(e)),
            }
        }
        if buf[layout.sync_offset] != TS_SYNC_BYTE {
            continue;
        }
        // Candidate passes single-sync; probe up to the next packet's
        // sync byte for a double-sync.
        let mut probed = 0;
        let mut hit_eof = false;
        while probed < probe_len {
            match input.read(&mut probe[probed..probe_len]) {
                Ok(0) => {
                    hit_eof = true;
                    break;
                }
                Ok(n) => probed += n,
                Err(e) => return Err(CoreError::Io(e)),
            }
        }
        if hit_eof {
            // EOF while probing after a clean candidate. Trust the
            // single sync byte; we can't double-check, but the packet
            // itself parsed (any partially probed bytes are a
            // truncated tail and are dropped).
            let mut out = [0u8; TS_PACKET_LEN];
            out.copy_from_slice(layout.window(&buf));
            return Ok(out);
        }
        if probe[probe_len - 1] == TS_SYNC_BYTE {
            // Push the probed bytes back so the next call sees them as
            // the head of a fresh packet.
            for &b in &probe[..probe_len] {
                putback.push_back(b);
            }
            let mut out = [0u8; TS_PACKET_LEN];
            out.copy_from_slice(layout.window(&buf));
            return Ok(out);
        }
        // Single 0x47 not confirmed by a sync one stride later; treat
        // as coincidence inside garbage data and keep scanning. The
        // probed bytes are also part of the corrupt span — drop them.
    }
    Err(CoreError::invalid(format!(
        "mpegts: bad sync byte 0x{bad_byte:02X} at offset {bytes_read} (packet {}), \
         resync failed after {RESYNC_PACKET_LIMIT} {psize}-byte chunks",
        bytes_read / psize as u64,
    )))
}

fn map_ts_err(e: crate::TsError) -> CoreError {
    CoreError::invalid(format!("mpegts: {e}"))
}

/// Read exactly `buf.len()` bytes (one physical packet) from `input`,
/// retrying on short reads. Used by the seek / duration probes, which
/// always start on a packet boundary and want a hard error rather than
/// the streaming reader's resync behaviour.
fn read_exact_packet(input: &mut Box<dyn ReadSeek>, buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "mpegts: short read during PCR probe",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Extract the [`Pcr`] from a 188-byte TS packet window iff the packet
/// is on `want_pid`, carries an adaptation field, and the field sets
/// `PCR_flag`. Returns `None` otherwise — including for a non-`0x47`
/// buffer (an unaligned probe window) or a malformed adaptation field.
fn pcr_from_packet(buf: &[u8], want_pid: u16) -> Option<Pcr> {
    if buf.first() != Some(&TS_SYNC_BYTE) {
        return None;
    }
    let pkt = TsPacket::parse(buf).ok()?;
    if pkt.pid != want_pid {
        return None;
    }
    let af = pkt.adaptation_field.as_ref()?;
    let base = af.pcr_base?;
    let ext = af.pcr_extension.unwrap_or(0);
    Some(Pcr::from_base_ext(base, ext))
}

/// Compute the 27 MHz tick span between a head PCR (`first`, at byte
/// `first_off`) and a tail PCR (`last`, at byte `last_off`),
/// correcting for the `PCR_MODULUS_27MHZ` wrap(s) a stream longer than
/// ~26.5 h crosses.
///
/// The naive `last - first` is ambiguous once the value wraps. We
/// report the zero-wrap modular delta (`(last - first) mod modulus`),
/// which is the exact span for every stream shorter than one PCR wrap
/// (≈26.5 h) — i.e. all realistic `.m2ts` / broadcast inputs. Telling
/// wrap count apart from two PCRs alone needs a transport-rate
/// estimate (§2.4.2.2, eq. 2-5) and is defeated by any mid-stream PCR
/// discontinuity, so the zero-wrap delta is the safe report.
fn pcr_span_27mhz(first: Pcr, first_off: u64, last: Pcr, last_off: u64) -> Option<i64> {
    if last_off <= first_off {
        return None;
    }
    let modulus = crate::PCR_MODULUS_27MHZ as i128;
    // Modular delta in [0, modulus): how far `last` is "after" `first`
    // on the PCR ring, ignoring whole wraps.
    let raw = last.ticks_27mhz as i128 - first.ticks_27mhz as i128;
    let modular = ((raw % modulus) + modulus) % modulus;
    i64::try_from(modular).ok()
}

/// Walk a PMT stream's ES_info descriptor loop and return the first
/// `ISO_639_language_descriptor` (tag 0x0A) language code as a UTF-8
/// string, trimming the spec's space padding. `None` when the loop
/// carries no language descriptor or the code is empty.
fn first_iso639_language(pmt_stream: &crate::PmtStream) -> Option<String> {
    for d in pmt_stream.iter_descriptors().flatten() {
        if let crate::DescriptorBody::Iso639Language(langs) = &d.body {
            if let Some(first) = langs.first() {
                let s: String = first
                    .language
                    .iter()
                    .map(|&b| b as char)
                    .collect::<String>()
                    .trim_end_matches([' ', '\0'])
                    .to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Map an MPEG-TS `stream_type` byte to a [`CodecParameters`] the
/// muxer registry understands. `None` means "drop this stream" —
/// interactive graphics, DSM-CC sections, vendor-private codes, etc.
fn codec_params_for_stream_type(st: u8) -> Option<CodecParameters> {
    let s = StreamType::from_raw(st);
    // (codec_id, is_video, is_subtitle); audio is the residual class.
    let (cid, is_video, is_subtitle): (&'static str, bool, bool) = match s {
        StreamType::Mpeg1Video => ("mpeg1video", true, false),
        StreamType::Mpeg2Video | StreamType::Mpeg2StereoView => ("mpeg2video", true, false),
        StreamType::Mpeg4Visual => ("mpeg4", true, false),
        StreamType::AvcVideo | StreamType::AvcStereoView => ("h264", true, false),
        StreamType::HevcVideo | StreamType::HevcTemporalSubset => ("hevc", true, false),
        StreamType::Jpeg2000Video => ("jpeg2000", true, false),
        StreamType::Vc1Video => ("vc1", true, false),
        StreamType::Mpeg1Audio | StreamType::Mpeg2Audio => ("mp2", false, false),
        StreamType::AacAdts | StreamType::AacLatm | StreamType::Mpeg4AudioRaw => {
            ("aac", false, false)
        }
        StreamType::LpcmAudio => ("pcm_s16be", false, false),
        StreamType::Ac3Audio | StreamType::EAc3SecondaryAudio => ("ac3", false, false),
        StreamType::EAc3Audio => ("eac3", false, false),
        StreamType::TruehdAudio => ("truehd", false, false),
        StreamType::DtsAudio
        | StreamType::DtsHdAudio
        | StreamType::DtsHdMaAudio
        | StreamType::DtsHdSecondaryAudio => ("dts", false, false),
        StreamType::PgsSubtitle => ("hdmv_pgs_subtitle", false, true),
        StreamType::TextSubtitle => ("hdmv_textst_subtitle", false, true),
        StreamType::Mpeg4Text => ("mov_text", false, true),
        // Interactive graphics, DSM-CC, metadata, private sections, and
        // every reserved / vendor-private code: drop the stream.
        _ => return None,
    };
    let codec_id = CodecId::new(cid);
    Some(if is_video {
        CodecParameters::video(codec_id)
    } else if is_subtitle {
        CodecParameters::subtitle(codec_id)
    } else {
        CodecParameters::audio(codec_id)
    })
}

/// Probe an MPEG-TS byte stream — the canonical heuristic checks for
/// the `0x47` sync byte on a consistent packet grid. All three
/// physical framings are recognised: plain 188-byte packets, 192-byte
/// (4-byte-prefixed) source packets, and 204-byte (16-byte-trailer)
/// packets. Real-world transport streams are sync-aligned at the
/// start; a hit at 3+ grid positions is unambiguous.
///
/// Scores follow the convention in
/// [`oxideav_core::ContainerProbeFn`]:
/// * `100` — sync byte present at 4 consecutive grid positions.
/// * `80`  — sync byte present at 3.
/// * `60`  — sync byte present at 2.
/// * `0`   — otherwise.
pub fn probe(p: &oxideav_core::ProbeData) -> oxideav_core::ProbeScore {
    use crate::packet::TsPacketLayout;
    let mut best = 0u8;
    for layout in [
        TsPacketLayout::STANDARD,
        TsPacketLayout::PREFIXED_192,
        TsPacketLayout::TRAILER_204,
    ] {
        let mut hits = 0u8;
        for k in 0..4usize {
            let off = k * layout.packet_size + layout.sync_offset;
            if p.buf.get(off).copied() == Some(TS_SYNC_BYTE) {
                hits += 1;
            } else {
                break; // grids must be consistent from packet 0
            }
        }
        best = best.max(hits);
    }
    match best {
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

    /// PSI CRC-32/MPEG-2 — shared by the multi-program test below.
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

    /// Build a TS whose PAT lists two programs (1 → PMT 0x100, 2 → PMT
    /// 0x200), each with a distinct elementary stream type. Only the
    /// selected program's PMT + PES are materialised; the other PMT is
    /// present so the demuxer must skip it.
    fn synth_two_program_ts() -> Vec<u8> {
        fn ts_psi(pid: u16, cc: u8, section: &[u8]) -> [u8; TS_PACKET_LEN] {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            pkt[1] = 0b0100_0000 | ((pid >> 8) as u8 & 0x1F);
            pkt[2] = pid as u8;
            pkt[3] = 0b0001_0000 | (cc & 0x0F);
            pkt[4] = 0; // pointer_field
            let take = (TS_PACKET_LEN - 5).min(section.len());
            pkt[5..5 + take].copy_from_slice(&section[..take]);
            pkt
        }
        // PAT: program 1 → 0x100, program 2 → 0x200.
        let mut pat = vec![
            0x00, 0xB0, 0x11, // table_id, ssi+len=17
            0x00, 0x01, // tsid
            0xC1, 0x00, 0x00, // version/cni, section, last
            0x00, 0x01, 0xE1, 0x00, // program 1 → 0x100
            0x00, 0x02, 0xE2, 0x00, // program 2 → 0x200
        ];
        let c = crc32_mpeg2(&pat);
        pat.extend_from_slice(&c.to_be_bytes());

        // PMT for program 2: one MPEG-2 video (0x02) stream on 0x201.
        let mut pmt2 = vec![
            0x02, 0xB0, 0x12, 0x00, 0x02, // program_number = 2
            0xC1, 0x00, 0x00, 0xE2, 0x01, // pcr_pid = 0x201
            0xF0, 0x00, // program_info_length = 0
            0x02, 0xE2, 0x01, 0xF0, 0x00, // stream_type 0x02, pid 0x201
        ];
        let c2 = crc32_mpeg2(&pmt2);
        pmt2.extend_from_slice(&c2.to_be_bytes());

        // PMT for program 1: one AVC (0x1B) stream on 0x101.
        let mut pmt1 = vec![
            0x02, 0xB0, 0x12, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x01, 0xF0, 0x00, 0x1B, 0xE1,
            0x01, 0xF0, 0x00,
        ];
        let c1 = crc32_mpeg2(&pmt1);
        pmt1.extend_from_slice(&c1.to_be_bytes());

        let mut buf = Vec::new();
        buf.extend_from_slice(&ts_psi(0x0000, 0, &pat));
        buf.extend_from_slice(&ts_psi(0x0100, 0, &pmt1));
        buf.extend_from_slice(&ts_psi(0x0200, 0, &pmt2));
        buf
    }

    #[test]
    fn default_open_selects_first_program_and_lists_all() {
        let bytes = synth_two_program_ts();
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let dmx = MpegTsDemuxer::new(cursor).expect("open");
        // Both programs enumerated, network PID excluded.
        assert_eq!(
            dmx.programs(),
            &[
                TsProgram {
                    program_number: 1,
                    pmt_pid: 0x100
                },
                TsProgram {
                    program_number: 2,
                    pmt_pid: 0x200
                },
            ]
        );
        // Default selection is program 1 → AVC.
        assert_eq!(dmx.selected_program(), 1);
        assert_eq!(dmx.streams().len(), 1);
        assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "h264");
    }

    #[test]
    fn open_program_selects_second_program() {
        let bytes = synth_two_program_ts();
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let dmx = MpegTsDemuxer::open_program(cursor, 2).expect("open program 2");
        assert_eq!(dmx.selected_program(), 2);
        assert_eq!(dmx.streams().len(), 1);
        // Program 2's stream is MPEG-2 video.
        assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "mpeg2video");
    }

    #[test]
    fn open_program_rejects_unknown_program_number() {
        let bytes = synth_two_program_ts();
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let err = MpegTsDemuxer::open_program(cursor, 9).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("program_number 9"), "got: {msg}");
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
        let r0 = read_one_packet(
            &mut cursor,
            &mut putback,
            0,
            crate::packet::TsPacketLayout::STANDARD,
        )
        .expect("first")
        .expect("Some");
        assert_eq!(r0[3] & 0x0F, 0);
        // Second read: bytes start at offset 188 (inside garbage), so
        // resync triggers. It should land on p1.
        let r1 = read_one_packet(
            &mut cursor,
            &mut putback,
            188,
            crate::packet::TsPacketLayout::STANDARD,
        )
        .expect("resync")
        .expect("Some");
        assert_eq!(r1[3] & 0x0F, 1, "expected CC=1, got CC={}", r1[3] & 0x0F);
        // Third read: should pick up p2 thanks to the probe-byte
        // putback — no second resync needed.
        let r2 = read_one_packet(
            &mut cursor,
            &mut putback,
            376,
            crate::packet::TsPacketLayout::STANDARD,
        )
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

    /// Encode a 33-bit PTS/DTS field per Table 2-22 with the given
    /// 4-bit marker nibble (`0b0010` PTS-only, `0b0011` PTS prefix of a
    /// PTS+DTS pair, `0b0001` the DTS).
    fn encode_ts33(v: u64, marker_nibble: u8) -> [u8; 5] {
        let mut b = [0u8; 5];
        b[0] = (marker_nibble << 4) | (((v >> 29) & 0x0E) as u8) | 1;
        b[1] = ((v >> 22) & 0xFF) as u8;
        b[2] = (((v >> 14) & 0xFE) as u8) | 1;
        b[3] = ((v >> 7) & 0xFF) as u8;
        b[4] = (((v << 1) & 0xFE) as u8) | 1;
        b
    }

    /// Encode a 6-byte adaptation-field program_clock_reference
    /// (§2.4.3.5): 33-bit base, 6 reserved '1' bits, 9-bit extension.
    fn encode_pcr(base: u64, ext: u16) -> [u8; 6] {
        let mut p = [0u8; 6];
        p[0] = (base >> 25) as u8;
        p[1] = (base >> 17) as u8;
        p[2] = (base >> 9) as u8;
        p[3] = (base >> 1) as u8;
        // bit7 = base LSB, bits6..1 = reserved '1', bit0 = ext MSB.
        p[4] = (((base & 1) as u8) << 7) | (0b0011_1111 << 1) | ((ext >> 8) & 1) as u8;
        p[5] = (ext & 0xFF) as u8;
        p
    }

    /// A PES packet body carrying a PTS (Table 2-22) and a short
    /// payload, with `stream_id = 0xE0`.
    fn pes_with_pts(pts: u64, payload: &[u8]) -> Vec<u8> {
        let pts_bytes = encode_ts33(pts, 0b0010);
        let opt_hdr_len: u8 = 5;
        let pes_len: u16 = 3 + opt_hdr_len as u16 + payload.len() as u16;
        let mut pes = vec![
            0x00,
            0x00,
            0x01,
            0xE0,
            (pes_len >> 8) as u8,
            pes_len as u8,
            0b1000_0000,
            0b1000_0000, // PTS_DTS_flags = 0b10
            opt_hdr_len,
        ];
        pes.extend_from_slice(&pts_bytes);
        pes.extend_from_slice(payload);
        pes
    }

    /// A TS packet on `pid` carrying a PES payload, optionally with an
    /// adaptation field holding a PCR. PUSI=1 (each PES is a fresh
    /// start). `cc` is the continuity counter.
    fn ts_pes(pid: u16, cc: u8, pcr: Option<(u64, u16)>, pes: &[u8]) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [0u8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = 0b0100_0000 | ((pid >> 8) as u8 & 0x1F);
        pkt[2] = pid as u8;
        let mut off = 4;
        if let Some((base, ext)) = pcr {
            // adaptation_field_control = 0b11 (AF + payload).
            pkt[3] = 0b0011_0000 | (cc & 0x0F);
            // adaptation_field_length covers flags(1) + PCR(6) = 7.
            pkt[4] = 7;
            pkt[5] = 0b0001_0000; // PCR_flag = 1
            let p = encode_pcr(base, ext);
            pkt[6..12].copy_from_slice(&p);
            off = 12;
        } else {
            pkt[3] = 0b0001_0000 | (cc & 0x0F); // payload only
        }
        let take = (TS_PACKET_LEN - off).min(pes.len());
        pkt[off..off + take].copy_from_slice(&pes[..take]);
        pkt
    }

    /// Build a single-program TS where the video ES PID (0x101) is also
    /// the PCR_PID, the first PES carries a PCR plus a PTS near the top
    /// of the 33-bit ring, and the second PES's PTS has wrapped past
    /// `2^33`. The demuxer must recover the PCR, set `start_time` to
    /// the first PTS, and unwrap the second PTS onto the extended
    /// timeline (so it reads as `first_pts + delta`, not a small
    /// post-wrap value).
    fn synth_pcr_and_wrap_ts() -> Vec<u8> {
        let mut pat = vec![
            0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xE1, 0x00,
        ];
        let c = crc32_mpeg2(&pat);
        pat.extend_from_slice(&c.to_be_bytes());
        // PMT: PCR_PID = 0x101, one AVC stream on 0x101.
        let mut pmt = vec![
            0x02, 0xB0, 0x12, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x01, 0xF0, 0x00, 0x1B, 0xE1,
            0x01, 0xF0, 0x00,
        ];
        let cp = crc32_mpeg2(&pmt);
        pmt.extend_from_slice(&cp.to_be_bytes());

        fn ts_psi(pid: u16, section: &[u8]) -> [u8; TS_PACKET_LEN] {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            pkt[1] = 0b0100_0000 | ((pid >> 8) as u8 & 0x1F);
            pkt[2] = pid as u8;
            pkt[3] = 0b0001_0000;
            pkt[4] = 0;
            let take = (TS_PACKET_LEN - 5).min(section.len());
            pkt[5..5 + take].copy_from_slice(&section[..take]);
            pkt
        }

        // PTS values: first near the top of the 33-bit ring, second
        // 90_000 ticks (1 s) later — which lands past the 2^33 wrap.
        let modulus = crate::TIMESTAMP_MODULUS_90KHZ;
        let pts0 = modulus - 45_000; // 0.5 s before wrap
        let pts1 = (pts0 + 90_000) & (modulus - 1); // wrapped to 0.5 s

        let mut buf = Vec::new();
        buf.extend_from_slice(&ts_psi(0x0000, &pat));
        buf.extend_from_slice(&ts_psi(0x0100, &pmt));
        // First PES on 0x101 with a PCR (base=pts0, ext=0).
        buf.extend_from_slice(&ts_pes(
            0x0101,
            0,
            Some((pts0, 0)),
            &pes_with_pts(pts0, b"frame0"),
        ));
        // Second PES on 0x101, PTS wrapped, no PCR. A different PID
        // packet in between forces the first PES to flush.
        buf.extend_from_slice(&ts_pes(0x0101, 1, None, &pes_with_pts(pts1, b"frame1")));
        buf
    }

    #[test]
    fn demux_recovers_pcr_and_unwraps_wrapped_pts() {
        let bytes = synth_pcr_and_wrap_ts();
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        assert_eq!(dmx.pcr_pid(), Some(0x101));

        let modulus = crate::TIMESTAMP_MODULUS_90KHZ;
        let pts0 = modulus - 45_000;

        let f0 = dmx.next_packet().expect("frame0");
        assert_eq!(f0.pts, Some(pts0 as i64));
        // start_time is anchored on the first PTS.
        assert_eq!(dmx.streams()[0].start_time, Some(pts0 as i64));
        // The PCR was recovered from the adaptation field.
        assert_eq!(dmx.last_pcr().map(|p| p.base_90khz()), Some(pts0));

        let f1 = dmx.next_packet().expect("frame1");
        // Without unwrapping, f1.pts would read as the small post-wrap
        // raw value (45_000). With the PtsTracker it continues on the
        // extended timeline: pts0 + 90_000.
        assert_eq!(f1.pts, Some((pts0 + 90_000) as i64));
        assert!(
            f1.pts.unwrap() > f0.pts.unwrap(),
            "extended PTS must stay monotonic across the 2^33 wrap"
        );
    }

    /// PAT/PMT pair where the program's PCR_PID is the video ES PID
    /// `0x101`. Returned as raw bytes the caller appends PES packets
    /// after.
    fn pat_pmt_header() -> Vec<u8> {
        let mut pat = vec![
            0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xE1, 0x00,
        ];
        let c = crc32_mpeg2(&pat);
        pat.extend_from_slice(&c.to_be_bytes());
        let mut pmt = vec![
            0x02, 0xB0, 0x12, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x01, 0xF0, 0x00, 0x1B, 0xE1,
            0x01, 0xF0, 0x00,
        ];
        let cp = crc32_mpeg2(&pmt);
        pmt.extend_from_slice(&cp.to_be_bytes());

        fn ts_psi(pid: u16, section: &[u8]) -> [u8; TS_PACKET_LEN] {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            pkt[1] = 0b0100_0000 | ((pid >> 8) as u8 & 0x1F);
            pkt[2] = pid as u8;
            pkt[3] = 0b0001_0000;
            pkt[4] = 0;
            let take = (TS_PACKET_LEN - 5).min(section.len());
            pkt[5..5 + take].copy_from_slice(&section[..take]);
            pkt
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&ts_psi(0x0000, &pat));
        buf.extend_from_slice(&ts_psi(0x0100, &pmt));
        buf
    }

    /// Build a TS that carries `pcr_count` PES packets on PID `0x101`,
    /// each with its own PCR. The PCR base advances by `step_90k` ticks
    /// (90 kHz units) per packet, so the head-to-tail PCR span is
    /// `(pcr_count - 1) × step_90k × 300` 27 MHz ticks — i.e.
    /// `(pcr_count - 1) × step_90k / 90_000` seconds.
    fn synth_pcr_span_ts(pcr_count: u64, step_90k: u64, base0: u64) -> Vec<u8> {
        let mut buf = pat_pmt_header();
        for i in 0..pcr_count {
            let base = base0 + i * step_90k;
            let cc = (i & 0x0F) as u8;
            buf.extend_from_slice(&ts_pes(
                0x0101,
                cc,
                Some((base, 0)),
                &pes_with_pts(base, b"frame"),
            ));
        }
        buf
    }

    #[test]
    fn duration_from_pcr_span_is_microseconds() {
        // 11 PCRs, 0.1 s apart → 1.0 s head-to-tail span.
        let bytes = synth_pcr_span_ts(11, 9_000, 1_000_000);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let dmx = MpegTsDemuxer::new(cursor).expect("open");
        // 10 × 9_000 ticks at 90 kHz = 90_000 / 90_000 = 1 s.
        assert_eq!(dmx.duration_micros(), Some(1_000_000));
        // The same figure lands on the stream in 90 kHz units (90_000).
        assert_eq!(dmx.streams()[0].duration, Some(90_000));
        // A successful duration probe must leave the streaming cursor
        // where the header scan stopped: the first demuxed packet is
        // still the very first PES, with PTS = base0.
        let mut dmx = dmx;
        let first = dmx.next_packet().expect("first PES after probe");
        assert_eq!(first.pts, Some(1_000_000));
    }

    #[test]
    fn duration_none_with_single_pcr() {
        // Only one PCR-bearing packet — no span to measure.
        let bytes = synth_pcr_span_ts(1, 9_000, 1_000_000);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let dmx = MpegTsDemuxer::new(cursor).expect("open");
        assert_eq!(dmx.duration_micros(), None);
        assert_eq!(dmx.streams()[0].duration, None);
    }

    #[test]
    fn seek_lands_on_pcr_at_or_before_target() {
        // 21 PCRs, 0.1 s (9_000 tick) apart, starting at base 1_000_000.
        // Bases: 1_000_000, 1_009_000, … 1_180_000.
        let bytes = synth_pcr_span_ts(21, 9_000, 1_000_000);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // Target lands between PCR #5 (1_045_000) and #6 (1_054_000):
        // seek must land on the one at-or-before → 1_045_000.
        let landed = dmx.seek_to(0, 1_050_000).expect("seek");
        assert_eq!(landed, 1_045_000);
        // The next demuxed PES is the one whose PTS == the landed PCR.
        let pkt = dmx.next_packet().expect("PES after seek");
        assert_eq!(pkt.pts, Some(1_045_000));
    }

    #[test]
    fn seek_clamps_before_first_and_after_last_pcr() {
        let bytes = synth_pcr_span_ts(11, 9_000, 2_000_000);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // Target before the head → first PCR (2_000_000).
        let landed = dmx.seek_to(0, 0).expect("seek-head");
        assert_eq!(landed, 2_000_000);
        let pkt = dmx.next_packet().expect("first PES");
        assert_eq!(pkt.pts, Some(2_000_000));

        // Target past the tail → last PCR (2_090_000).
        let landed = dmx.seek_to(0, i64::MAX).expect("seek-tail");
        assert_eq!(landed, 2_090_000);
        let pkt = dmx.next_packet().expect("last PES");
        assert_eq!(pkt.pts, Some(2_090_000));
    }

    #[test]
    fn seek_is_repeatable_and_lands_exactly_on_a_pcr() {
        let bytes = synth_pcr_span_ts(11, 9_000, 0);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // Seek to each exact PCR base; expect to land precisely on it
        // and read it back, twice, to prove the search resets cleanly.
        for &base in &[18_000i64, 45_000, 72_000, 9_000, 90_000] {
            let landed = dmx.seek_to(0, base).expect("seek");
            assert_eq!(landed, base, "seek to {base} landed on {landed}");
            let pkt = dmx.next_packet().expect("PES");
            assert_eq!(pkt.pts, Some(base));
        }
    }

    /// A null-PID (0x1FFF) padding packet — present in real streams
    /// between PCR-bearing ES packets. The duration / seek probes must
    /// skip these (they carry no PCR) without losing alignment.
    fn ts_null_packet(cc: u8) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        // PID = 0x1FFF (null), no PUSI.
        pkt[1] = 0x1F;
        pkt[2] = 0xFF;
        pkt[3] = 0b0001_0000 | (cc & 0x0F); // payload-only
        pkt
    }

    #[test]
    fn duration_and_seek_skip_interleaved_null_packets() {
        // Build 6 PCR-bearing PES packets 0.5 s (45_000 tick) apart,
        // each followed by two null-PID padding packets — so PCRs are
        // sparse (1 in 3 packets). Head-to-tail span = 5 × 0.5 s = 2.5 s.
        let mut buf = pat_pmt_header();
        for i in 0..6u64 {
            let base = 3_000_000 + i * 45_000;
            buf.extend_from_slice(&ts_pes(
                0x0101,
                (i & 0x0F) as u8,
                Some((base, 0)),
                &pes_with_pts(base, b"f"),
            ));
            buf.extend_from_slice(&ts_null_packet(i as u8));
            buf.extend_from_slice(&ts_null_packet(i as u8));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // 5 × 45_000 ticks @ 90 kHz = 225_000 / 90_000 = 2.5 s.
        assert_eq!(dmx.duration_micros(), Some(2_500_000));

        // Seek between PCR #2 (3_090_000) and #3 (3_135_000) → land on #2.
        let landed = dmx.seek_to(0, 3_100_000).expect("seek");
        assert_eq!(landed, 3_090_000);
        let pkt = dmx.next_packet().expect("PES after seek over nulls");
        assert_eq!(pkt.pts, Some(3_090_000));
    }

    #[test]
    fn seek_unsupported_without_two_pcrs() {
        // Single PCR → no bracket → seeking is Unsupported.
        let bytes = synth_pcr_span_ts(1, 9_000, 1_000_000);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        assert!(matches!(
            dmx.seek_to(0, 500_000),
            Err(CoreError::Unsupported(_))
        ));
    }

    #[test]
    fn seek_crosses_2pow33_wrap_on_extended_timeline() {
        // 21 PCR-bearing PES packets 9_000 ticks (0.1 s) apart whose
        // bases start 45_000 ticks below the 2^33 wrap — the PCR (and
        // PTS) ring wraps between packets #4 and #5. The synth helpers
        // mask to 33 bits, so the wire carries genuine wrapped values.
        let m = crate::TIMESTAMP_MODULUS_90KHZ;
        let base0 = m - 45_000;
        let bytes = synth_pcr_span_ts(21, 9_000, base0);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // Duration spans the wrap: 20 × 9_000 ticks = 2.0 s.
        assert_eq!(dmx.duration_micros(), Some(2_000_000));

        // Seek PAST the wrap on the extended axis. Extended bases run
        // …, m − 9_000, m, m + 9_000, m + 18_000, m + 27_000, …; the
        // last at or before m + 20_000 is m + 18_000.
        let landed = dmx.seek_to(0, (m + 20_000) as i64).expect("seek");
        assert_eq!(landed, (m + 18_000) as i64);
        // The post-seek PES carries raw PTS 18_000 on the wire; the
        // seeded trackers must re-enter epoch 1, not re-anchor at the
        // small raw value.
        let pkt = dmx.next_packet().expect("PES after wrap seek");
        assert_eq!(pkt.pts, Some((m + 18_000) as i64));

        // And BACK before the wrap: extended target m − 30_000 lands on
        // m − 36_000 (raw base 2^33 − 36_000, epoch 0).
        let landed = dmx.seek_to(0, (m - 30_000) as i64).expect("seek back");
        assert_eq!(landed, (m - 36_000) as i64);
        let pkt = dmx.next_packet().expect("PES after backward seek");
        assert_eq!(pkt.pts, Some((m - 36_000) as i64));

        // Forward progress from a post-wrap landing stays monotonic on
        // the extended axis across further reads.
        let landed = dmx.seek_to(0, (m - 4_000) as i64).expect("pre-wrap seek");
        assert_eq!(landed, (m - 9_000) as i64);
        let a = dmx.next_packet().expect("last pre-wrap PES");
        let b = dmx.next_packet().expect("first post-wrap PES");
        assert_eq!(a.pts, Some((m - 9_000) as i64));
        assert_eq!(b.pts, Some(m as i64), "wrap crossed while streaming");
    }

    #[test]
    fn seek_clamps_on_wrapped_tail_anchor() {
        // Head base sits 9_000 ticks below the wrap, tail extends past
        // it: clamping past-the-end targets must use the EXTENDED tail
        // time, not its small raw base.
        let m = crate::TIMESTAMP_MODULUS_90KHZ;
        let bytes = synth_pcr_span_ts(6, 9_000, m - 9_000);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        // Extended tail = (m − 9_000) + 5 × 9_000 = m + 36_000.
        let landed = dmx.seek_to(0, i64::MAX).expect("clamp to tail");
        assert_eq!(landed, (m + 36_000) as i64);
        let pkt = dmx.next_packet().expect("tail PES");
        assert_eq!(pkt.pts, Some((m + 36_000) as i64));
    }

    /// A TS packet on `pid` carrying a PES payload with full control
    /// over the adaptation field: optional PCR and/or the §2.4.3.5
    /// `random_access_indicator`. PUSI is a parameter so indicator
    /// carrier packets (no PES start) can be built too.
    fn ts_pes_ex(
        pid: u16,
        cc: u8,
        pusi: bool,
        pcr: Option<(u64, u16)>,
        rai: bool,
        pes: &[u8],
    ) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = (if pusi { 0b0100_0000 } else { 0 }) | ((pid >> 8) as u8 & 0x1F);
        pkt[2] = pid as u8;
        let mut off = 4;
        if pcr.is_some() || rai {
            pkt[3] = 0b0011_0000 | (cc & 0x0F); // AF + payload
            let af_flags =
                (if rai { 0b0100_0000 } else { 0 }) | (if pcr.is_some() { 0b0001_0000 } else { 0 });
            if let Some((base, ext)) = pcr {
                pkt[4] = 7; // flags(1) + PCR(6)
                pkt[5] = af_flags;
                pkt[6..12].copy_from_slice(&encode_pcr(base, ext));
                off = 12;
            } else {
                pkt[4] = 1; // flags only
                pkt[5] = af_flags;
                off = 6;
            }
        } else {
            pkt[3] = 0b0001_0000 | (cc & 0x0F); // payload only
        }
        let take = (TS_PACKET_LEN - off).min(pes.len());
        pkt[off..off + take].copy_from_slice(&pes[..take]);
        for b in &mut pkt[off + take..] {
            *b = 0xFF;
        }
        pkt
    }

    /// A PES packet body like [`pes_with_pts`] but with the §2.4.3.7
    /// `data_alignment_indicator` set in flags1.
    fn pes_with_pts_aligned(pts: u64, payload: &[u8]) -> Vec<u8> {
        let mut pes = pes_with_pts(pts, payload);
        pes[6] |= 0b0000_0100;
        pes
    }

    /// Single-program AVC stream on PID 0x101 (also the PCR PID):
    /// `count` PES packets `step` ticks apart starting at `base0`,
    /// every packet carrying a PCR, with the `random_access_indicator`
    /// on packets whose index is a multiple of `gop`.
    fn synth_rai_gop_ts(count: u64, step: u64, base0: u64, gop: u64) -> Vec<u8> {
        let mut buf = pat_pmt_header();
        for i in 0..count {
            let t = base0 + i * step;
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                (i & 0x0F) as u8,
                true,
                Some((t, 0)),
                i % gop == 0,
                &pes_with_pts(t, b"frame"),
            ));
        }
        buf
    }

    #[test]
    fn seek_to_lands_on_random_access_point_before_target() {
        // 60 frames 3_000 ticks apart, keyframe (RAI) every 10:
        // keyframe PTS = 0, 30_000, 60_000, 90_000, 120_000, 150_000.
        let bytes = synth_rai_gop_ts(60, 3_000, 0, 10);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // Target mid-GOP: frame 47 (141_000) → keyframe at 120_000,
        // NOT the PCR right before the target (which would be 141_000).
        let landed = dmx.seek_to(0, 141_000).expect("seek");
        assert_eq!(landed, 120_000);
        let pkt = dmx.next_packet().expect("PES after seek");
        assert_eq!(pkt.pts, Some(120_000));
        assert!(
            pkt.flags.keyframe,
            "landing PES must re-derive the keyframe flag from the indicator"
        );

        // Exactly on a keyframe stays on it.
        let landed = dmx.seek_to(0, 90_000).expect("seek exact");
        assert_eq!(landed, 90_000);
        assert_eq!(dmx.next_packet().expect("kf").pts, Some(90_000));
    }

    #[test]
    fn seek_to_backs_off_across_long_gop() {
        // 120 frames 3_000 ticks apart; the ONLY keyframes sit at
        // frame 0 and frame 10 (t = 30_000). A target near the tail
        // (frame 115, t = 345_000) is ~3.5 s past the last keyframe,
        // so the first windows (PCR landing, −1 s, −2 s) hold no
        // access point and the search must widen back to find it.
        let bytes = synth_rai_gop_ts(120, 3_000, 0, 110);
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        let landed = dmx.seek_to(0, 345_000).expect("seek");
        assert_eq!(landed, 330_000, "keyframes at 0 and 330_000 (110×3_000)");
        let pkt = dmx.next_packet().expect("PES");
        assert_eq!(pkt.pts, Some(330_000));
        assert!(pkt.flags.keyframe);
    }

    #[test]
    fn seek_to_clamps_up_to_first_access_point() {
        // Keyframes only from frame 10 (t = 130_000) on; a target
        // before every access point clamps UP to the first one.
        let mut buf = pat_pmt_header();
        for i in 0..30u64 {
            let t = 100_000 + i * 3_000;
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                (i & 0x0F) as u8,
                true,
                Some((t, 0)),
                i >= 10 && (i - 10) % 10 == 0,
                &pes_with_pts(t, b"frame"),
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        let landed = dmx.seek_to(0, 103_000).expect("seek");
        assert_eq!(landed, 130_000, "first indicator-announced PES");
        let pkt = dmx.next_packet().expect("PES");
        assert_eq!(pkt.pts, Some(130_000));
        assert!(pkt.flags.keyframe);
    }

    #[test]
    fn seek_to_uses_data_alignment_tier_when_no_indicator() {
        // No random_access_indicator anywhere; every 5th PES sets the
        // §2.4.3.7 data_alignment_indicator. Aligned PES at t = 0,
        // 15_000, 30_000, 45_000, …
        let mut buf = pat_pmt_header();
        for i in 0..40u64 {
            let t = i * 3_000;
            let pes = if i % 5 == 0 {
                pes_with_pts_aligned(t, b"frame")
            } else {
                pes_with_pts(t, b"frame")
            };
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                (i & 0x0F) as u8,
                true,
                Some((t, 0)),
                false,
                &pes,
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        let landed = dmx.seek_to(0, 52_000).expect("seek");
        assert_eq!(landed, 45_000, "last data-aligned PES at or before 52_000");
        let pkt = dmx.next_packet().expect("PES");
        assert_eq!(pkt.pts, Some(45_000));
        // The §2.4.3.5 keyframe promise was never made — the emitted
        // packet must NOT claim one.
        assert!(!pkt.flags.keyframe);
        // seek_to_random_access, the strict §2.4.3.5 surface, refuses.
        assert!(matches!(
            dmx.seek_to_random_access(Some(0), 52_000),
            Err(CoreError::Unsupported(_))
        ));
    }

    #[test]
    fn seek_to_prefers_indicator_over_data_alignment() {
        // Every PES is data-aligned; every 10th ALSO carries the
        // indicator. The indicator tier must win even though a nearer
        // data-aligned point exists.
        let mut buf = pat_pmt_header();
        for i in 0..40u64 {
            let t = i * 3_000;
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                (i & 0x0F) as u8,
                true,
                Some((t, 0)),
                i % 10 == 0,
                &pes_with_pts_aligned(t, b"frame"),
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        let landed = dmx.seek_to(0, 57_000).expect("seek");
        assert_eq!(
            landed, 30_000,
            "indicator keyframe at 30_000 beats aligned PES at 57_000"
        );
        assert!(dmx.next_packet().expect("PES").flags.keyframe);
    }

    #[test]
    fn seek_to_anchors_on_indicator_carrier_packet() {
        // The indicator rides a payload-less carrier packet (PUSI=0,
        // adaptation-only); the announced PES starts one packet later.
        // The landing must anchor on the CARRIER so the reassembler
        // re-derives the keyframe flag.
        let mut buf = pat_pmt_header();
        for i in 0..20u64 {
            let t = 50_000 + i * 3_000;
            if i % 10 == 0 {
                // Carrier: RAI + PCR, no payload-unit start, no PES.
                buf.extend_from_slice(&ts_pes_ex(
                    0x0101,
                    (i & 0x0F) as u8,
                    false,
                    Some((t, 0)),
                    true,
                    &[],
                ));
            }
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                ((i + 1) & 0x0F) as u8,
                true,
                if i % 10 == 0 { None } else { Some((t, 0)) },
                false,
                &pes_with_pts(t, b"frame"),
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        let landed = dmx.seek_to(0, 95_000).expect("seek");
        assert_eq!(landed, 80_000, "keyframes at 50_000 and 80_000");
        let pkt = dmx.next_packet().expect("PES");
        assert_eq!(pkt.pts, Some(80_000));
        assert!(pkt.flags.keyframe, "indicator folded from carrier packet");
    }

    #[test]
    fn access_point_index_tiers_and_extended_pts() {
        // Index contents: kinds, per-tier counts, and extended PTS
        // across a 2^33 wrap.
        let m = crate::TIMESTAMP_MODULUS_90KHZ;
        let base0 = m - 15_000;
        let mut buf = pat_pmt_header();
        for i in 0..12u64 {
            let t = (base0 + i * 3_000) & (m - 1); // wraps at i == 5
            let rai = i % 6 == 0;
            let pes = if i % 3 == 0 && !rai {
                pes_with_pts_aligned(t, b"f")
            } else {
                pes_with_pts(t, b"f")
            };
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                (i & 0x0F) as u8,
                true,
                Some((t, 0)),
                rai,
                &pes,
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        let index: Vec<RandomAccessPoint> = dmx.random_access_points().expect("index").to_vec();
        let rai: Vec<_> = index
            .iter()
            .filter(|r| r.kind == AccessPointKind::RandomAccessIndicator)
            .collect();
        let dai: Vec<_> = index
            .iter()
            .filter(|r| r.kind == AccessPointKind::DataAligned)
            .collect();
        // RAI at i = 0, 6; data-aligned at i = 3, 9 (i % 3 == 0 minus
        // the indicator ones).
        assert_eq!(rai.len(), 2);
        assert_eq!(dai.len(), 2);
        assert_eq!(rai[0].pts_90k, Some(base0));
        // i = 6 crossed the wrap: extended, not the small raw value.
        assert_eq!(rai[1].pts_90k, Some(base0 + 18_000));
        assert!(rai[1].pts_90k.unwrap() > m, "extended past the wrap");
        assert_eq!(dai[0].pts_90k, Some(base0 + 9_000));
        assert_eq!(dai[1].pts_90k, Some(base0 + 27_000));

        // And the access-point seek works across the wrap end-to-end.
        let landed = dmx.seek_to(0, (base0 + 20_000) as i64).expect("seek");
        assert_eq!(landed, (base0 + 18_000) as i64);
        let pkt = dmx.next_packet().expect("PES");
        assert_eq!(pkt.pts, Some((base0 + 18_000) as i64));
        assert!(pkt.flags.keyframe);
    }

    #[test]
    fn seek_to_sparse_pcr_still_lands_on_access_point() {
        // PCR only on every 8th packet (sparse); keyframes every 4th.
        // The window scan from the (distant) PCR landing must still
        // find the exact keyframe at or before the target.
        let mut buf = pat_pmt_header();
        for i in 0..64u64 {
            let t = i * 3_000;
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                (i & 0x0F) as u8,
                true,
                (i % 8 == 0).then_some((t, 0)),
                i % 4 == 0,
                &pes_with_pts(t, b"frame"),
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");
        for target in [50_000i64, 100_000, 150_000, 187_000] {
            let landed = dmx.seek_to(0, target).expect("seek");
            let expect = (target / 12_000) * 12_000; // keyframe grid
            assert_eq!(landed, expect, "target {target}");
            assert_eq!(dmx.next_packet().expect("PES").pts, Some(expect));
        }
    }

    #[test]
    fn pcr_fallback_landing_mid_pes_discards_partial_and_resumes_clean() {
        // Each PES spans exactly two TS packets: a PUSI start (184
        // payload bytes) and a continuation packet that carries the
        // PCR in its adaptation field (176 payload bytes). No RAI, no
        // data alignment → the seek degrades to the PCR landing, whose
        // packet sits MID-PES. The reposition must discard the partial
        // PES (continuity history is void) and emit the NEXT PES
        // cleanly.
        let mut buf = pat_pmt_header();
        let n = 12u64;
        for i in 0..n {
            let pts = 10_000 + i * 3_000;
            let pes = pes_with_pts(pts, &[0xB7u8; 346]); // 360 bytes total
            assert_eq!(pes.len(), 360);
            let cc0 = ((2 * i) & 0x0F) as u8;
            let cc1 = ((2 * i + 1) & 0x0F) as u8;
            buf.extend_from_slice(&ts_pes_ex(0x0101, cc0, true, None, false, &pes[..184]));
            // Continuation packet: AF(PCR) + the remaining 176 bytes.
            buf.extend_from_slice(&ts_pes_ex(
                0x0101,
                cc1,
                false,
                Some((pts, 0)),
                false,
                &pes[184..],
            ));
        }
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut dmx = MpegTsDemuxer::new(cursor).expect("open");

        // Target between PES #5 (25_000) and #6 (28_000): the last PCR
        // at or before it rides PES #5's continuation packet.
        let landed = dmx.seek_to(0, 26_500).expect("seek");
        assert_eq!(landed, 25_000, "PCR-granular landing");
        // The landing packet is the tail half of PES #5 — unusable.
        // The first emitted packet must be PES #6, intact.
        let pkt = dmx.next_packet().expect("clean PES after mid-PES landing");
        assert_eq!(pkt.pts, Some(28_000));
        assert_eq!(
            pkt.data.len(),
            346,
            "full reassembled payload, no tail bytes"
        );
        assert!(pkt.data.iter().all(|&b| b == 0xB7), "payload uncorrupted");
    }

    #[test]
    fn duration_handles_pcr_extension_in_span() {
        // Two PCRs 2.0 s apart with a non-zero extension on the tail to
        // confirm the 27 MHz composition (base × 300 + ext) is used.
        let mut buf = pat_pmt_header();
        buf.extend_from_slice(&ts_pes(
            0x0101,
            0,
            Some((5_000_000, 0)),
            &pes_with_pts(5_000_000, b"a"),
        ));
        buf.extend_from_slice(&ts_pes(
            0x0101,
            1,
            // +180_000 ticks (2.0 s) of base, +150 of extension.
            Some((5_180_000, 150)),
            &pes_with_pts(5_180_000, b"b"),
        ));
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let dmx = MpegTsDemuxer::new(cursor).expect("open");
        // span = 180_000 × 300 + 150 = 54_000_150 ticks.
        // micros = 54_000_150 × 1_000_000 / 27_000_000 = 2_000_005.
        assert_eq!(dmx.duration_micros(), Some(2_000_005));
    }
}
