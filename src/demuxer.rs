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
//!   spans, per §2.4.4. Every section of a multi-section PAT
//!   (`last_section_number > 0`) is collected; a PMT is one section
//!   per program by definition (§2.4.4.9).
//! * Damaged input. The streaming path resynchronises byte by byte,
//!   drops what does not parse, and keeps going; the PAT and the
//!   selected program's PMT are followed, so a mid-stream PID
//!   reassignment re-points the streams. See [`MpegTsDemuxer`] and
//!   [`TsDemuxStats`].
//! * Per-PID streams. Streams whose [`StreamType`] maps to an audio /
//!   video / subtitle [`CodecParameters`] surface as
//!   [`StreamInfo`]s the muxer can write; streams whose type we don't
//!   handle (interactive graphics, private data) are silently
//!   dropped — their PES packets never reach `next_packet`.
//!
//! ## Time base
//!
//! TS PTS / DTS are in 90 kHz units. Each [`StreamInfo`] uses
//! `TimeBase::new(1, 90_000)`; packet timestamps are the 33-bit wire
//! values unwrapped onto one 64-bit axis (§2.4.3.7), without
//! rescaling — downstream muxers do their own base conversion.

use std::collections::VecDeque;
use std::io::Seek;

use oxideav_core::{
    CodecId, CodecParameters, CodecResolver, Demuxer, Error as CoreError, MediaType, Packet,
    ReadSeek, Result as CoreResult, StreamInfo, TimeBase,
};

use crate::clock::NearestEpochUnwrap;
use crate::{
    PAT_PID, Pcr, PcrTracker, PesPacket, PesReassembler, ProgramAssociationTable, ProgramMapTable,
    PsiSectionAssembler, StreamType, TS_PACKET_LEN, TS_SYNC_BYTE, TsPacket,
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
#[non_exhaustive]
pub struct TsProgram {
    /// 16-bit program label, unique within the transport stream.
    pub program_number: u16,
    /// 13-bit PID of the TS packets carrying this program's PMT.
    pub pmt_pid: u16,
}

/// Counters of what the streaming path skipped or repaired. All are
/// zero on a clean stream; read them with [`MpegTsDemuxer::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TsDemuxStats {
    /// Bytes discarded while re-acquiring the packet grid after a bad
    /// sync byte (inserted / deleted bytes, garbage runs).
    pub resync_bytes: u64,
    /// Packets on the demuxed PIDs (and the `PCR_PID`) dropped because
    /// their adaptation field does not parse (e.g. an
    /// `adaptation_field_length` running past the packet).
    pub malformed_packets: u64,
    /// Packets dropped because `transport_error_indicator` was set.
    pub transport_errors: u64,
    /// §2.4.3.3 duplicate packets skipped on the demuxed PIDs.
    pub duplicate_packets: u64,
    /// Continuity-counter gaps seen on the demuxed PIDs (packets were
    /// lost; the PES packet in flight is flagged corrupt).
    pub continuity_errors: u64,
    /// PES packets dropped because their header does not parse.
    pub damaged_pes: u64,
    /// Payload packets on the demuxed PIDs whose
    /// `transport_scrambling_control` is not '00' (Table 2-4). Their
    /// payload is passed on as it is.
    pub scrambled_packets: u64,
    /// Times the selected program's map changed mid-stream — a new
    /// `program_map_PID` in the PAT, or a PMT assigning different
    /// elementary PIDs or a different `PCR_PID` — and the demuxer
    /// re-pointed its streams (see [`MpegTsDemuxer`]).
    pub program_map_changes: u64,
}

/// Bytes read from the input per block. Large enough that a plain
/// `std::fs::File` source costs one system call per several hundred
/// packets instead of one per packet.
const READ_BLOCK: usize = 128 << 10;

/// Consecutive packets whose sync bytes must line up for the resync
/// search to accept a candidate grid position (fewer only when the
/// input ends first).
const RESYNC_CONFIRM_PACKETS: usize = 3;

/// Block-buffered reader of physical packets with byte-granular
/// resynchronisation.
///
/// `position()` is the stream offset of the next unread byte; the
/// offsets handed out with each packet are true byte offsets even
/// after a resync skipped bytes. Out-of-band probes borrow the
/// underlying source through [`Self::raw`], which is safe at any
/// time: the next refill re-seeks to where the buffer ends.
struct PacketReader {
    input: Box<dyn ReadSeek>,
    layout: crate::packet::TsPacketLayout,
    buf: Box<[u8]>,
    /// Unread bytes are `buf[head..tail]`.
    head: usize,
    tail: usize,
    /// Stream offset of `buf[head]`.
    pos: u64,
    /// The source cursor sits at `pos + (tail - head)`.
    synced: bool,
    eof: bool,
    /// Bytes skipped by resynchronisation so far.
    resync_bytes: u64,
}

impl PacketReader {
    fn new(input: Box<dyn ReadSeek>, layout: crate::packet::TsPacketLayout) -> Self {
        Self {
            input,
            layout,
            buf: vec![0u8; READ_BLOCK].into_boxed_slice(),
            head: 0,
            tail: 0,
            pos: 0,
            synced: false,
            eof: false,
            resync_bytes: 0,
        }
    }

    /// Stream offset of the next unread byte.
    fn position(&self) -> u64 {
        self.pos
    }

    /// Continue reading at stream offset `pos`.
    fn seek(&mut self, pos: u64) {
        self.head = 0;
        self.tail = 0;
        self.pos = pos;
        self.synced = false;
        self.eof = false;
    }

    /// The underlying source, for an out-of-band probe that seeks and
    /// reads on its own. The streaming position is unaffected.
    fn raw(&mut self) -> &mut Box<dyn ReadSeek> {
        self.synced = false;
        &mut self.input
    }

    /// Buffer at least `need` unread bytes (fewer only at end of
    /// input); returns how many are available.
    fn fill(&mut self, need: usize) -> std::io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        debug_assert!(need <= self.buf.len());
        while self.tail - self.head < need && !self.eof {
            if self.head > 0 {
                self.buf.copy_within(self.head..self.tail, 0);
                self.tail -= self.head;
                self.head = 0;
            }
            if !self.synced {
                self.input
                    .seek(SeekFrom::Start(self.pos + self.tail as u64))?;
                self.synced = true;
            }
            match self.input.read(&mut self.buf[self.tail..]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.tail += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(self.tail - self.head)
    }

    fn consume(&mut self, n: usize) {
        self.head += n;
        self.pos += n as u64;
    }

    /// Read the next physical packet and return its stream offset and
    /// logical 188-byte window.
    ///
    /// `Ok(None)` is the end of the stream — including a trailing
    /// fragment shorter than one packet (a capture cut mid-packet) and
    /// a tail in which no packet grid can be found any more.
    ///
    /// On a sync-byte mismatch the reader searches forward **byte by
    /// byte** for a position where the sync byte recurs at the packet
    /// stride ([`RESYNC_CONFIRM_PACKETS`] packets, fewer only at the
    /// very end of the input), so inserted or deleted bytes shift the
    /// grid instead of ending the stream. One call examines at most
    /// [`RESYNC_PACKET_LIMIT`] packets' worth of bytes; past that it
    /// reports the corruption as an error, and the following call
    /// carries on from where the search stopped.
    fn next_packet(&mut self) -> CoreResult<Option<(u64, [u8; TS_PACKET_LEN])>> {
        let psize = self.layout.packet_size;
        let sync_at = self.layout.sync_offset;
        let have = self.fill(psize).map_err(CoreError::Io)?;
        if have < psize {
            self.consume(have);
            return Ok(None);
        }
        if self.buf[self.head + sync_at] != TS_SYNC_BYTE && !self.resync()? {
            return Ok(None);
        }
        let start = self.head + sync_at;
        let mut out = [0u8; TS_PACKET_LEN];
        out.copy_from_slice(&self.buf[start..start + TS_PACKET_LEN]);
        let offset = self.pos;
        self.consume(psize);
        Ok(Some((offset, out)))
    }

    /// Search forward for the packet grid. `Ok(true)` leaves a whole
    /// packet with a good sync byte at the head of the buffer;
    /// `Ok(false)` means the input ended first.
    fn resync(&mut self) -> CoreResult<bool> {
        let psize = self.layout.packet_size;
        let sync_at = self.layout.sync_offset;
        let bad_at = self.pos;
        let bad_byte = self.buf[self.head + sync_at];
        let limit = RESYNC_PACKET_LIMIT * psize;
        let mut skipped = 0usize;
        loop {
            let have = self
                .fill(RESYNC_CONFIRM_PACKETS * psize)
                .map_err(CoreError::Io)?;
            if have < psize {
                self.consume(have);
                self.resync_bytes += have as u64;
                return Ok(false);
            }
            let window = &self.buf[self.head..self.tail];
            // Candidates that can be fully confirmed inside the window;
            // at end of input the confirmation shrinks to what is left.
            let full = window.len() / psize >= RESYNC_CONFIRM_PACKETS;
            let last_candidate = if full {
                window.len() - RESYNC_CONFIRM_PACKETS * psize
            } else {
                window.len() - psize
            };
            let mut found = None;
            let mut c = 0usize;
            while c <= last_candidate && skipped + c <= limit {
                let confirmed = (0..RESYNC_CONFIRM_PACKETS).all(|k| {
                    window
                        .get(c + k * psize + sync_at)
                        .is_none_or(|&b| b == TS_SYNC_BYTE)
                });
                if confirmed {
                    found = Some(c);
                    break;
                }
                c += 1;
            }
            let advance = found.unwrap_or(c);
            self.consume(advance);
            self.resync_bytes += advance as u64;
            skipped += advance;
            if found.is_some() {
                return Ok(true);
            }
            if skipped > limit {
                return Err(CoreError::invalid(format!(
                    "mpegts: bad sync byte 0x{bad_byte:02X} at offset {bad_at} (packet {}), \
                     no packet grid within {RESYNC_PACKET_LIMIT} {psize}-byte packets",
                    bad_at / psize as u64,
                )));
            }
            if !full {
                // End of input and nothing lined up in what was left.
                let rest = self.tail - self.head;
                self.consume(rest);
                self.resync_bytes += rest as u64;
                return Ok(false);
            }
        }
    }
}

/// Shifts a source so that stream offset 0 is the first whole packet:
/// a capture that begins mid-packet (or behind leading bytes that are
/// not transport packets) then presents the same aligned grid as any
/// other, which is what the byte-offset arithmetic of the duration
/// probe, the PCR bisection and the access-point index rely on.
struct OffsetInput {
    inner: Box<dyn ReadSeek>,
    base: u64,
}

impl std::io::Read for OffsetInput {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl std::io::Seek for OffsetInput {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::SeekFrom;
        let abs = match pos {
            SeekFrom::Start(p) => self
                .inner
                .seek(SeekFrom::Start(p.saturating_add(self.base)))?,
            other => self.inner.seek(other)?,
        };
        if abs < self.base {
            // Landed in the skipped prefix: clamp to the logical start.
            self.inner.seek(SeekFrom::Start(self.base))?;
            return Ok(0);
        }
        Ok(abs - self.base)
    }
}

/// Fixed-grid block scanner for the out-of-band probes (duration, PCR
/// bisection, access-point index): walks whole packets from a
/// packet-aligned offset, reading the source a block at a time.
struct GridScan<'a> {
    input: &'a mut Box<dyn ReadSeek>,
    layout: crate::packet::TsPacketLayout,
    block: Vec<u8>,
    /// Valid bytes in `block` and the read cursor into them.
    have: usize,
    next: usize,
    /// Stream offset of `block[next]`.
    off: u64,
    /// Exclusive end offset of the scan.
    end: u64,
    done: bool,
}

impl<'a> GridScan<'a> {
    /// Packets per block read.
    const BLOCK_PACKETS: usize = 256;

    fn new(
        input: &'a mut Box<dyn ReadSeek>,
        layout: crate::packet::TsPacketLayout,
        from: u64,
        end: u64,
    ) -> std::io::Result<Self> {
        use std::io::{Seek, SeekFrom};
        input.seek(SeekFrom::Start(from))?;
        Ok(Self {
            input,
            layout,
            block: Vec::new(),
            have: 0,
            next: 0,
            off: from,
            end,
            done: false,
        })
    }

    /// Stream offset and logical 188-byte window of the next whole
    /// packet before `end`; `None` when the range or the input is
    /// exhausted.
    fn next_packet(&mut self) -> Option<(u64, &[u8])> {
        use std::io::Read;
        let psize = self.layout.packet_size;
        if self.done || self.off + psize as u64 > self.end {
            return None;
        }
        if self.have - self.next < psize {
            let left = (self.end - self.off) / psize as u64;
            let want = (left.min(Self::BLOCK_PACKETS as u64) as usize) * psize;
            self.block.resize(want, 0);
            let mut filled = 0usize;
            while filled < want {
                match self.input.read(&mut self.block[filled..want]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            self.have = filled - filled % psize;
            self.next = 0;
            if self.have == 0 {
                self.done = true;
                return None;
            }
        }
        let at = self.next;
        let off = self.off;
        self.next += psize;
        self.off += psize as u64;
        Some((off, self.layout.window(&self.block[at..at + psize])))
    }
}

/// Number of PID values (13 bits).
const PID_SPACE: usize = 1 << 13;

/// Ceiling on the bytes all in-flight PES packets of one demuxer may
/// hold together; each PID gets an equal share of it, capped at
/// [`crate::pes::DEFAULT_MAX_PES_BYTES`].
const MAX_INFLIGHT_BYTES: usize = 256 << 20;

/// Per-PID demux state of one elementary stream. The slot index is the
/// stream index.
struct PidSlot {
    pid: u16,
    /// `false` once a later PMT no longer lists a stream of this
    /// slot's codec: no PID routes here any more.
    mapped: bool,
    /// Codec the PMT entry names (before any refinement from the
    /// elementary stream) — what a later PMT's entries are matched on.
    pmt_codec: CodecId,
    reassembler: PesReassembler,
    /// 33-bit PTS / DTS unwrappers (§2.4.3.7) onto one monotonic
    /// 64-bit timeline; reorder-tolerant.
    pts: NearestEpochUnwrap,
    dts: NearestEpochUnwrap,
    /// Audio access-unit splitter for streams whose framing is staged
    /// (AC-3 / E-AC-3, MPEG-1/2 audio, AAC ADTS): a PES payload
    /// carrying several syncframes leaves as one packet per frame
    /// (§2.4.3.7 / §2.7.5 timestamp interpolation, see
    /// [`crate::audio_frame`]).
    splitter: Option<crate::AudioFrameSplitter>,
    /// `continuity_counter` of the last payload-carrying packet.
    last_cc: Option<u8>,
    /// The packet carrying `last_cc` has already been seen twice.
    duplicate_seen: bool,
    /// Fingerprint of the payload that carried `last_cc`.
    last_payload: crate::packet::PayloadMark,
    /// Packets were lost inside the PES packet in flight.
    damaged: bool,
}

impl PidSlot {
    /// Void everything that depends on stream position.
    fn rehome(&mut self, time_hint: Option<u64>) {
        self.reassembler.reset();
        if let Some(s) = &mut self.splitter {
            s.reset();
        }
        self.last_cc = None;
        self.duplicate_seen = false;
        self.damaged = false;
        for t in [&mut self.pts, &mut self.dts] {
            match time_hint {
                Some(h) => t.seed(h),
                None => t.reset(),
            }
        }
    }
}

/// MPEG-TS demuxer state — reads physical packets from a `ReadSeek` a
/// block at a time, reassembles PES per PID, hands one [`Packet`] per
/// PES (or per audio access unit) back through `next_packet`.
///
/// ## Robustness
///
/// The streaming path does not give up on damaged input: bytes that
/// break the packet grid are skipped by a byte-granular resync,
/// packets that do not parse or carry `transport_error_indicator` are
/// dropped, duplicate packets are skipped, a continuity-counter gap
/// flags the affected [`Packet`] `corrupt`,
/// and a PES packet whose header does not parse is dropped on its own.
/// [`Self::stats`] counts each of these. Memory is bounded whatever the
/// input: every PID's in-flight PES packet has a ceiling (an unbounded
/// PES packet that reaches it is handed out in pieces).
///
/// ## Program-map changes
///
/// The PAT and the selected program's PMT are followed while
/// streaming. When the PAT moves the program to another
/// `program_map_PID`, or the PMT assigns different elementary PIDs or a
/// different `PCR_PID` (spliced captures, a remultiplexed service), each
/// stream is re-pointed at the first not-yet-taken PMT entry of its
/// codec, in order; the PES packet in flight on the old PID is handed
/// out first. The stream list itself is fixed at open: a stream whose
/// codec the new PMT no longer lists simply stops, and entries beyond
/// the opened set are not picked up. [`TsDemuxStats::program_map_changes`]
/// counts the changes.
pub struct MpegTsDemuxer {
    reader: PacketReader,
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
    /// `program_map_PID` of the selected program, as the latest PAT
    /// gives it.
    pmt_pid: u16,
    /// Section assemblers following the PAT and the program's PMT
    /// while streaming.
    pat_watch: PsiSectionAssembler,
    pmt_watch: PsiSectionAssembler,
    /// `(stream_type, elementary_PID)` of every entry of the PMT in
    /// effect — what a later PMT is compared against.
    pmt_entries: Vec<(u8, u16)>,
    /// 27 MHz clock recovery on the selected program's `PCR_PID`. Fed
    /// every adaptation field that carries a PCR; supplies the absolute
    /// clock anchor a remux uses to align the PES timeline.
    pcr_tracker: PcrTracker,
    streams: Vec<StreamInfo>,
    /// Direct PID table: `pid_slot[pid]` is the index into `slots`
    /// plus one, or 0 for a PID this demuxer does not follow.
    pid_slot: Box<[u16]>,
    /// One entry per elementary stream, in `streams` order.
    slots: Vec<PidSlot>,
    /// Already-reassembled packets waiting to be handed out.
    pending: VecDeque<Packet>,
    /// `true` once the input ran dry and every reassembler has been
    /// flushed.
    eof_reached: bool,
    /// Bytes ahead of the first whole packet in the source (a capture
    /// cut mid-packet); every offset this demuxer reports is a true
    /// source offset, i.e. includes it.
    base_offset: u64,
    stats: TsDemuxStats,
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
#[non_exhaustive]
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
#[non_exhaustive]
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
        // trailer-appended packets) and where the first whole packet
        // sits, from the head of the stream. Everything downstream
        // works on the logical 188-byte window; the framing bytes are
        // stripped at the read layer.
        let (layout, base_offset) = {
            use std::io::Read;
            let mut head = vec![0u8; LAYOUT_PROBE_BYTES];
            let mut filled = 0usize;
            input
                .seek(std::io::SeekFrom::Start(0))
                .map_err(CoreError::Io)?;
            while filled < head.len() {
                match input.read(&mut head[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(CoreError::Io(e)),
                }
            }
            // A head too corrupt (or short) to classify falls back to
            // the plain layout at offset 0; the streaming resync path
            // takes over from there.
            crate::packet::locate_packet_layout(&head[..filled])
                .map(|(layout, at)| (layout, at as u64))
                .unwrap_or((crate::packet::TsPacketLayout::STANDARD, 0))
        };
        let input: Box<dyn ReadSeek> = if base_offset == 0 {
            input
        } else {
            Box::new(OffsetInput {
                inner: input,
                base: base_offset,
            })
        };
        let mut reader = PacketReader::new(input, layout);

        // Step 1: scan for the PAT, reassembling its sections across
        // as many same-PID TS packets as the spec permits per §2.4.4.
        //
        // We collect *every* non-network program the PAT lists so a
        // caller can enumerate them and re-open on a chosen one
        // (§2.4.4.5: `program_number == 0` names the network PID, not a
        // program). A PAT may span several sections
        // (`last_section_number > 0`); collection runs until each has
        // been seen once, or gives up [`PAT_COMPLETION_BYTES`] past
        // the first one. A table flagged `current_next_indicator = 0`
        // is not yet applicable and only serves when the stream offers
        // nothing else. Packets and sections that do not parse are
        // skipped.
        // `(section_number, program)` so the final list is in PAT
        // order whichever section the stream happened to show first.
        let mut listed: Vec<(u8, TsProgram)> = Vec::new();
        let mut upcoming: Vec<(u8, TsProgram)> = Vec::new();
        let mut sections_seen = [false; 256];
        let mut sections_missing: Option<usize> = None;
        let mut first_pat_at: Option<u64> = None;
        let mut pat_assembler = PsiSectionAssembler::new();
        let add = |list: &mut Vec<(u8, TsProgram)>, pat: &ProgramAssociationTable| {
            for &(program_number, pmt_pid) in &pat.programs {
                if program_number != 0
                    && !list.iter().any(|(_, p)| p.program_number == program_number)
                {
                    list.push((
                        pat.section_number,
                        TsProgram {
                            program_number,
                            pmt_pid,
                        },
                    ));
                }
            }
        };
        while let Some((offset, raw)) = reader.next_packet()? {
            if let Some(first) = first_pat_at
                && offset - first > PAT_COMPLETION_BYTES
            {
                break;
            }
            let Ok(pkt) = TsPacket::parse(&raw) else {
                continue;
            };
            if pkt.pid != PAT_PID || pkt.payload.is_empty() || pkt.transport_error {
                continue;
            }
            let Ok(sections) =
                pat_assembler.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
            else {
                continue;
            };
            for section in &sections {
                let Ok(pat) = ProgramAssociationTable::parse(section) else {
                    continue;
                };
                if !pat.current_next_indicator {
                    add(&mut upcoming, &pat);
                    continue;
                }
                first_pat_at.get_or_insert(offset);
                let missing = sections_missing.get_or_insert(pat.last_section_number as usize + 1);
                if !std::mem::replace(&mut sections_seen[pat.section_number as usize], true)
                    && pat.section_number <= pat.last_section_number
                {
                    *missing -= 1;
                }
                add(&mut listed, &pat);
            }
            if sections_missing == Some(0) {
                break;
            }
        }
        if listed.is_empty() {
            listed = upcoming;
        }
        listed.sort_by_key(|&(section, _)| section);
        let programs: Vec<TsProgram> = listed.into_iter().map(|(_, p)| p).collect();
        if programs.is_empty() {
            return Err(CoreError::invalid(if first_pat_at.is_some() {
                "mpegts: PAT carried no program with a PMT PID"
            } else {
                "mpegts: stream ended before a PAT was seen"
            }));
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
        //
        // Several programs may share one `program_map_PID`; the section
        // for this program is the one whose `program_number` matches
        // (§2.4.4.9) and that is currently applicable. A section that
        // fails either test is kept as a fallback for streams that
        // carry nothing better within [`PMT_FALLBACK_BYTES`].
        let mut pmt_assembler = PsiSectionAssembler::new();
        let mut fallback: Option<(ProgramMapTable, u64, u64)> = None;
        let mut chosen: Option<ProgramMapTable> = None;
        while let Some((offset, raw)) = reader.next_packet()? {
            if let Some((_, seen_at, _)) = &fallback
                && offset - seen_at > PMT_FALLBACK_BYTES
            {
                break;
            }
            let Ok(pkt) = TsPacket::parse(&raw) else {
                continue;
            };
            if pkt.pid != pmt_pid || pkt.payload.is_empty() || pkt.transport_error {
                continue;
            }
            let Ok(sections) =
                pmt_assembler.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
            else {
                continue;
            };
            for section in &sections {
                let Ok(pmt) = ProgramMapTable::parse(section) else {
                    continue;
                };
                if pmt.program_number == selected_program && pmt.current_next_indicator {
                    chosen = Some(pmt);
                    break;
                }
                if fallback.is_none() {
                    fallback = Some((pmt, offset, reader.position()));
                }
            }
            if chosen.is_some() {
                break;
            }
        }
        let pmt = match (chosen, fallback) {
            (Some(pmt), _) => pmt,
            (None, Some((pmt, _, resume))) => {
                // Streaming resumes right behind the fallback section.
                reader.seek(resume);
                pmt
            }
            (None, None) => {
                return Err(CoreError::invalid(
                    "mpegts: stream ended before the PMT was seen",
                ));
            }
        };

        // Step 3: map PMT streams → CodecParameters → StreamInfo. PIDs
        // whose stream_type we don't have a CodecId for are silently
        // dropped (we won't open a reassembler for them and their PES
        // bytes never reach the caller).
        //
        // A private-data PES entry (stream_type 0x06) that no descriptor
        // identifies is examined once: when its payloads frame as one
        // of the audio syntaxes this crate splits, it is that codec.
        let undescribed: Vec<u16> = pmt
            .streams
            .iter()
            .filter(|e| e.stream_type == 0x06 && pmt_entry_codec(e).is_none())
            .map(|e| e.elementary_pid & 0x1FFF)
            .collect();
        let sniffed = sniff_private_audio(&mut reader, &undescribed);
        let tb = TimeBase::new(1, 90_000);
        let mut streams: Vec<StreamInfo> = Vec::new();
        let mut pid_slot = vec![0u16; PID_SPACE].into_boxed_slice();
        let mut slots: Vec<PidSlot> = Vec::new();
        for pmt_stream in &pmt.streams {
            let by_payload = sniffed
                .iter()
                .find(|(pid, _)| *pid == pmt_stream.elementary_pid & 0x1FFF)
                .map(|&(_, id)| CodecParameters::audio(CodecId::new(id)));
            let mut params = match pmt_entry_codec(pmt_stream).or(by_payload) {
                Some(p) => p,
                None => continue,
            };
            let pmt_codec = params.codec_id.clone();
            apply_descriptor_params(&mut params, pmt_stream);
            let syntax = if StreamType::from_raw(pmt_stream.stream_type) == StreamType::AacAdts {
                Some(crate::AudioSyntax::AacAdts)
            } else {
                crate::es_params::audio_syntax_for(params.codec_id.as_str())
            };
            // Lift the ES_info ISO_639_language_descriptor (tag 0x0A,
            // §2.6.18) into the per-stream language tag so a demux →
            // remux path keeps each track's audio/subtitle language.
            // The first language entry wins (multi-language audio is
            // rare and a single tag is what the core surface holds).
            if params.language.is_none()
                && let Some(code) = first_iso639_language(pmt_stream)
            {
                params = params.with_language(code);
            }
            let idx = streams.len() as u32;
            streams.push(StreamInfo {
                index: idx,
                time_base: tb,
                duration: None,
                start_time: None,
                params,
            });
            let pid = pmt_stream.elementary_pid & 0x1FFF;
            // A PID listed twice keeps its last entry, as a map would.
            pid_slot[pid as usize] = idx as u16 + 1;
            slots.push(PidSlot {
                pid,
                mapped: true,
                pmt_codec,
                reassembler: PesReassembler::new(),
                pts: NearestEpochUnwrap::default(),
                dts: NearestEpochUnwrap::default(),
                splitter: syntax.map(crate::AudioFrameSplitter::new),
                last_cc: None,
                duplicate_seen: false,
                last_payload: Default::default(),
                damaged: false,
            });
        }
        if streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegts: PMT advertised no streams we recognise (BD-relevant types: \
                 0x02/0x1B/0x24/0xEA video, 0x80-0x86 audio, 0x90/0x92 subtitle)",
            ));
        }
        // Share the in-flight budget between the PIDs.
        let per_pid = (MAX_INFLIGHT_BYTES / slots.len()).min(crate::pes::DEFAULT_MAX_PES_BYTES);
        for slot in &mut slots {
            slot.reassembler = PesReassembler::new().with_max_bytes(per_pid);
        }

        let mut demuxer = Self {
            reader,
            programs,
            selected_program,
            pcr_pid: pmt.pcr_pid,
            pmt_pid,
            pat_watch: PsiSectionAssembler::new(),
            pmt_watch: PsiSectionAssembler::new(),
            pmt_entries: pmt_signature(&pmt),
            pcr_tracker: PcrTracker::new(),
            streams,
            pid_slot,
            slots,
            pending: VecDeque::new(),
            eof_reached: false,
            base_offset,
            stats: TsDemuxStats::default(),
            duration_micros: None,
            first_pcr: None,
            last_pcr: None,
            rap_index: None,
            layout,
        };

        // Probe the stream parameters and the container duration from
        // the PCR span (§2.4.2.2); both are out-of-band reads. A source
        // too short to carry two PCRs leaves `duration_micros` at
        // `None`.
        //
        // Streaming then starts over from the first packet: a capture
        // cut mid-stream carries elementary-stream packets ahead of its
        // first PAT / PMT, and they belong to the streams just mapped.
        demuxer.probe_stream_params();
        demuxer.duration_micros = demuxer.compute_duration_micros();
        demuxer.reader.seek(0);
        demuxer.reader.resync_bytes = 0;
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

    /// What the streaming path has skipped or repaired so far.
    pub fn stats(&self) -> TsDemuxStats {
        TsDemuxStats {
            resync_bytes: self.reader.resync_bytes,
            ..self.stats
        }
    }

    /// Set the ceiling on the bytes held for one PID's in-flight PES
    /// packet (default: an equal share of 256 MiB per stream, at most
    /// [`crate::pes::DEFAULT_MAX_PES_BYTES`]). A PES packet of
    /// undeclared length that reaches the ceiling is handed out in
    /// pieces — the first carries the timestamps, the rest none — so a
    /// lower ceiling trades packet integrity of oversized access units
    /// for memory.
    pub fn set_max_pes_bytes(&mut self, max_bytes: usize) {
        for slot in &mut self.slots {
            slot.reassembler.set_max_bytes(max_bytes);
        }
    }

    /// Bytes currently buffered across every PID's in-flight PES
    /// packet.
    pub fn buffered_bytes(&self) -> usize {
        self.slots
            .iter()
            .map(|s| s.reassembler.buffered_len())
            .sum()
    }

    /// Bytes in the source ahead of the first whole transport packet —
    /// non-zero for a capture that starts mid-packet or behind leading
    /// bytes that are not transport packets.
    pub fn leading_bytes(&self) -> u64 {
        self.base_offset
    }

    /// Slot (= stream) index following `pid`, if any.
    fn slot_of(&self, pid: u16) -> Option<usize> {
        match self.pid_slot[pid as usize & (PID_SPACE - 1)] {
            0 => None,
            n => Some(n as usize - 1),
        }
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
        let len = self.reader.raw().seek(std::io::SeekFrom::End(0)).ok()?;
        if len < 2 * psize {
            return None;
        }
        let aligned_len = (len / psize) * psize;

        // First PCR from the head: align to a packet boundary and scan
        // forward. Real BD/broadcast streams carry a PCR within the
        // first handful of packets on the PCR_PID.
        let (first_pcr, first_off) = self.scan_pcr_forward(0, len.min(PCR_ANCHOR_SCAN_BYTES))?;
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
            if start == 0 || window >= PCR_ANCHOR_SCAN_BYTES {
                // Scanned the whole stream (or the largest tail window)
                // and found at most one PCR.
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
        let psize = self.layout.packet_size as u64;
        let base = self.base_offset;
        let len = self
            .reader
            .raw()
            .seek(SeekFrom::End(0))
            .map_err(CoreError::Io)?;
        let aligned_len = (len / psize) * psize;

        let mut out: Vec<RandomAccessPoint> = Vec::new();
        // Per slot: indices into `out` of indicator points whose
        // announced PES start (the next PUSI=1 packet on the PID)
        // hasn't been seen yet.
        let mut unresolved: Vec<Vec<usize>> = vec![Vec::new(); self.slots.len()];
        // Per-slot reference time for the out-of-order-tolerant PTS
        // unwrap: each PES start's raw 33-bit PTS extends to the epoch
        // nearest the previous one on the PID (`extend_near`), exactly
        // tracking the wraps the streaming unwrapper counts while
        // shrugging off B-picture reordering.
        let mut pts_ref: Vec<Option<u64>> = vec![None; self.slots.len()];
        let mut scan =
            GridScan::new(self.reader.raw(), self.layout, 0, aligned_len).map_err(CoreError::Io)?;
        while let Some((off, window)) = scan.next_packet() {
            if out.len() >= MAX_INDEX_ENTRIES {
                break;
            }
            // A stray mid-stream corruption shouldn't abort the index;
            // skip unparseable packets (the streaming path has its own
            // resync story).
            let Ok(pkt) = TsPacket::parse(window) else {
                continue;
            };
            let slot = match self.pid_slot[pkt.pid as usize] {
                0 => continue,
                n => n as usize - 1,
            };
            let stream_index = slot as u32;
            let rai = pkt
                .adaptation_field
                .as_ref()
                .is_some_and(|af| af.random_access_indicator);
            if rai {
                unresolved[slot].push(out.len());
                out.push(RandomAccessPoint {
                    byte_offset: off + base,
                    pid: pkt.pid,
                    stream_index,
                    pts_90k: None,
                    kind: AccessPointKind::RandomAccessIndicator,
                });
            }
            if pkt.payload_unit_start {
                let pes = PesPacket::parse_header(pkt.payload).ok().map(|(p, _)| p);
                let pts = pes.as_ref().and_then(|p| p.pts_90k).map(|raw| {
                    let ext = match pts_ref[slot] {
                        Some(r) => crate::clock::extend_near(raw, r),
                        None => raw,
                    };
                    pts_ref[slot] = Some(ext);
                    ext
                });
                if !unresolved[slot].is_empty() {
                    // This PES start is the one the pending
                    // indicator(s) announced; lift its PTS.
                    for i in unresolved[slot].drain(..) {
                        out[i].pts_90k = pts;
                    }
                } else if pes.is_some_and(|p| p.data_alignment_indicator) && pts.is_some() {
                    // No indicator announced this PES, but its
                    // payload starts data-aligned (§2.4.3.7) —
                    // the fallback access-point tier.
                    out.push(RandomAccessPoint {
                        byte_offset: off + base,
                        pid: pkt.pid,
                        stream_index,
                        pts_90k: pts,
                        kind: AccessPointKind::DataAligned,
                    });
                }
            }
        }
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
        self.reposition(offset - self.base_offset, Some(pts as i64));
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
            .slots
            .get(stream_index as usize)
            .map(|slot| slot.pid)
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

        let mut scan = GridScan::new(self.reader.raw(), self.layout, from_off, u64::MAX)
            .map_err(CoreError::Io)?;

        let mut best_rai: Option<(u64, i64)> = None;
        let mut best_dai: Option<(u64, i64)> = None;
        // Anchor of an unresolved §2.4.3.5 indicator: the flagged
        // packet's offset, waiting for the next PES start on the PID.
        let mut pending_rai: Option<u64> = None;
        // Reference for the epoch-nearest PTS unwrap, advanced to each
        // resolved PES time; seeded by the PCR landing time.
        let mut pts_ref = from_time.max(0) as u64;

        // Ends with the window, or with the stream.
        while let Some((pkt_off, window)) = scan.next_packet() {
            let Ok(pkt) = TsPacket::parse(window) else {
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
            let pes = match PesPacket::parse_header(pkt.payload) {
                Ok((p, _)) => p,
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
        self.reposition(offset - self.base_offset, Some(pts as i64));
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
        self.reader.seek(offset);
        self.pending.clear();
        self.eof_reached = false;
        self.pcr_tracker.reset();
        self.pat_watch.reset();
        self.pmt_watch.reset();
        let hint = time_hint_90k.and_then(|t| u64::try_from(t).ok());
        for slot in &mut self.slots {
            slot.rehome(hint);
        }
    }

    /// Scan forward from byte offset `from` (must be packet-aligned)
    /// toward `len`, returning the first PCR on the selected `PCR_PID`
    /// and the byte offset of the packet that carried it — an
    /// out-of-band probe that leaves the streaming position alone.
    fn scan_pcr_forward(&mut self, from: u64, len: u64) -> Option<(Pcr, u64)> {
        let pcr_pid = self.pcr_pid;
        let mut scan = GridScan::new(self.reader.raw(), self.layout, from, len).ok()?;
        while let Some((off, window)) = scan.next_packet() {
            if let Some(pcr) = pcr_from_packet(window, pcr_pid) {
                return Some((pcr, off));
            }
        }
        None
    }

    /// Scan the half-open packet-aligned byte range `[from, to)` and
    /// return the **last** PCR on the selected `PCR_PID` together with
    /// its packet offset. `from` and `to` must be packet-aligned.
    fn scan_pcr_backward(&mut self, from: u64, to: u64) -> Option<(Pcr, u64)> {
        let pcr_pid = self.pcr_pid;
        let mut scan = GridScan::new(self.reader.raw(), self.layout, from, to).ok()?;
        let mut found: Option<(Pcr, u64)> = None;
        while let Some((off, window)) = scan.next_packet() {
            if let Some(pcr) = pcr_from_packet(window, pcr_pid) {
                found = Some((pcr, off));
            }
        }
        found
    }

    /// Turn a reassembled PES into output packets on `self.pending`:
    /// one per PES, or — for a stream with an [`crate::AudioFrameSplitter`]
    /// — one per audio access unit the payload completes. `corrupt`
    /// marks packets cut from a PES that lost transport packets.
    /// Returns the number of packets queued.
    fn emit_pes(&mut self, slot: usize, mut pes: PesPacket, corrupt: bool) -> usize {
        if self.slots[slot].splitter.is_none() {
            let pkt = self.finish_pes(slot, pes).with_corrupt(corrupt);
            self.pending.push_back(pkt);
            return 1;
        }
        let payload = std::mem::take(&mut pes.payload);
        // Timestamps through the same unwrap path as whole-PES packets.
        let head = self.finish_pes(slot, pes).with_corrupt(corrupt);
        let splitter = self.slots[slot].splitter.as_mut().expect("checked above");
        let was_locked = splitter.is_locked();
        let frames = splitter.push(&payload, head.pts);
        if frames.is_empty() && !was_locked {
            splitter.unlock();
            // Nothing in this payload framed as an access unit (a
            // stream that is not what its stream_type claims, or a
            // tail fragment after a seek): hand the PES through whole
            // rather than drop it, as before splitting existed.
            let mut head = head;
            head.data = payload;
            self.pending.push_back(head);
            return 1;
        }
        let n = frames.len();
        for f in frames {
            let pkt = self
                .audio_frame_packet(slot as u32, f)
                .with_corrupt(corrupt);
            self.pending.push_back(pkt);
        }
        n
    }

    /// Wrap one split audio access unit as a core packet. Every audio
    /// frame is an entry point of its stream, so each is flagged a
    /// keyframe.
    fn audio_frame_packet(&self, stream_idx: u32, f: crate::AudioFrame) -> Packet {
        let tb = TimeBase::new(1, 90_000);
        let dur = f.info.duration_90k() as i64;
        let mut pkt = Packet::new(stream_idx, tb, f.data);
        if let Some(p) = f.pts {
            pkt = pkt.with_pts(p).with_dts(p);
        }
        if dur > 0 {
            pkt = pkt.with_duration(dur);
        }
        pkt.with_keyframe(true)
    }

    /// Unwrap a freshly reassembled PES into a [`Packet`], carrying the
    /// monotonic 64-bit extended PTS/DTS (§2.4.3.7) rather than the raw
    /// 33-bit ring value, and record the stream's `start_time` on its
    /// first timestamped packet.
    fn finish_pes(&mut self, slot: usize, mut pes: PesPacket) -> Packet {
        let tb = TimeBase::new(1, 90_000);
        let mut pkt = Packet::new(slot as u32, tb, std::mem::take(&mut pes.payload));
        // A TS-level random_access_indicator (§2.4.3.5) announced this
        // PES as beginning at an elementary-stream access point — the
        // container-level keyframe signal. Audio, subtitle and data
        // access units are each an entry point of their stream.
        let params = &self.streams[slot].params;
        if pes.random_access
            || params.media_type != MediaType::Video
            || crate::es_params::es_starts_with_keyframe(params.codec_id.as_str(), &pkt.data)
        {
            pkt = pkt.with_keyframe(true);
        }
        let state = &mut self.slots[slot];
        let mut pts_ext: Option<u64> = None;
        if let Some(raw) = pes.pts_90k {
            let ext = state.pts.extend(raw);
            pts_ext = Some(ext);
            pkt = pkt.with_pts(ext as i64);
            let info = &mut self.streams[slot];
            if info.start_time.is_none() {
                info.start_time = Some(ext as i64);
            }
        }
        if let Some(raw) = pes.dts_90k {
            // §2.4.3.7: DTS and PTS share one time base. A stream
            // whose first coded DTS only appears after a 2^33 wrap
            // must not anchor an independent epoch at the raw ring
            // value — place it next to this PES's extended PTS so both
            // fields stay on the same 64-bit axis (found by the
            // mux_roundtrip fuzz target on a wrap-crossing timeline).
            if !state.dts.is_anchored()
                && let Some(hint) = pts_ext
            {
                state.dts.seed(hint);
            }
            let ext = state.dts.extend(raw);
            pkt = pkt.with_dts(ext as i64);
        } else if let Some(ext) = pts_ext {
            // §2.4.3.7 (PTS_DTS_flags '10'): no DTS is coded when the
            // decoding time equals the presentation time.
            pkt = pkt.with_dts(ext as i64);
        }
        pkt
    }

    /// Open-time look-ahead that fills each stream's picture / audio
    /// parameters from its first access unit when the PMT descriptors
    /// did not (ISO/IEC 13818-1 §2.6 carries no picture size or channel
    /// count for the common stream types): H.264 SPS / MPEG-1/2
    /// sequence header for video, the first syncframe header for audio
    /// (which also refines MPEG-audio layer and AC-3 vs E-AC-3).
    ///
    /// Reads at most [`PARAM_PROBE_BYTES`] from the head; the caller
    /// sets the streaming position afterwards.
    fn probe_stream_params(&mut self) {
        let n = self.slots.len();
        let mut need = vec![false; n];
        for (i, slot) in self.slots.iter().enumerate() {
            let id = self.streams[i].params.codec_id.as_str();
            // Only the slot a PID actually routes to can be probed.
            need[i] = self.slot_of(slot.pid) == Some(i)
                && (slot.splitter.is_some() || matches!(id, "h264" | "mpeg1video" | "mpeg2video"));
        }
        let mut wanted = need.iter().filter(|&&w| w).count();
        let mut asm: Vec<PesReassembler> = (0..n)
            .map(|_| PesReassembler::new().with_max_bytes(PARAM_PROBE_VIDEO_BYTES))
            .collect();
        let mut video_bytes: Vec<Vec<u8>> = vec![Vec::new(); n];
        // Accumulated size at which a video stream's headers are next
        // looked for: every PES while the buffer is small, then at
        // doublings, so the total scan work stays linear.
        let mut retry_at = vec![0usize; n];
        self.reader.seek(0);
        while wanted > 0 && self.reader.position() < PARAM_PROBE_BYTES {
            let Ok(Some((_, raw))) = self.reader.next_packet() else {
                break;
            };
            let Ok(pkt) = TsPacket::parse(&raw) else {
                continue;
            };
            let Some(i) = self.slot_of(pkt.pid) else {
                continue;
            };
            if !need[i] || pkt.transport_error {
                continue;
            }
            let Ok(Some(pes)) = asm[i].feed(&pkt) else {
                continue;
            };
            if self.probe_pes(i, &pes.payload, &mut video_bytes[i], &mut retry_at[i]) {
                need[i] = false;
                wanted -= 1;
            }
        }
        // A stream whose only PES packet never met a successor (a
        // one-picture file) still has it in flight.
        for i in 0..n {
            if need[i]
                && let Ok(Some(pes)) = asm[i].flush()
            {
                self.probe_pes(i, &pes.payload, &mut video_bytes[i], &mut retry_at[i]);
            }
        }
    }

    /// Look for stream `i`'s parameters in one more PES payload.
    /// Returns `true` once the stream needs no further payloads.
    fn probe_pes(
        &mut self,
        i: usize,
        payload: &[u8],
        acc: &mut Vec<u8>,
        retry_at: &mut usize,
    ) -> bool {
        if let Some(sp) = &self.slots[i].splitter {
            let mut probe = crate::AudioFrameSplitter::new(sp.syntax());
            if let Some(f) = probe.push(payload, None).first() {
                crate::es_params::apply_audio(&mut self.streams[i].params, &f.info);
                return true;
            }
            return false;
        }
        acc.extend_from_slice(payload);
        if acc.len() < *retry_at {
            return false;
        }
        *retry_at = if acc.len() < PARAM_PROBE_RESCAN_BYTES {
            0
        } else {
            acc.len().saturating_mul(2)
        };
        let params = &mut self.streams[i].params;
        let found = match params.codec_id.as_str() {
            "h264" => crate::es_params::h264_params(acc),
            _ => crate::es_params::mpeg12_params(acc),
        };
        if let Some(v) = found {
            // `stream_type` 0x02 also carries ISO/IEC 11172-2
            // constrained-parameter streams (Table 2-34): the absence
            // of a sequence_extension tells them apart.
            if !v.mpeg2 && params.codec_id.as_str() == "mpeg2video" {
                params.codec_id = CodecId::new("mpeg1video");
            }
            crate::es_params::apply_video(params, &v);
            return true;
        }
        acc.len() > PARAM_PROBE_VIDEO_BYTES
    }

    /// Route one transport packet read at stream offset `offset`:
    /// PCR recovery on the `PCR_PID`, continuity bookkeeping and PES
    /// reassembly on the elementary PIDs. Nothing here fails — damage
    /// is skipped and counted (see [`TsDemuxStats`]).
    fn route(&mut self, offset: u64, raw: &[u8; TS_PACKET_LEN]) {
        if raw[1] & 0x80 != 0 {
            // transport_error_indicator: any field of the packet may
            // be wrong, the PID included.
            self.stats.transport_errors += 1;
            return;
        }
        // Most packets of a multi-program stream belong to PIDs this
        // demuxer does not follow: decide that from the two PID bytes
        // before parsing anything else.
        let pid = (u16::from(raw[1] & 0x1F) << 8) | u16::from(raw[2]);
        if self.pid_slot[pid as usize] == 0
            && pid != self.pcr_pid
            && pid != self.pmt_pid
            && pid != PAT_PID
        {
            return;
        }
        let Ok(pkt) = TsPacket::parse(raw) else {
            self.stats.malformed_packets += 1;
            return;
        };
        if pid == PAT_PID {
            self.watch_pat(&pkt);
        }
        if pid == self.pmt_pid {
            self.watch_pmt(&pkt);
        }
        // PCR recovery runs on the PCR_PID regardless of whether that
        // PID also carries an elementary stream we track.
        if pkt.pid == self.pcr_pid
            && let Some(af) = &pkt.adaptation_field
        {
            self.pcr_tracker.observe(af, offset);
        }
        let Some(i) = self.slot_of(pkt.pid) else {
            return;
        };
        let slot = &mut self.slots[i];
        // §2.4.3.3: the counter increments on packets with a payload
        // (adaptation_field_control '01' / '11'); the same value over
        // the same payload is a duplicate; any other step means
        // packets were lost — unless the adaptation field announces
        // the discontinuity.
        let has_payload = raw[3] & 0x10 != 0;
        if has_payload {
            if pkt.transport_scrambling_control != 0 {
                self.stats.scrambled_packets += 1;
            }
            let cc = pkt.continuity_counter;
            let mark = crate::packet::PayloadMark::of(pkt.payload);
            let announced = pkt
                .adaptation_field
                .as_ref()
                .is_some_and(|af| af.discontinuity_indicator);
            if let Some(prev) = slot.last_cc
                && !announced
            {
                if cc == prev && !slot.duplicate_seen && mark == slot.last_payload {
                    slot.duplicate_seen = true;
                    self.stats.duplicate_packets += 1;
                    return;
                }
                if cc != (prev + 1) & 0x0F {
                    self.stats.continuity_errors += 1;
                    slot.damaged = true;
                }
            }
            slot.last_cc = Some(cc);
            slot.duplicate_seen = false;
            slot.last_payload = mark;
        }
        match slot.reassembler.feed(&pkt) {
            Ok(Some(pes)) => {
                let corrupt = std::mem::take(&mut slot.damaged);
                self.emit_pes(i, pes, corrupt);
            }
            Ok(None) => {}
            Err(_) => {
                slot.damaged = false;
                self.stats.damaged_pes += 1;
            }
        }
    }

    /// Follow the PAT: when a currently applicable table lists the
    /// selected program under another `program_map_PID`, watch that
    /// PID from now on.
    fn watch_pat(&mut self, pkt: &TsPacket<'_>) {
        if pkt.payload.is_empty() {
            return;
        }
        let Ok(sections) =
            self.pat_watch
                .feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
        else {
            return;
        };
        for section in &sections {
            let Ok(pat) = ProgramAssociationTable::parse(section) else {
                continue;
            };
            if !pat.current_next_indicator {
                continue;
            }
            let listed = pat
                .programs
                .iter()
                .find(|&&(number, _)| number == self.selected_program)
                .map(|&(_, pid)| pid & 0x1FFF);
            if let Some(pid) = listed
                && pid != self.pmt_pid
            {
                self.pmt_pid = pid;
                self.pmt_watch.reset();
                self.stats.program_map_changes += 1;
            }
        }
    }

    /// Follow the selected program's PMT: a currently applicable
    /// section that differs from the map in effect re-points the
    /// streams (see the type docs).
    fn watch_pmt(&mut self, pkt: &TsPacket<'_>) {
        if pkt.payload.is_empty() {
            return;
        }
        let Ok(sections) =
            self.pmt_watch
                .feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
        else {
            return;
        };
        for section in &sections {
            let Ok(pmt) = ProgramMapTable::parse(section) else {
                continue;
            };
            if pmt.program_number != self.selected_program || !pmt.current_next_indicator {
                continue;
            }
            let entries = pmt_signature(&pmt);
            if entries == self.pmt_entries && pmt.pcr_pid == self.pcr_pid {
                continue;
            }
            self.apply_program_map(&pmt, entries);
        }
    }

    /// Re-point every stream at the first not-yet-taken entry of its
    /// codec in `pmt`.
    fn apply_program_map(&mut self, pmt: &ProgramMapTable, entries: Vec<(u8, u16)>) {
        self.stats.program_map_changes += 1;
        let codecs: Vec<Option<CodecId>> = pmt
            .streams
            .iter()
            .map(|e| pmt_entry_codec(e).map(|p| p.codec_id))
            .collect();
        let mut taken = vec![false; codecs.len()];
        let mut target: Vec<Option<u16>> = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let hit = (0..codecs.len())
                .find(|&k| !taken[k] && codecs[k].as_ref() == Some(&slot.pmt_codec));
            if let Some(k) = hit {
                taken[k] = true;
            }
            target.push(hit.map(|k| pmt.streams[k].elementary_pid & 0x1FFF));
        }
        for (i, new_pid) in target.iter().enumerate() {
            let slot = &mut self.slots[i];
            let unchanged = slot.mapped && *new_pid == Some(slot.pid);
            if unchanged {
                continue;
            }
            // Whatever was in flight on the old PID is complete as far
            // as this stream will ever see it.
            let flushed = slot.reassembler.flush();
            let corrupt = std::mem::take(&mut slot.damaged);
            slot.last_cc = None;
            slot.duplicate_seen = false;
            if slot.mapped {
                self.pid_slot[slot.pid as usize] = 0;
            }
            slot.mapped = new_pid.is_some();
            if let Some(pid) = *new_pid {
                slot.pid = pid;
            }
            match flushed {
                Ok(Some(pes)) => {
                    self.emit_pes(i, pes, corrupt);
                }
                Ok(None) => {}
                Err(_) => self.stats.damaged_pes += 1,
            }
        }
        // Old entries are cleared above before any new one is set, so
        // two streams trading PIDs end up routed correctly.
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.mapped {
                self.pid_slot[slot.pid as usize] = i as u16 + 1;
            }
        }
        if pmt.pcr_pid != self.pcr_pid {
            self.pcr_pid = pmt.pcr_pid;
            self.pcr_tracker.reset();
        }
        self.pmt_entries = entries;
    }

    /// Flush every per-PID reassembler — used once the input runs
    /// dry. Pushes a final `Packet` per stream that had a buffered
    /// in-flight PES at end-of-stream, in ascending PID order.
    fn flush_reassemblers(&mut self) {
        let mut order: Vec<usize> = (0..self.slots.len()).collect();
        order.sort_by_key(|&i| self.slots[i].pid);
        for i in order {
            match self.slots[i].reassembler.flush() {
                Ok(Some(pes)) => {
                    let corrupt = std::mem::take(&mut self.slots[i].damaged);
                    self.emit_pes(i, pes, corrupt);
                }
                Ok(None) => {}
                Err(_) => self.stats.damaged_pes += 1,
            }
            // A trailing partial audio frame (truncated stream) still
            // reaches the decoder, which decides whether it is usable.
            if let Some(f) = self.slots[i].splitter.as_mut().and_then(|s| s.flush()) {
                let pkt = self.audio_frame_packet(i as u32, f);
                self.pending.push_back(pkt);
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
            match self.reader.next_packet()? {
                Some((offset, raw)) => self.route(offset, &raw),
                None => {
                    self.eof_reached = true;
                    self.flush_reassemblers();
                }
            }
        }
    }
}

/// Head bytes examined to find the packet layout and the first whole
/// packet.
const LAYOUT_PROBE_BYTES: usize = 64 << 10;

/// Input bytes read past the first PAT section while waiting for the
/// remaining sections of a multi-section PAT.
const PAT_COMPLETION_BYTES: u64 = 4 << 20;

/// Input bytes read past a PMT section that is not (yet) the selected
/// program's applicable one before settling for it.
const PMT_FALLBACK_BYTES: u64 = 4 << 20;

/// Input bytes the open-time parameter probe reads past the PMT
/// before giving up on streams whose first access unit never arrived.
const PARAM_PROBE_BYTES: u64 = 8 << 20;

/// Elementary-stream bytes accumulated per video PID while hunting for
/// a sequence parameter set / sequence header.
const PARAM_PROBE_VIDEO_BYTES: usize = 2 << 20;

/// Below this many accumulated bytes the header hunt re-runs on every
/// PES packet; above it only when the buffer has doubled.
const PARAM_PROBE_RESCAN_BYTES: usize = 64 << 10;

/// Input bytes scanned from the head of the stream for the first PCR,
/// and the largest tail window scanned for the last one. §2.7.2 spaces
/// PCRs at most 0,1 s apart, so both sit within a fraction of this at
/// any realistic rate.
const PCR_ANCHOR_SCAN_BYTES: u64 = 64 << 20;

/// Ceiling on the entries of the access-point index (32 bytes each).
const MAX_INDEX_ENTRIES: usize = 4 << 20;

/// Bytes, in packets, one read may examine while resyncing after a bad
/// sync byte. We've observed real BD M2TS streams with ~2 AACS units
/// (~12 KB ≈ 64 TS packets) of undecryptable bytes at chapter
/// boundaries — an independent decryption of the same disc reproduces
/// the same garbage bytes there, so the bytes are part of the
/// protected variant-key area, not a flaw in our decryption. 256
/// packets gives a comfortable ceiling without silently swallowing a
/// longer corruption that the caller should know about.
const RESYNC_PACKET_LIMIT: usize = 256;

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
        if let crate::DescriptorBody::Iso639Language(langs) = &d.body
            && let Some(first) = langs.first()
        {
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
    None
}

/// Input bytes examined while identifying private-data PES streams by
/// their payload.
const PRIVATE_SNIFF_BYTES: u64 = 4 << 20;

/// PES packets of one private-data stream examined before giving up.
const PRIVATE_SNIFF_PACKETS: u32 = 4;

/// Identify the private-data PES streams on `pids` by their payload: a
/// PES packet whose payload starts with a frame header of one syntax
/// and frames as at least two consecutive access units of it (or one
/// filling the whole payload) names the codec. Streams that never do
/// are left out. Reads from the head of the source.
fn sniff_private_audio(reader: &mut PacketReader, pids: &[u16]) -> Vec<(u16, &'static str)> {
    use crate::AudioSyntax as S;
    let mut found = Vec::new();
    if pids.is_empty() {
        return found;
    }
    let mut pending: Vec<(u16, PesReassembler, u32)> = pids
        .iter()
        .map(|&pid| (pid, PesReassembler::new().with_max_bytes(1 << 20), 0))
        .collect();
    reader.seek(0);
    while !pending.is_empty() && reader.position() < PRIVATE_SNIFF_BYTES {
        let Ok(Some((_, raw))) = reader.next_packet() else {
            break;
        };
        let Ok(pkt) = TsPacket::parse(&raw) else {
            continue;
        };
        let Some(at) = pending.iter().position(|(pid, ..)| *pid == pkt.pid) else {
            continue;
        };
        let Ok(Some(pes)) = pending[at].1.feed(&pkt) else {
            continue;
        };
        let hit = [
            (S::Ac3, "ac3"),
            (S::Dts, "dts"),
            (S::AacLoas, "aac_latm"),
            (S::AacAdts, "aac"),
            (S::MpegAudio, "mp2"),
        ]
        .into_iter()
        .find(|&(syntax, _)| {
            let mut sp = crate::AudioFrameSplitter::new(syntax);
            let frames = sp.push(&pes.payload, None);
            sp.discarded_bytes() == 0
                && (frames.len() >= 2 || (frames.len() == 1 && sp.pending_bytes() == 0))
        });
        pending[at].2 += 1;
        if let Some((_, id)) = hit {
            found.push((pkt.pid, id));
            pending.swap_remove(at);
        } else if pending[at].2 >= PRIVATE_SNIFF_PACKETS {
            pending.swap_remove(at);
        }
    }
    found
}

/// Codec parameters a PMT entry names: by `stream_type`, or — for PES
/// private data — by its descriptors. `None` for entries this demuxer
/// does not surface.
fn pmt_entry_codec(entry: &crate::PmtStream) -> Option<CodecParameters> {
    codec_params_for_stream_type(entry.stream_type).or_else(|| codec_params_for_private_pes(entry))
}

/// `(stream_type, elementary_PID)` of every PMT entry, in order.
fn pmt_signature(pmt: &ProgramMapTable) -> Vec<(u8, u16)> {
    pmt.streams
        .iter()
        .map(|e| (e.stream_type, e.elementary_pid & 0x1FFF))
        .collect()
}

/// `stream_type` 0x06 (PES private data, Table 2-34) names its codec
/// only through descriptors:
///
/// * the DVB `AC-3_descriptor` (0x6A) / `enhanced_AC-3_descriptor`
///   (0x7A) (ATSC A/52 Annex A §5 / EN 300 468 Annex D), or a
///   `registration_descriptor` (§2.6.8) whose `format_identifier` is
///   "AC-3" (A/52 Annex A §3) / "EAC3" (A/52 Annex G §3);
/// * the DVB `DTS_descriptor` (0x7B, EN 300 468 Annex G) or the
///   "DTS1" / "DTS2" / "DTS3" / "DTSH" `format_identifier`s
///   (ETSI TS 102 114 Annex F.2.1);
/// * the DVB `subtitling_descriptor` (0x59, EN 300 468 §6.2.41) —
///   an EN 300 743 subtitle stream;
/// * the DVB `teletext_descriptor` (0x56, §6.2.43) or
///   `VBI_teletext_descriptor` (0x46, §6.2.48) — EBU teletext.
fn codec_params_for_private_pes(pmt_stream: &crate::PmtStream) -> Option<CodecParameters> {
    if pmt_stream.stream_type != 0x06 {
        return None;
    }
    for d in pmt_stream.iter_descriptors().flatten() {
        let (id, media) = match (&d.body, d.tag) {
            (_, 0x6A) => ("ac3", MediaType::Audio),
            (_, 0x7A) => ("eac3", MediaType::Audio),
            (_, 0x7B) => ("dts", MediaType::Audio),
            (_, 0x59) => ("dvb_subtitle", MediaType::Subtitle),
            (_, 0x56 | 0x46) => ("dvb_teletext", MediaType::Subtitle),
            (
                crate::DescriptorBody::Registration {
                    format_identifier, ..
                },
                _,
            ) => match format_identifier {
                b"AC-3" => ("ac3", MediaType::Audio),
                b"EAC3" => ("eac3", MediaType::Audio),
                b"DTS1" | b"DTS2" | b"DTS3" | b"DTSH" => ("dts", MediaType::Audio),
                _ => continue,
            },
            _ => continue,
        };
        let id = CodecId::new(id);
        return Some(match media {
            MediaType::Subtitle => CodecParameters::subtitle(id),
            _ => CodecParameters::audio(id),
        });
    }
    None
}

/// Lift the numeric facts the PMT ES_info descriptors carry into the
/// stream's parameters:
///
/// * `video_stream_descriptor` (tag 0x02, §2.6.2 / §2.6.3) — a single
///   `frame_rate_code` (`multiple_frame_rate_flag = 0`) per H.262
///   Table 6-4.
/// * ATSC `AC-3_audio_stream_descriptor` (tag 0x81, A/52 Annex A §4.3
///   Table A4.1) on an AC-3 stream — an exact `sample_rate_code`
///   (Table A4.2 codes '000'..'010'; the "or" sets are not a rate).
fn apply_descriptor_params(params: &mut CodecParameters, pmt_stream: &crate::PmtStream) {
    const FRAME_RATES: [(i64, i64); 9] = [
        (0, 0),
        (24_000, 1001),
        (24, 1),
        (25, 1),
        (30_000, 1001),
        (30, 1),
        (50, 1),
        (60_000, 1001),
        (60, 1),
    ];
    for d in pmt_stream.iter_descriptors().flatten() {
        match &d.body {
            crate::DescriptorBody::VideoStream(v) if !v.multiple_frame_rate_flag => {
                if let Some(&(n, den)) = FRAME_RATES.get(v.frame_rate_code as usize)
                    && den != 0
                    && params.frame_rate.is_none()
                {
                    params.frame_rate = Some(oxideav_core::Rational::new(n, den));
                }
            }
            _ if d.tag == 0x81
                && matches!(params.codec_id.as_str(), "ac3" | "eac3")
                && !d.data.is_empty() =>
            {
                let rate = match d.data[0] >> 5 {
                    0 => Some(48_000),
                    1 => Some(44_100),
                    2 => Some(32_000),
                    _ => None,
                };
                if params.sample_rate.is_none() {
                    params.sample_rate = rate;
                }
            }
            _ => {}
        }
    }
}

/// Map an MPEG-TS `stream_type` byte to a [`CodecParameters`] the
/// muxer registry understands. `None` means "drop this stream" —
/// interactive graphics, DSM-CC sections, vendor-private codes, etc.
pub(crate) fn codec_params_for_stream_type(st: u8) -> Option<CodecParameters> {
    let s = StreamType::from_raw(st);
    // (codec_id, is_video, is_subtitle); audio is the residual class.
    let (cid, is_video, is_subtitle): (&'static str, bool, bool) = match s {
        StreamType::Mpeg1Video => ("mpeg1video", true, false),
        StreamType::Mpeg2Video | StreamType::Mpeg2StereoView => ("mpeg2video", true, false),
        StreamType::Mpeg4Visual => ("mpeg4video", true, false),
        StreamType::AvcVideo | StreamType::AvcStereoView => ("h264", true, false),
        StreamType::HevcVideo | StreamType::HevcTemporalSubset => ("h265", true, false),
        StreamType::VvcVideo | StreamType::VvcTemporalSubset => ("h266", true, false),
        StreamType::EvcVideo => ("evc", true, false),
        StreamType::Jpeg2000Video => ("jpeg2000", true, false),
        StreamType::JpegXsVideo => ("jpegxs", true, false),
        StreamType::Vc1Video => ("vc1", true, false),
        StreamType::Mpeg1Audio | StreamType::Mpeg2Audio => ("mp2", false, false),
        StreamType::AacAdts | StreamType::Mpeg4AudioRaw => ("aac", false, false),
        // ISO/IEC 14496-3 LATM: a different framing from ADTS / raw
        // access units, so it keeps its own id.
        StreamType::AacLatm => ("aac_latm", false, false),
        StreamType::LpcmAudio => ("pcm_s16be", false, false),
        StreamType::Ac3Audio | StreamType::EAc3SecondaryAudio => ("ac3", false, false),
        StreamType::EAc3Audio | StreamType::AtscEAc3Audio => ("eac3", false, false),
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
/// * `50`  — no grid from byte 0, but one of five consecutive packets
///   starts further into the buffer (a capture cut mid-packet; see
///   [`crate::packet::locate_packet_layout`]).
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
        _ if crate::packet::locate_packet_layout(p.buf).is_some() => 50,
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
            d.extend(std::iter::repeat_n(0xAA, 200));
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
        let cursor: Box<dyn ReadSeek> = Box::new(Cursor::new(buf));
        let mut reader = PacketReader::new(cursor, crate::packet::TsPacketLayout::STANDARD);
        // First read: clean.
        let (o0, r0) = reader.next_packet().expect("first").expect("Some");
        assert_eq!((o0, r0[3] & 0x0F), (0, 0));
        // Second read: bytes start at offset 188 (inside garbage), so
        // resync triggers. It should land on p1 and report where p1
        // really sits.
        let (o1, r1) = reader.next_packet().expect("resync").expect("Some");
        assert_eq!(r1[3] & 0x0F, 1, "expected CC=1, got CC={}", r1[3] & 0x0F);
        assert_eq!(o1, 12 * TS_PACKET_LEN as u64);
        // Third read: p2 follows without a second resync.
        let (o2, r2) = reader.next_packet().expect("p2").expect("Some");
        assert_eq!(r2[3] & 0x0F, 2, "expected CC=2, got CC={}", r2[3] & 0x0F);
        assert_eq!(o2, 13 * TS_PACKET_LEN as u64);
        assert!(reader.next_packet().expect("eof").is_none());
        assert_eq!(reader.resync_bytes, 11 * TS_PACKET_LEN as u64);
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
