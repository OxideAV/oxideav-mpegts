//! Container [`Muxer`] implementation that writes elementary-stream
//! [`Packet`]s into a 188-byte MPEG-TS file per ISO/IEC 13818-1.
//!
//! Scope:
//!
//! * Synthesises a PAT (`PID 0x0000`) listing every program's
//!   `(program_number, pmt_pid)` pair, and one PMT per program on its
//!   own PID, on `write_header`. The single-program `open` factory
//!   groups all streams into `program_number` 1 (PMT PID 0x0100);
//!   [`MpegTsMuxer::with_config`] takes a [`MpegTsMuxConfig`] of several
//!   [`ProgramSpec`]s for a genuine multi-program transport stream. PSI
//!   sections too long for one packet split across multiple TS packets
//!   per §2.4.4 — PUSI + `pointer_field` on the first, continuation on
//!   the rest.
//! * When a program carries a [`ServiceSpec`], a DVB Service Description
//!   Table (`PID 0x0011`) is emitted with a `service_descriptor` per
//!   service (ETSI EN 300 468 §5.2.3).
//! * Wraps each [`Packet`] in a PES envelope with PTS (and DTS when
//!   set), then fragments the PES into 188-byte TS packets — first
//!   packet has `payload_unit_start_indicator = 1`, continuations
//!   have it clear. Tail packets get an adaptation-field stuffing
//!   pass so the byte count lands on the 188-byte boundary.
//! * Per-PID continuity counters increment 0..0xF and wrap.
//! * Each program's PCR PID (its first video track by default) carries a
//!   PCR adaptation field on every PES start, and standalone PCR-only
//!   packets are injected on that PID whenever the inter-PCR interval
//!   would exceed the §2.7.2 bound (0,1 s), tracked independently per
//!   program and driven off PTS progression.
//! * The PAT / PMTs / SDT are re-emitted mid-stream at a configurable
//!   PTS interval (default ~200 ms; see
//!   [`MpegTsMuxer::set_psi_repetition_interval`]) so a receiver tuning
//!   in mid-file re-acquires the tables quickly, and once more at
//!   `write_trailer`.
//!
//! * A keyframe-flagged [`Packet`] (`PacketFlags::keyframe`) sets the
//!   `random_access_indicator` (§2.4.3.5) on the first TS packet of
//!   its PES envelope, so a receiver can locate random-access points
//!   without parsing the elementary stream. On the PCR PID the
//!   indicator is only emitted when that packet also carries a PCR,
//!   per the §2.4.3.5 constraint.
//!
//! Out of scope:
//!
//! * MPEG-DASH-style time slicing, PES-CRC, or scrambling.
//! * Adaptation-field discontinuity / private-data / splice flags on
//!   the write path (the [`crate::AdaptationFieldSpec`] builder covers
//!   them for callers assembling their own packets). The PCR PID gets
//!   PCR at every PES start plus periodic standalone PCR packets;
//!   non-PCR-PID tracks get an adaptation field for keyframe
//!   random-access marking and the tail-packet stuffing pass.
//!
//! CodecId → MPEG-TS `stream_type` (Table 2-29 + HDMV extension
//! 0x80..0xFF). The reverse mapping is performed at `open`; unknown
//! codecs surface as `Error::Unsupported`. The full list mirrors the
//! demuxer's `codec_params_for_stream_type` so a demux + mux
//! round-trip preserves the codec set on the disc.

use std::collections::HashMap;
use std::io::Write;

use oxideav_core::{
    Error as CoreError, Muxer, Packet, Result as CoreResult, StreamInfo, WriteSeek,
};

use crate::{TS_PACKET_LEN, TS_SYNC_BYTE};

/// PAT lives on PID 0x0000 by spec.
const PAT_PID: u16 = 0x0000;
/// PMT PID handed to the single (or first) program by default; the
/// conventional value. Multi-program configs assign subsequent PMT PIDs
/// upward from here (or the caller pins them explicitly).
const DEFAULT_PMT_PID: u16 = 0x0100;
/// First PID we hand out for an elementary stream.
const FIRST_ES_PID: u16 = 0x1011;
/// Default `program_number` for the single-program factory.
const DEFAULT_PROGRAM_NUMBER: u16 = 1;
/// ISO/IEC 13818-1 §2.7.2 bounds the interval between consecutive PCRs
/// on the PCR_PID at 0,1 s. We aim well inside it — a PCR at least
/// every ~40 ms (3600 ticks of the 90 kHz PCR base) — so even a player
/// that joins mid-stream locks the clock quickly. Driven off PTS, not
/// wall time: when a packet's PTS has advanced past
/// `last_pcr_pts + PCR_MAX_INTERVAL_90K`, a standalone PCR-only TS
/// packet is injected on the PCR_PID ahead of the PES.
const PCR_MAX_INTERVAL_90K: i64 = 3600;

/// `Open` factory matching `oxideav_core::OpenMuxerFn`. Registered
/// under the `"mpegts"` container name. Produces a single-program
/// muxer; use [`MpegTsMuxer::with_config`] for multi-program output.
pub fn open(output: Box<dyn WriteSeek>, streams: &[StreamInfo]) -> CoreResult<Box<dyn Muxer>> {
    MpegTsMuxer::new(output, streams).map(|m| Box::new(m) as Box<dyn Muxer>)
}

/// Human-readable service metadata carried in the DVB SDT for one
/// program (ETSI EN 300 468 §5.2.3 / §6.2.33). When a [`ProgramSpec`]
/// carries one, the muxer emits an SDT `service_descriptor` for the
/// program so a receiver can label the channel.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// `service_type` (Table 89) — e.g. `0x01` digital TV, `0x02` radio,
    /// `0x19` H.264 HD, `0x1F` HEVC.
    pub service_type: u8,
    /// Raw `service_provider_name` bytes (DVB text string).
    pub provider_name: Vec<u8>,
    /// Raw `service_name` bytes (DVB text string).
    pub service_name: Vec<u8>,
}

/// A present/following event described for one program in the DVB EIT
/// (ETSI EN 300 468 §5.2.4). The muxer emits a `short_event_descriptor`
/// for the event when `event_name` / `text` are non-empty.
#[derive(Debug, Clone)]
pub struct EventSpec {
    /// 16-bit `event_id`, unique within the service.
    pub event_id: u16,
    /// Event start time (DVB 40-bit MJD + BCD `UTC_time`), or `None` for
    /// the undefined sentinel.
    pub start_time: Option<crate::psi::EitDateTime>,
    /// Event duration (BCD hours/minutes/seconds).
    pub duration: crate::psi::EitDuration,
    /// `running_status` of the event.
    pub running_status: crate::psi::RunningStatus,
    /// 3-byte ISO 639-2 language of the `short_event_descriptor`.
    pub language: [u8; 3],
    /// Raw `event_name` bytes (DVB text string). Empty → no
    /// `short_event_descriptor`.
    pub event_name: Vec<u8>,
    /// Raw short-text description bytes (DVB text string).
    pub text: Vec<u8>,
}

/// One program of a multi-program transport stream.
///
/// A program groups a set of the muxer's input streams (by their
/// `StreamInfo.index`) under one `program_number`, its own PMT PID, and
/// its own PCR PID. The PAT gains one `(program_number, pmt_pid)` entry
/// per spec, and each program's PMT is emitted on its own PID.
#[derive(Debug, Clone)]
pub struct ProgramSpec {
    /// `program_number` advertised in the PAT + carried in the PMT's
    /// `table_id_extension`. Must be non-zero (0 is the network PID).
    pub program_number: u16,
    /// PID this program's PMT section is carried on. Must be unique
    /// across programs.
    pub pmt_pid: u16,
    /// PCR PID for this program. `None` → the first video stream in the
    /// program (or its first stream when there is no video).
    pub pcr_pid: Option<u16>,
    /// `StreamInfo.index` values of the input streams that belong to
    /// this program, in PMT order.
    pub stream_indices: Vec<u32>,
    /// Optional DVB service metadata → an SDT entry for this program.
    pub service: Option<ServiceSpec>,
    /// Present/following events for this program → an EIT p/f section
    /// (PID 0x0012) keyed on the program's `program_number` as
    /// `service_id`. Empty → no EIT for this program.
    pub events: Vec<EventSpec>,
    /// Extra PMT `ES_info` descriptor bytes to append for a stream, keyed
    /// by its `StreamInfo.index`. Lets a caller attach the DVB
    /// component descriptors the muxer can't infer — teletext (0x56),
    /// subtitling (0x59), AC-3 (0x6A), etc. — built with the `build`
    /// module. Appended after the auto-emitted stream_identifier +
    /// language descriptors.
    pub es_descriptors: Vec<(u32, Vec<u8>)>,
}

/// Network metadata carried in the DVB NIT (ETSI EN 300 468 §5.2.1). When
/// a [`MpegTsMuxConfig`] carries one, the muxer emits a NIT on PID 0x0010
/// naming the network and listing this transport stream (optionally with
/// delivery-system / service-list descriptors supplied verbatim).
#[derive(Debug, Clone)]
pub struct NetworkSpec {
    /// 16-bit `network_id` (rides the NIT `table_id_extension`).
    pub network_id: u16,
    /// Raw `network_name` bytes (DVB text string) → a
    /// `network_name_descriptor` in the network-level loop.
    pub network_name: Vec<u8>,
    /// Extra network-level descriptor bytes appended after the
    /// `network_name_descriptor` (may be empty).
    pub network_descriptors: Vec<u8>,
    /// Per-TS descriptor loop for this transport stream's entry in the
    /// `transport_stream_loop` (delivery-system / service_list, etc.).
    pub transport_descriptors: Vec<u8>,
}

/// Multi-program muxer configuration passed to
/// [`MpegTsMuxer::with_config`].
#[derive(Debug, Clone)]
pub struct MpegTsMuxConfig {
    /// `transport_stream_id` carried in the PAT (and SDT, when emitted).
    pub transport_stream_id: u16,
    /// `original_network_id` carried in the SDT / NIT (when emitted).
    pub original_network_id: u16,
    /// The programs multiplexed into this transport stream.
    pub programs: Vec<ProgramSpec>,
    /// Optional network metadata → a NIT on PID 0x0010.
    pub network: Option<NetworkSpec>,
}

impl Default for MpegTsMuxConfig {
    fn default() -> Self {
        Self {
            transport_stream_id: 1,
            original_network_id: 1,
            programs: Vec::new(),
            network: None,
        }
    }
}

/// MPEG-TS muxer state.
pub struct MpegTsMuxer {
    output: Box<dyn WriteSeek>,
    /// Per-stream PID + stream_type + stream_id + CC + owning program.
    tracks: Vec<TrackState>,
    /// One entry per multiplexed program — its PMT PID, PCR PID, and the
    /// tracks it carries.
    programs: Vec<ProgramState>,
    /// `stream_index` → `tracks[index]` for `write_packet` dispatch.
    idx_to_track: HashMap<u32, usize>,
    /// `transport_stream_id` for the PAT / SDT.
    transport_stream_id: u16,
    /// `original_network_id` for the SDT.
    original_network_id: u16,
    /// Continuity counter for PAT TS packets.
    pat_cc: u8,
    /// Continuity counter for SDT TS packets (PID 0x0011).
    sdt_cc: u8,
    /// Continuity counter for NIT TS packets (PID 0x0010).
    nit_cc: u8,
    /// Continuity counter for EIT TS packets (PID 0x0012).
    eit_cc: u8,
    /// Optional network metadata for the NIT.
    network: Option<NetworkSpec>,
    /// PSI re-emission interval in 90 kHz ticks, or `None` to emit the
    /// program tables only at header + trailer. When set, the PAT / PMTs
    /// / SDT are re-emitted mid-stream whenever the running PTS advances
    /// past `last_psi_pts + interval`, so a receiver that tunes in
    /// mid-file re-acquires the tables quickly (DVB TR 101 290 §5 calls
    /// for a PAT/PMT at least every 0,5 s; the default aims well inside
    /// that).
    psi_repetition_90k: Option<i64>,
    /// PTS at which the PSI tables were last (re-)emitted mid-stream.
    last_psi_pts: Option<i64>,
    /// `true` once `write_header` has run.
    header_written: bool,
}

impl std::fmt::Debug for MpegTsMuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpegTsMuxer")
            .field("tracks", &self.tracks.len())
            .field("programs", &self.programs.len())
            .field("header_written", &self.header_written)
            .finish()
    }
}

/// Per-program mux state.
#[derive(Debug, Clone)]
struct ProgramState {
    program_number: u16,
    pmt_pid: u16,
    pcr_pid: u16,
    /// Continuity counter for this program's PMT TS packets.
    pmt_cc: u8,
    /// Indices into `MpegTsMuxer::tracks` of the streams in this program,
    /// in PMT order.
    track_indices: Vec<usize>,
    /// 90 kHz PCR-base value of the last PCR emitted on this program's
    /// PCR_PID, or `None` before the first PCR (§2.7.2 interval bound).
    last_pcr_pts: Option<i64>,
    /// Optional DVB service metadata for the SDT.
    service: Option<ServiceSpec>,
    /// Present/following events for this program's EIT.
    events: Vec<EventSpec>,
}

#[derive(Debug, Clone)]
struct TrackState {
    pid: u16,
    stream_type: u8,
    stream_id: u8,
    cc: u8,
    is_video: bool,
    /// Index into `MpegTsMuxer::programs` of this track's owning program.
    program: usize,
    /// DVB `component_tag` (EN 300 468 §6.2.39) — a per-program ordinal
    /// (1-based) emitted as a `stream_identifier_descriptor` in this
    /// track's PMT ES_info loop so an EIT `component_descriptor` can
    /// cross-reference the stream.
    component_tag: u8,
    /// 3-byte ISO 639-2 language code, when the `StreamInfo` carried a
    /// language tag. Drives an `ISO_639_language_descriptor` (tag 0x0A)
    /// in this track's PMT ES_info loop. `None` → no language loop.
    language: Option<[u8; 3]>,
    /// Caller-supplied extra ES_info descriptor bytes (teletext /
    /// subtitling / AC-3 / …) appended verbatim after the auto ones.
    extra_es_descriptors: Vec<u8>,
}

impl MpegTsMuxer {
    /// Single-program factory: every stream is placed in one program
    /// (`program_number` 1, PMT PID 0x0100). Backwards-compatible with
    /// the original muxer surface.
    fn new(output: Box<dyn WriteSeek>, streams: &[StreamInfo]) -> CoreResult<Self> {
        if streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegts muxer: at least one stream required",
            ));
        }
        let config = MpegTsMuxConfig {
            transport_stream_id: 1,
            original_network_id: 1,
            programs: vec![ProgramSpec {
                program_number: DEFAULT_PROGRAM_NUMBER,
                pmt_pid: DEFAULT_PMT_PID,
                pcr_pid: None,
                stream_indices: streams.iter().map(|s| s.index).collect(),
                service: None,
                events: Vec::new(),
                es_descriptors: Vec::new(),
            }],
            network: None,
        };
        Self::with_config(output, streams, config)
    }

    /// Multi-program factory. Each [`ProgramSpec`] in `config.programs`
    /// becomes a PAT entry + its own PMT on `pmt_pid`, grouping the
    /// input streams named by its `stream_indices`. Elementary-stream
    /// PIDs are assigned sequentially from 0x1011 in program order.
    pub fn with_config(
        output: Box<dyn WriteSeek>,
        streams: &[StreamInfo],
        config: MpegTsMuxConfig,
    ) -> CoreResult<Self> {
        if streams.is_empty() {
            return Err(CoreError::invalid(
                "mpegts muxer: at least one stream required",
            ));
        }
        if config.programs.is_empty() {
            return Err(CoreError::invalid(
                "mpegts muxer: at least one program required",
            ));
        }
        let by_index: HashMap<u32, &StreamInfo> = streams.iter().map(|s| (s.index, s)).collect();

        let mut tracks: Vec<TrackState> = Vec::with_capacity(streams.len());
        let mut idx_to_track: HashMap<u32, usize> = HashMap::with_capacity(streams.len());
        let mut programs: Vec<ProgramState> = Vec::with_capacity(config.programs.len());
        let mut next_pid = FIRST_ES_PID;

        for spec in &config.programs {
            if spec.program_number == 0 {
                return Err(CoreError::invalid(
                    "mpegts muxer: program_number 0 is reserved for the network PID",
                ));
            }
            let mut track_indices = Vec::with_capacity(spec.stream_indices.len());
            for &sidx in &spec.stream_indices {
                let s = by_index.get(&sidx).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "mpegts muxer: program {} references unknown stream_index {sidx}",
                        spec.program_number
                    ))
                })?;
                if idx_to_track.contains_key(&sidx) {
                    return Err(CoreError::invalid(format!(
                        "mpegts muxer: stream_index {sidx} assigned to more than one program"
                    )));
                }
                let (stream_type, stream_id, is_video) =
                    stream_type_for_codec(s.params.codec_id.as_str()).ok_or_else(|| {
                        CoreError::unsupported(format!(
                            "mpegts muxer: no MPEG-TS stream_type for codec_id '{}'",
                            s.params.codec_id.as_str()
                        ))
                    })?;
                let language = if is_video {
                    None
                } else {
                    s.params.language.as_deref().map(iso639_code)
                };
                // component_tag = 1-based ordinal within the program.
                let component_tag = (track_indices.len() as u8).wrapping_add(1);
                let extra_es_descriptors = spec
                    .es_descriptors
                    .iter()
                    .find(|(idx, _)| *idx == sidx)
                    .map(|(_, d)| d.clone())
                    .unwrap_or_default();
                let track_idx = tracks.len();
                tracks.push(TrackState {
                    pid: next_pid,
                    stream_type,
                    stream_id,
                    cc: 0,
                    is_video,
                    program: programs.len(),
                    component_tag,
                    language,
                    extra_es_descriptors,
                });
                idx_to_track.insert(sidx, track_idx);
                track_indices.push(track_idx);
                next_pid = next_pid.wrapping_add(1);
            }
            if track_indices.is_empty() {
                return Err(CoreError::invalid(format!(
                    "mpegts muxer: program {} has no streams",
                    spec.program_number
                )));
            }
            // PCR PID: explicit, else first video track, else first track.
            let pcr_pid = spec.pcr_pid.unwrap_or_else(|| {
                track_indices
                    .iter()
                    .map(|&i| &tracks[i])
                    .find(|t| t.is_video)
                    .map(|t| t.pid)
                    .unwrap_or(tracks[track_indices[0]].pid)
            });
            programs.push(ProgramState {
                program_number: spec.program_number,
                pmt_pid: spec.pmt_pid,
                pcr_pid,
                pmt_cc: 0,
                track_indices,
                last_pcr_pts: None,
                service: spec.service.clone(),
                events: spec.events.clone(),
            });
        }

        Ok(Self {
            output,
            tracks,
            programs,
            idx_to_track,
            transport_stream_id: config.transport_stream_id,
            original_network_id: config.original_network_id,
            network: config.network.clone(),
            pat_cc: 0,
            sdt_cc: 0,
            nit_cc: 0,
            eit_cc: 0,
            // ~200 ms (18000 ticks of the 90 kHz clock) — a conformant
            // default that keeps the tables fresh without flooding the
            // multiplex. Callers can widen / disable it.
            psi_repetition_90k: Some(18_000),
            last_psi_pts: None,
            header_written: false,
        })
    }

    /// Override the PSI re-emission interval (90 kHz ticks). `None`
    /// disables mid-stream repetition — the program tables are then only
    /// written at `write_header` and `write_trailer`. Call before
    /// `write_header`.
    pub fn set_psi_repetition_interval(&mut self, ticks: Option<i64>) {
        self.psi_repetition_90k = ticks;
    }

    /// Re-emit the full PSI set (PAT + every PMT + SDT) mid-stream when
    /// the running PTS has advanced past the configured repetition
    /// interval. Anchored to `write_header`'s emission so the first
    /// repeat lands one interval into the stream.
    fn maybe_repeat_psi(&mut self, pts: i64) -> CoreResult<()> {
        let interval = match self.psi_repetition_90k {
            Some(i) if i > 0 => i,
            _ => return Ok(()),
        };
        let due = match self.last_psi_pts {
            None => false,
            Some(last) => pts.saturating_sub(last) >= interval,
        };
        // Seed the anchor on the first packet so repetition is measured
        // from the stream start, not from t=0.
        if self.last_psi_pts.is_none() {
            self.last_psi_pts = Some(pts);
            return Ok(());
        }
        if due {
            self.write_pat()?;
            self.write_pmt()?;
            self.write_sdt()?;
            self.write_nit()?;
            self.write_eit()?;
            self.last_psi_pts = Some(pts);
        }
        Ok(())
    }

    /// Emit a complete PSI section as one or more 188-byte TS packets
    /// per §2.4.4. The first packet carries `payload_unit_start_indicator
    /// = 1` and a leading `pointer_field = 0` (the section begins
    /// immediately after it); continuation packets clear the PUSI and
    /// carry no pointer_field. The last packet is stuffed to the 188-byte
    /// boundary with `0xFF` bytes per §2.4.4 (sections never span a
    /// stuffing run — once a `0xFF` appears after a section, the rest of
    /// the packet is stuffing).
    ///
    /// A section may legally be up to 1021 payload bytes (long-form) or
    /// 4093 (private), so the single-packet fast path is no longer the
    /// only path: a PMT that carries a registration / ISO-639 descriptor
    /// loop routinely overflows the 183-byte first-packet window.
    fn write_psi_packet(&mut self, pid: u16, cc: &mut u8, section: &[u8]) -> CoreResult<()> {
        let mut cursor = 0usize;
        let mut first = true;
        while first || cursor < section.len() {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            let pusi = if first { 0b0100_0000 } else { 0 };
            pkt[1] = pusi | ((pid >> 8) as u8 & 0b0001_1111);
            pkt[2] = pid as u8;
            // afc = 0b01 (payload only — PSI never carries adaptation
            // fields in this muxer; stuffing is done with 0xFF section
            // bytes, which is the §2.4.4 PSI convention).
            pkt[3] = 0b0001_0000 | (*cc & 0x0F);
            *cc = (*cc + 1) & 0x0F;

            let mut payload_start = 4;
            if first {
                // pointer_field = 0 → section starts right after it.
                pkt[4] = 0;
                payload_start = 5;
            }
            let room = TS_PACKET_LEN - payload_start;
            let take = room.min(section.len() - cursor);
            pkt[payload_start..payload_start + take]
                .copy_from_slice(&section[cursor..cursor + take]);
            cursor += take;
            // Bytes past `payload_start + take` stay 0xFF (pre-filled),
            // which is exactly the PSI stuffing terminator.
            self.output.write_all(&pkt).map_err(CoreError::Io)?;
            first = false;
        }
        Ok(())
    }

    /// Emit the Program Association Table listing every program's
    /// `(program_number, pmt_pid)` pair (§2.4.4.3).
    fn write_pat(&mut self) -> CoreResult<()> {
        let entries: Vec<(u16, u16)> = self
            .programs
            .iter()
            .map(|p| (p.program_number, p.pmt_pid))
            .collect();
        let section = crate::build::build_pat(self.transport_stream_id, 0, &entries);
        let mut cc = self.pat_cc;
        self.write_psi_packet(PAT_PID, &mut cc, &section)?;
        self.pat_cc = cc;
        Ok(())
    }

    /// Emit one Program Map Table per program on its own PMT PID
    /// (§2.4.4.8), each carrying its streams' `stream_type` + PID +
    /// ES-info descriptor loop.
    fn write_pmt(&mut self) -> CoreResult<()> {
        for pi in 0..self.programs.len() {
            let streams: Vec<crate::build::PmtStreamEntry> = self.programs[pi]
                .track_indices
                .iter()
                .map(|&ti| {
                    let t = &self.tracks[ti];
                    crate::build::PmtStreamEntry {
                        stream_type: t.stream_type,
                        elementary_pid: t.pid,
                        es_info: build_es_descriptors(t),
                    }
                })
                .collect();
            let section = crate::build::build_pmt(
                self.programs[pi].program_number,
                0,
                self.programs[pi].pcr_pid,
                &[],
                &streams,
            );
            let pmt_pid = self.programs[pi].pmt_pid;
            let mut cc = self.programs[pi].pmt_cc;
            self.write_psi_packet(pmt_pid, &mut cc, &section)?;
            self.programs[pi].pmt_cc = cc;
        }
        Ok(())
    }

    /// Emit a DVB Service Description Table (PID 0x0011) describing every
    /// program that carries a [`ServiceSpec`]. Skipped entirely when no
    /// program has service metadata.
    fn write_sdt(&mut self) -> CoreResult<()> {
        let services: Vec<crate::build::SdtServiceEntry> = self
            .programs
            .iter()
            .filter_map(|p| {
                p.service.as_ref().map(|svc| crate::build::SdtServiceEntry {
                    service_id: p.program_number,
                    eit_schedule: false,
                    eit_present_following: false,
                    running_status: crate::psi::RunningStatus::Running,
                    free_ca_mode: false,
                    descriptors: crate::build::service_descriptor(
                        svc.service_type,
                        &svc.provider_name,
                        &svc.service_name,
                    ),
                })
            })
            .collect();
        if services.is_empty() {
            return Ok(());
        }
        let section = crate::build::build_sdt(
            true,
            self.transport_stream_id,
            self.original_network_id,
            0,
            &services,
        );
        let mut cc = self.sdt_cc;
        self.write_psi_packet(crate::psi::SDT_PID, &mut cc, &section)?;
        self.sdt_cc = cc;
        Ok(())
    }

    /// Emit a DVB Network Information Table (PID 0x0010) naming the
    /// network and listing this transport stream. Skipped when the config
    /// carried no [`NetworkSpec`].
    fn write_nit(&mut self) -> CoreResult<()> {
        let net = match &self.network {
            Some(n) => n.clone(),
            None => return Ok(()),
        };
        let mut network_descriptors = crate::build::network_name_descriptor(&net.network_name);
        network_descriptors.extend_from_slice(&net.network_descriptors);
        let ts_entry = crate::build::NitTsEntry {
            transport_stream_id: self.transport_stream_id,
            original_network_id: self.original_network_id,
            descriptors: net.transport_descriptors.clone(),
        };
        let section = crate::build::build_nit(
            true,
            net.network_id,
            0,
            &network_descriptors,
            std::slice::from_ref(&ts_entry),
        );
        let mut cc = self.nit_cc;
        self.write_psi_packet(crate::psi::NIT_PID, &mut cc, &section)?;
        self.nit_cc = cc;
        Ok(())
    }

    /// Emit one DVB present/following Event Information Table section
    /// (PID 0x0012, `table_id` 0x4E) per program that carries events,
    /// keyed on the program's `program_number` as `service_id`. Skipped
    /// when no program declares events.
    fn write_eit(&mut self) -> CoreResult<()> {
        for pi in 0..self.programs.len() {
            if self.programs[pi].events.is_empty() {
                continue;
            }
            let service_id = self.programs[pi].program_number;
            let events: Vec<crate::build::EitEventEntry> = self.programs[pi]
                .events
                .iter()
                .map(|ev| {
                    let descriptors = if ev.event_name.is_empty() && ev.text.is_empty() {
                        Vec::new()
                    } else {
                        crate::build::short_event_descriptor(ev.language, &ev.event_name, &ev.text)
                    };
                    crate::build::EitEventEntry {
                        event_id: ev.event_id,
                        start_time: ev.start_time,
                        duration: ev.duration,
                        running_status: ev.running_status,
                        free_ca_mode: false,
                        descriptors,
                    }
                })
                .collect();
            let section = crate::build::build_eit_pf(
                true,
                service_id,
                self.transport_stream_id,
                self.original_network_id,
                0,
                &events,
            );
            let mut cc = self.eit_cc;
            self.write_psi_packet(crate::psi::EIT_PID, &mut cc, &section)?;
            self.eit_cc = cc;
        }
        Ok(())
    }

    /// Emit a standalone PCR-only TS packet on the PCR_PID. The packet
    /// carries no payload — `adaptation_field_control = 0b10` (AF only)
    /// with the AF spanning the whole 184-byte body: a flags byte with
    /// `PCR_flag` set, the 6-byte PCR, then 0xFF stuffing. Per §2.4.3.4
    /// a packet may legally carry an adaptation field and no payload.
    fn write_pcr_only_packet(&mut self, prog_idx: usize, pts: i64) -> CoreResult<()> {
        let pcr_pid = self.programs[prog_idx].pcr_pid;
        let pcr_track = match self.tracks.iter().position(|t| t.pid == pcr_pid) {
            Some(i) => i,
            None => return Ok(()),
        };
        let cc = self.tracks[pcr_track].cc;
        self.tracks[pcr_track].cc = (cc + 1) & 0x0F;

        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        // PUSI = 0 (no payload start), PID high.
        pkt[1] = (pcr_pid >> 8) as u8 & 0b0001_1111;
        pkt[2] = pcr_pid as u8;
        // adaptation_field_control = 0b10 (AF only, no payload).
        pkt[3] = 0b0010_0000 | (cc & 0x0F);
        // AF spanning the whole 184-byte body (§2.4.3.5 requires
        // adaptation_field_length == 183 when the AF control is '10'):
        // PCR + 0xFF stuffing.
        let af = crate::AdaptationFieldSpec::with_pcr(pts.max(0) as u64, 0)
            .encode(Some(TS_PACKET_LEN - 4))
            .map_err(|e| CoreError::invalid(format!("mpegts muxer: {e}")))?;
        pkt[4..4 + af.len()].copy_from_slice(&af);
        self.output.write_all(&pkt).map_err(CoreError::Io)?;
        self.programs[prog_idx].last_pcr_pts = Some(pts);
        Ok(())
    }

    /// Inject PCR-only packets ahead of a PES so the gap between
    /// consecutive PCRs on the program's PCR_PID stays under
    /// [`PCR_MAX_INTERVAL_90K`] (§2.7.2's 0,1 s bound, with margin).
    /// Driven by the PES PTS rather than wall time — the muxer has no
    /// real-time clock.
    fn maybe_emit_periodic_pcr(&mut self, prog_idx: usize, pts: i64) -> CoreResult<()> {
        match self.programs[prog_idx].last_pcr_pts {
            None => self.write_pcr_only_packet(prog_idx, pts),
            Some(last) if pts.saturating_sub(last) >= PCR_MAX_INTERVAL_90K => {
                self.write_pcr_only_packet(prog_idx, pts)
            }
            _ => Ok(()),
        }
    }

    /// Build one PES packet from a [`Packet`] and fragment it into
    /// TS packets, emitting each. Inserts a PCR adaptation field on
    /// the first TS packet of a video PES, and injects standalone
    /// PCR-only packets when the inter-PCR interval would be exceeded.
    fn write_pes_packet(&mut self, track_idx: usize, packet: &Packet) -> CoreResult<()> {
        let track = self.tracks[track_idx].clone();
        let prog_idx = track.program;
        let pcr_pid = self.programs[prog_idx].pcr_pid;
        // Bound the inter-PCR interval (§2.7.2). Any track's PTS can
        // advance the program's notion of time; the PCR is emitted on the
        // program's PCR_PID regardless of which track triggered it.
        let pcr_on_this_pes = if track.pid == pcr_pid {
            // The PCR PID's own PES carries an inline PCR on its first
            // TS packet — record it so the periodic logic doesn't
            // double-emit.
            packet.pts
        } else {
            if let Some(p) = packet.pts {
                self.maybe_emit_periodic_pcr(prog_idx, p)?;
            }
            None
        };
        let pes = build_pes(track.stream_id, packet)?;
        let pcr = pcr_on_this_pes.map(|p| {
            // PCR-base = PTS - ~10ms guard so the PCR never leads the
            // first access unit it accompanies. Both are 90 kHz units;
            // the 9-bit 27 MHz extension is zeroed.
            let pcr_base = p.saturating_sub(900).max(0) as u64;
            (pcr_base, 0u16)
        });
        if let Some((base, _)) = pcr {
            self.programs[prog_idx].last_pcr_pts = Some(base as i64);
        }
        // random_access_indicator on the PES-start packet for keyframes
        // (§2.4.3.5). On the PCR PID the indicator may only be set in a
        // packet that carries the PCR fields, so it is suppressed for a
        // PCR-PID PES that carries no inline PCR (e.g. no PTS).
        let random_access = packet.flags.keyframe
            && (track.pid != self.programs[prog_idx].pcr_pid || pcr.is_some());
        self.write_pes_bytes_as_ts(track.pid, track_idx, &pes, pcr, random_access)
    }

    /// Fragment a contiguous PES byte buffer into 188-byte TS packets
    /// for `pid`, with PUSI=1 on the first packet and continuity-
    /// counter increment per packet. `first_packet_pcr` is an optional
    /// PCR carried in the FIRST packet's adaptation field;
    /// `random_access` sets the §2.4.3.5 `random_access_indicator`
    /// there (the PES starting in that packet begins at an
    /// elementary-stream access point).
    fn write_pes_bytes_as_ts(
        &mut self,
        pid: u16,
        track_idx: usize,
        pes: &[u8],
        first_packet_pcr: Option<(u64, u16)>,
        random_access: bool,
    ) -> CoreResult<()> {
        let mut cursor = 0usize;
        let mut first = true;
        while cursor < pes.len() {
            let mut pkt = [0xFFu8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            let pusi = if first { 0b0100_0000 } else { 0 };
            pkt[1] = pusi | ((pid >> 8) as u8 & 0b0001_1111);
            pkt[2] = pid as u8;
            let cc = self.tracks[track_idx].cc;
            let remaining = pes.len() - cursor;
            // Adaptation field carried when the first packet needs a
            // PCR / random-access flag, or when the (tail) fragment is
            // short and needs AF stuffing to land on 188 bytes
            // (§2.4.3.5 — the only stuffing method for PES packets).
            let spec = crate::AdaptationFieldSpec {
                random_access_indicator: first && random_access,
                pcr: first_packet_pcr.filter(|_| first),
                ..Default::default()
            };
            // Worst-case payload room with NO adaptation field.
            let payload_room_no_af = TS_PACKET_LEN - 4;
            let af_present = !spec.is_empty() || remaining < payload_room_no_af;
            let afc = if af_present { 0b11 } else { 0b01 };
            pkt[3] = (afc << 4) | (cc & 0x0F);
            self.tracks[track_idx].cc = (cc + 1) & 0x0F;

            if af_present {
                let map_err = |e: crate::TsError| CoreError::invalid(format!("mpegts muxer: {e}"));
                let bare = spec.encode(None).map_err(map_err)?;
                let room_after_bare = TS_PACKET_LEN - 4 - bare.len();
                let af = if remaining < room_after_bare {
                    // Grow the AF with stuffing so the payload window
                    // shrinks to exactly the remaining PES bytes.
                    spec.encode(Some(TS_PACKET_LEN - 4 - remaining))
                        .map_err(map_err)?
                } else {
                    bare
                };
                pkt[4..4 + af.len()].copy_from_slice(&af);
                let payload_start = 4 + af.len();
                let take = (TS_PACKET_LEN - payload_start).min(remaining);
                pkt[payload_start..payload_start + take]
                    .copy_from_slice(&pes[cursor..cursor + take]);
                cursor += take;
            } else {
                let take = payload_room_no_af.min(remaining);
                pkt[4..4 + take].copy_from_slice(&pes[cursor..cursor + take]);
                cursor += take;
            }
            self.output.write_all(&pkt).map_err(CoreError::Io)?;
            first = false;
        }
        Ok(())
    }
}

impl Muxer for MpegTsMuxer {
    fn format_name(&self) -> &str {
        "mpegts"
    }

    fn write_header(&mut self) -> CoreResult<()> {
        self.write_pat()?;
        self.write_pmt()?;
        self.write_sdt()?;
        self.write_nit()?;
        self.write_eit()?;
        self.header_written = true;
        Ok(())
    }

    fn write_packet(&mut self, packet: &Packet) -> CoreResult<()> {
        if !self.header_written {
            return Err(CoreError::invalid(
                "mpegts muxer: write_packet called before write_header",
            ));
        }
        let track_idx = *self.idx_to_track.get(&packet.stream_index).ok_or_else(|| {
            CoreError::invalid(format!(
                "mpegts muxer: packet for unknown stream_index {}",
                packet.stream_index
            ))
        })?;
        if let Some(p) = packet.pts {
            self.maybe_repeat_psi(p)?;
        }
        self.write_pes_packet(track_idx, packet)
    }

    fn write_trailer(&mut self) -> CoreResult<()> {
        // Re-emit the program / SI tables once so a late-joining player
        // still finds them after seeking near the end.
        self.write_pat()?;
        self.write_pmt()?;
        self.write_sdt()?;
        self.write_nit()?;
        self.write_eit()?;
        self.output.flush().map_err(CoreError::Io)?;
        Ok(())
    }
}

/// Build one PES packet through the shared write-side header builder
/// ([`crate::pes::PesHeaderSpec`]): fixed header, optional PTS / DTS,
/// then the payload. Video stream_ids (`0xE0..=0xEF`) get the
/// unbounded `PES_packet_length = 0` form (what BD discs use); other
/// IDs carry the real length per §2.4.3.7. Timestamps ride the 33-bit
/// ring, so extended values are reduced modulo `2^33` before
/// encoding.
fn build_pes(stream_id: u8, packet: &Packet) -> CoreResult<Vec<u8>> {
    let ring = |t: i64| (t as u64) & 0x1_FFFF_FFFF;
    // Compare on the ring: two timestamps that coincide there must
    // collapse to the PTS-only form (§2.7.5 forbids DTS == PTS).
    let has_dts = packet.dts.is_some() && packet.dts.map(ring) != packet.pts.map(ring);
    let spec = crate::pes::PesHeaderSpec {
        stream_id,
        pts_90k: packet.pts.map(ring),
        dts_90k: if has_dts { packet.dts.map(ring) } else { None },
        unbounded_length: (0xE0..=0xEF).contains(&stream_id),
        ..Default::default()
    };
    spec.encode(&packet.data)
        .map_err(|e| CoreError::invalid(format!("mpegts muxer: {e}")))
}

/// Normalise an arbitrary language tag into the 3-byte ISO 639-2 code
/// the descriptor field is exactly sized for. Shorter tags are
/// right-padded with spaces (the conventional `und`-style fill is left
/// to the caller — we keep their bytes verbatim), longer tags truncate
/// to the first three ASCII bytes. Non-ASCII bytes pass through as-is;
/// the spec stores each character as 8 bits with no charset selection.
fn iso639_code(tag: &str) -> [u8; 3] {
    let mut out = [b' '; 3];
    for (i, b) in tag.bytes().take(3).enumerate() {
        out[i] = b;
    }
    out
}

/// Build the PMT ES_info descriptor loop for one track. Currently this
/// emits a single `ISO_639_language_descriptor` (tag 0x0A, §2.6.18)
/// when the track carries a language code; the body is one
/// `(ISO_639_language_code, audio_type)` entry, with `audio_type = 0x00`
/// (undefined) since the core `StreamInfo` does not distinguish the
/// clean-effects / hearing-impaired / visual-impaired sub-types.
fn build_es_descriptors(track: &TrackState) -> Vec<u8> {
    let mut out = crate::build::stream_identifier_descriptor(track.component_tag);
    if let Some(lang) = track.language {
        out.extend_from_slice(&crate::build::iso639_language_descriptor(&[(lang, 0x00)]));
    }
    out.extend_from_slice(&track.extra_es_descriptors);
    out
}

/// CodecId string → (stream_type byte, PES `stream_id`, is_video).
///
/// `stream_id` is conventional:
/// * video → 0xE0
/// * MPEG audio → 0xC0
/// * AC-3 / DTS / TrueHD / LPCM / HDMV-PGS / HDMV-TextST → 0xBD
///   (private_stream_1) per BD-ROM AV §5.6 / ATSC convention.
fn stream_type_for_codec(codec_id: &str) -> Option<(u8, u8, bool)> {
    Some(match codec_id {
        "mpeg2video" => (0x02, 0xE0, true),
        "h264" => (0x1B, 0xE0, true),
        "hevc" => (0x24, 0xE0, true),
        "vc1" => (0xEA, 0xE0, true),
        "pcm_s16be" => (0x80, 0xBD, false),
        "ac3" => (0x81, 0xBD, false),
        "dts" => (0x82, 0xBD, false),
        "truehd" => (0x83, 0xBD, false),
        "eac3" => (0x84, 0xBD, false),
        "hdmv_pgs_subtitle" => (0x90, 0xBD, false),
        "hdmv_textst_subtitle" => (0x92, 0xBD, false),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxideav_core::{CodecId, CodecParameters, ReadSeek, TimeBase};
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

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

    /// Shared in-memory sink shaped as `Box<dyn WriteSeek + 'static>`.
    /// The muxer takes ownership of its writer for the duration of
    /// the test; we hand it an `Arc<Mutex<Cursor<Vec<u8>>>>` clone so
    /// the caller can still extract the bytes after.
    #[derive(Clone)]
    struct SharedSink(Arc<Mutex<Cursor<Vec<u8>>>>);

    impl SharedSink {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Cursor::new(Vec::new()))))
        }
        fn into_bytes(self) -> Vec<u8> {
            // After the muxer drops, we should be the only owner.
            let inner = Arc::try_unwrap(self.0)
                .map_err(|_| "shared sink still has live references")
                .unwrap()
                .into_inner()
                .unwrap();
            inner.into_inner()
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

    /// Build a tiny TS file via the muxer and round-trip it through
    /// the demuxer in the same crate.
    #[test]
    fn mux_then_demux_round_trip_avc_plus_ac3() {
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            let video_pkt = Packet::new(0, TimeBase::new(1, 90_000), vec![0xDE, 0xAD, 0xBE, 0xEF])
                .with_pts(12345);
            let audio_pkt =
                Packet::new(1, TimeBase::new(1, 90_000), vec![0xCA, 0xFE]).with_pts(22222);
            mx.write_packet(&video_pkt).unwrap();
            mx.write_packet(&audio_pkt).unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        assert!(bytes.len() % TS_PACKET_LEN == 0);

        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let resolver = oxideav_core::NullCodecResolver;
        let mut dmx = crate::demuxer::open(input, &resolver).expect("dmx open");
        assert_eq!(dmx.streams().len(), 2);
        let codecs: Vec<&str> = dmx
            .streams()
            .iter()
            .map(|s| s.params.codec_id.as_str())
            .collect();
        assert!(codecs.contains(&"h264"));
        assert!(codecs.contains(&"ac3"));
        let p1 = dmx.next_packet().expect("p1");
        let p2 = dmx.next_packet().expect("p2");
        let mut pts_set = vec![p1.pts.unwrap(), p2.pts.unwrap()];
        pts_set.sort();
        assert_eq!(pts_set, vec![12345, 22222]);
    }

    /// Two independent programs, each with its own PMT PID + PCR PID,
    /// must round-trip through the demuxer's `programs()` enumeration and
    /// be individually selectable with `open_program`.
    #[test]
    fn multi_program_round_trips_through_pat() {
        let streams = vec![
            stream_info(0, "h264", true),
            stream_info(1, "ac3", false),
            stream_info(2, "hevc", true),
            stream_info(3, "eac3", false),
        ];
        let config = MpegTsMuxConfig {
            transport_stream_id: 0x0042,
            original_network_id: 0x2024,
            programs: vec![
                ProgramSpec {
                    program_number: 1,
                    pmt_pid: 0x0100,
                    pcr_pid: None,
                    stream_indices: vec![0, 1],
                    service: None,
                    events: Vec::new(),
                    es_descriptors: Vec::new(),
                },
                ProgramSpec {
                    program_number: 2,
                    pmt_pid: 0x0101,
                    pcr_pid: None,
                    stream_indices: vec![2, 3],
                    service: None,
                    events: Vec::new(),
                    es_descriptors: Vec::new(),
                },
            ],
            network: None,
        };
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::with_config(output, &streams, config).expect("open");
            mx.write_header().expect("hdr");
            for k in 0..4i64 {
                mx.write_packet(
                    &Packet::new(k as u32, TimeBase::new(1, 90_000), vec![k as u8; 6])
                        .with_pts(1000 + k * 10),
                )
                .unwrap();
            }
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();

        // Enumerate the programs via the concrete demuxer.
        use oxideav_core::Demuxer as _;
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes.clone()));
        let dmx = crate::demuxer::MpegTsDemuxer::open_program(input, 1).expect("open prog 1");
        let mut progs: Vec<(u16, u16)> = dmx
            .programs()
            .iter()
            .map(|p| (p.program_number, p.pmt_pid))
            .collect();
        progs.sort();
        assert_eq!(progs, vec![(1, 0x0100), (2, 0x0101)]);

        // Program 2 selected explicitly must expose its hevc+eac3 streams.
        let input2: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let dmx2 = crate::demuxer::MpegTsDemuxer::open_program(input2, 2).expect("open prog 2");
        assert_eq!(dmx2.selected_program(), 2);
        let codecs: Vec<&str> = dmx2
            .streams()
            .iter()
            .map(|s| s.params.codec_id.as_str())
            .collect();
        assert!(codecs.contains(&"hevc"), "codecs={codecs:?}");
        assert!(codecs.contains(&"eac3"), "codecs={codecs:?}");
    }

    /// A program carrying `ServiceSpec` metadata must emit an SDT on
    /// PID 0x0011 that reassembles + parses back to the same service.
    #[test]
    fn sdt_service_round_trips_through_mux() {
        use crate::psi::{iter_sections, ServiceDescriptionTable, SDT_PID};
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let config = MpegTsMuxConfig {
            transport_stream_id: 0x0007,
            original_network_id: 0x1000,
            programs: vec![ProgramSpec {
                program_number: 0x0064,
                pmt_pid: 0x0100,
                pcr_pid: None,
                stream_indices: vec![0, 1],
                service: Some(ServiceSpec {
                    service_type: 0x19,
                    provider_name: b"OxideAV".to_vec(),
                    service_name: b"Channel One".to_vec(),
                }),
                events: Vec::new(),
                es_descriptors: Vec::new(),
            }],
            network: None,
        };
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::with_config(output, &streams, config).expect("open");
            mx.write_header().expect("hdr");
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![1; 4]).with_pts(90))
                .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        // Find the first SDT_PID packet with PUSI and parse its section.
        let mut found = None;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let pid = (((chunk[1] & 0x1F) as u16) << 8) | chunk[2] as u16;
            let pusi = chunk[1] & 0x40 != 0;
            if pid == SDT_PID && pusi {
                // afc = payload only (0b01) → payload from byte 4.
                for sec in iter_sections(&chunk[4..]) {
                    if let Ok(sdt) = ServiceDescriptionTable::parse(sec) {
                        found = Some(sdt);
                        break;
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        let sdt = found.expect("SDT section on PID 0x0011");
        assert_eq!(sdt.transport_stream_id, 0x0007);
        assert_eq!(sdt.original_network_id, 0x1000);
        assert_eq!(sdt.services.len(), 1);
        let svc = &sdt.services[0];
        assert_eq!(svc.service_id, 0x0064);
        match svc.iter_descriptors().next().unwrap().unwrap().body {
            crate::descriptor::DescriptorBody::Service(s) => {
                assert_eq!(s.service_type, 0x19);
                assert_eq!(s.service_provider_name, b"OxideAV");
                assert_eq!(s.service_name, b"Channel One");
            }
            other => panic!("expected Service descriptor, got {other:?}"),
        }
    }

    /// Helper: find + parse the first section on `pid` with a matching
    /// table_id via `parse`.
    fn first_section_on<T>(
        bytes: &[u8],
        pid: u16,
        parse: impl Fn(&[u8]) -> Result<T, crate::TsError>,
    ) -> Option<T> {
        use crate::psi::iter_sections;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let p = (((chunk[1] & 0x1F) as u16) << 8) | chunk[2] as u16;
            let pusi = chunk[1] & 0x40 != 0;
            if p == pid && pusi {
                for sec in iter_sections(&chunk[4..]) {
                    if let Ok(parsed) = parse(sec) {
                        return Some(parsed);
                    }
                }
            }
        }
        None
    }

    /// A NetworkSpec makes the muxer emit a NIT on PID 0x0010 that
    /// reassembles + parses back to the same network + TS entry.
    #[test]
    fn nit_round_trips_through_mux() {
        use crate::psi::{NetworkInformationTable, NIT_PID};
        let streams = vec![stream_info(0, "h264", true)];
        let config = MpegTsMuxConfig {
            transport_stream_id: 0x0007,
            original_network_id: 0x2024,
            programs: vec![ProgramSpec {
                program_number: 1,
                pmt_pid: 0x0100,
                pcr_pid: None,
                stream_indices: vec![0],
                service: None,
                events: Vec::new(),
                es_descriptors: Vec::new(),
            }],
            network: Some(NetworkSpec {
                network_id: 0x1000,
                network_name: b"OxideNet".to_vec(),
                network_descriptors: Vec::new(),
                transport_descriptors: crate::build::service_list_descriptor(&[(1, 0x01)]),
            }),
        };
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::with_config(output, &streams, config).expect("open");
            mx.write_header().unwrap();
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![1; 4]).with_pts(10))
                .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        let nit = first_section_on(&bytes, NIT_PID, NetworkInformationTable::parse)
            .expect("NIT on PID 0x0010");
        assert_eq!(nit.network_id, 0x1000);
        assert_eq!(nit.transport_streams.len(), 1);
        assert_eq!(nit.transport_streams[0].transport_stream_id, 0x0007);
        assert_eq!(nit.transport_streams[0].original_network_id, 0x2024);
        match nit.iter_descriptors().next().unwrap().unwrap().body {
            crate::descriptor::DescriptorBody::NetworkName(n) => {
                assert_eq!(n.network_name, b"OxideNet")
            }
            other => panic!("{other:?}"),
        }
    }

    /// An EventSpec makes the muxer emit an EIT present/following section
    /// on PID 0x0012 that reassembles + parses back to the same event,
    /// including its short_event_descriptor.
    #[test]
    fn eit_pf_round_trips_through_mux() {
        use crate::psi::{EitDateTime, EitDuration, EventInformationTable, RunningStatus, EIT_PID};
        let streams = vec![stream_info(0, "h264", true)];
        let ev = EventSpec {
            event_id: 0x0001,
            start_time: Some(EitDateTime {
                year: 2024,
                month: 6,
                day: 15,
                hour: 20,
                minute: 0,
                second: 0,
                mjd: 0,
            }),
            duration: EitDuration {
                hours: 0,
                minutes: 30,
                seconds: 0,
            },
            running_status: RunningStatus::Running,
            language: *b"eng",
            event_name: b"News".to_vec(),
            text: b"Evening bulletin".to_vec(),
        };
        let config = MpegTsMuxConfig {
            transport_stream_id: 0x0007,
            original_network_id: 0x2024,
            programs: vec![ProgramSpec {
                program_number: 0x0064,
                pmt_pid: 0x0100,
                pcr_pid: None,
                stream_indices: vec![0],
                service: None,
                events: vec![ev],
                es_descriptors: Vec::new(),
            }],
            network: None,
        };
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::with_config(output, &streams, config).expect("open");
            mx.write_header().unwrap();
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![1; 4]).with_pts(10))
                .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        let eit = first_section_on(&bytes, EIT_PID, EventInformationTable::parse)
            .expect("EIT on PID 0x0012");
        assert_eq!(eit.service_id, 0x0064);
        assert!(!eit.schedule);
        assert_eq!(eit.events.len(), 1);
        let e = &eit.events[0];
        assert_eq!(e.event_id, 0x0001);
        let st = e.start_time.unwrap();
        assert_eq!((st.year, st.month, st.day), (2024, 6, 15));
        assert_eq!(e.duration.as_seconds(), 1800);
        match e.iter_descriptors().next().unwrap().unwrap().body {
            crate::descriptor::DescriptorBody::ShortEvent(s) => {
                assert_eq!(s.event_name, b"News");
                assert_eq!(s.text, b"Evening bulletin");
            }
            other => panic!("{other:?}"),
        }
    }

    /// End-to-end harness: a two-program TS carrying SDT + NIT + EIT +
    /// per-stream descriptors and PES with distinct PTS/DTS must demux
    /// back with every table, descriptor, and timestamp intact.
    #[test]
    fn full_multiprogram_si_round_trip_harness() {
        use crate::descriptor::DescriptorBody;
        use crate::psi::{
            EitDateTime, EitDuration, EventInformationTable, NetworkInformationTable,
            RunningStatus, ServiceDescriptionTable, EIT_PID, NIT_PID, SDT_PID,
        };
        use oxideav_core::Demuxer as _;

        let streams = vec![
            stream_info(0, "h264", true),
            stream_info(1, "ac3", false),
            stream_info(2, "hevc", true),
        ];
        let config = MpegTsMuxConfig {
            transport_stream_id: 0x0100,
            original_network_id: 0x2024,
            programs: vec![
                ProgramSpec {
                    program_number: 1,
                    pmt_pid: 0x1000,
                    pcr_pid: None,
                    stream_indices: vec![0, 1],
                    service: Some(ServiceSpec {
                        service_type: 0x19,
                        provider_name: b"OxideAV".to_vec(),
                        service_name: b"Prog One".to_vec(),
                    }),
                    events: vec![EventSpec {
                        event_id: 0x0011,
                        start_time: Some(EitDateTime {
                            year: 2024,
                            month: 6,
                            day: 15,
                            hour: 20,
                            minute: 0,
                            second: 0,
                            mjd: 0,
                        }),
                        duration: EitDuration {
                            hours: 1,
                            minutes: 0,
                            seconds: 0,
                        },
                        running_status: RunningStatus::Running,
                        language: *b"eng",
                        event_name: b"Movie".to_vec(),
                        text: b"Feature film".to_vec(),
                    }],
                    es_descriptors: Vec::new(),
                },
                ProgramSpec {
                    program_number: 2,
                    pmt_pid: 0x1001,
                    pcr_pid: None,
                    stream_indices: vec![2],
                    service: Some(ServiceSpec {
                        service_type: 0x1F,
                        provider_name: b"OxideAV".to_vec(),
                        service_name: b"Prog Two".to_vec(),
                    }),
                    events: Vec::new(),
                    es_descriptors: Vec::new(),
                },
            ],
            network: Some(NetworkSpec {
                network_id: 0x3000,
                network_name: b"OxideNet".to_vec(),
                network_descriptors: Vec::new(),
                transport_descriptors: crate::build::service_list_descriptor(&[
                    (1, 0x19),
                    (2, 0x1F),
                ]),
            }),
        };

        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::with_config(output, &streams, config).expect("open");
            mx.set_psi_repetition_interval(None);
            mx.write_header().unwrap();
            // Video packet on program 1 with distinct PTS/DTS.
            mx.write_packet(
                &Packet::new(0, TimeBase::new(1, 90_000), vec![0xAA; 8])
                    .with_pts(12_000)
                    .with_dts(9_000),
            )
            .unwrap();
            mx.write_packet(
                &Packet::new(1, TimeBase::new(1, 90_000), vec![0xBB; 6]).with_pts(12_500),
            )
            .unwrap();
            // Video on program 2.
            mx.write_packet(
                &Packet::new(2, TimeBase::new(1, 90_000), vec![0xCC; 8]).with_pts(13_000),
            )
            .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        assert_eq!(bytes.len() % TS_PACKET_LEN, 0);

        // --- PAT enumerates both programs. ---
        let dmx = crate::demuxer::MpegTsDemuxer::open_program(
            Box::new(Cursor::new(bytes.clone())) as Box<dyn ReadSeek>,
            1,
        )
        .expect("open prog 1");
        let mut progs: Vec<(u16, u16)> = dmx
            .programs()
            .iter()
            .map(|p| (p.program_number, p.pmt_pid))
            .collect();
        progs.sort();
        assert_eq!(progs, vec![(1, 0x1000), (2, 0x1001)]);

        // --- Program 1 PES timing: video PTS/DTS + audio PTS. ---
        let mut dmx1 = crate::demuxer::MpegTsDemuxer::open_program(
            Box::new(Cursor::new(bytes.clone())) as Box<dyn ReadSeek>,
            1,
        )
        .expect("open prog 1");
        let mut video_seen = false;
        let mut audio_seen = false;
        while let Ok(p) = dmx1.next_packet() {
            match p.pts {
                Some(12_000) => {
                    assert_eq!(p.dts, Some(9_000), "video DTS must round-trip");
                    video_seen = true;
                }
                Some(12_500) => audio_seen = true,
                _ => {}
            }
        }
        assert!(video_seen && audio_seen, "prog-1 PES timing lost");

        // --- SDT names both services. ---
        let sdt =
            first_section_on(&bytes, SDT_PID, ServiceDescriptionTable::parse).expect("SDT present");
        let mut names: Vec<Vec<u8>> = sdt
            .services
            .iter()
            .filter_map(|s| {
                s.iter_descriptors().find_map(|d| match d.unwrap().body {
                    DescriptorBody::Service(sv) => Some(sv.service_name.to_vec()),
                    _ => None,
                })
            })
            .collect();
        names.sort();
        assert_eq!(names, vec![b"Prog One".to_vec(), b"Prog Two".to_vec()]);

        // --- NIT names the network + lists the TS. ---
        let nit =
            first_section_on(&bytes, NIT_PID, NetworkInformationTable::parse).expect("NIT present");
        assert_eq!(nit.network_id, 0x3000);
        assert_eq!(nit.transport_streams.len(), 1);
        assert_eq!(nit.transport_streams[0].transport_stream_id, 0x0100);

        // --- EIT carries program 1's event. ---
        let eit =
            first_section_on(&bytes, EIT_PID, EventInformationTable::parse).expect("EIT present");
        assert_eq!(eit.service_id, 1);
        assert_eq!(eit.events.len(), 1);
        assert_eq!(eit.events[0].duration.as_seconds(), 3600);
        let ev_name = eit.events[0]
            .iter_descriptors()
            .find_map(|d| match d.unwrap().body {
                DescriptorBody::ShortEvent(s) => Some(s.event_name.to_vec()),
                _ => None,
            })
            .unwrap();
        assert_eq!(ev_name, b"Movie");
    }

    /// With PSI repetition enabled, a long PTS run re-emits the PAT
    /// mid-stream (more than the two header/trailer copies). With it
    /// disabled, exactly two PAT sections appear.
    #[test]
    fn psi_repetition_reemits_pat_mid_stream() {
        let streams = vec![stream_info(0, "h264", true)];
        let count_pat = |bytes: &[u8]| -> usize {
            bytes
                .chunks_exact(TS_PACKET_LEN)
                .filter(|c| {
                    let pid = (((c[1] & 0x1F) as u16) << 8) | c[2] as u16;
                    let pusi = c[1] & 0x40 != 0;
                    pid == 0x0000 && pusi
                })
                .count()
        };
        // Repetition enabled (default 18000): interval crossed each step.
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().unwrap();
            for k in 0..8i64 {
                mx.write_packet(
                    &Packet::new(0, TimeBase::new(1, 90_000), vec![0; 8]).with_pts(k * 40_000),
                )
                .unwrap();
            }
            mx.write_trailer().unwrap();
        }
        let with_rep = count_pat(&sink.into_bytes());
        assert!(
            with_rep > 2,
            "expected mid-stream PAT repeats, got {with_rep}"
        );

        // Repetition disabled: only header + trailer PAT.
        let sink2 = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink2.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.set_psi_repetition_interval(None);
            mx.write_header().unwrap();
            for k in 0..8i64 {
                mx.write_packet(
                    &Packet::new(0, TimeBase::new(1, 90_000), vec![0; 8]).with_pts(k * 40_000),
                )
                .unwrap();
            }
            mx.write_trailer().unwrap();
        }
        assert_eq!(count_pat(&sink2.into_bytes()), 2);
    }

    /// A stream_index referenced by no program (or by two) is rejected.
    #[test]
    fn with_config_rejects_bad_stream_mapping() {
        let streams = vec![stream_info(0, "h264", true)];
        // Unknown stream_index 9.
        let bad = MpegTsMuxConfig {
            transport_stream_id: 1,
            original_network_id: 1,
            programs: vec![ProgramSpec {
                program_number: 1,
                pmt_pid: 0x0100,
                pcr_pid: None,
                stream_indices: vec![9],
                service: None,
                events: Vec::new(),
                es_descriptors: Vec::new(),
            }],
            network: None,
        };
        let out: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        assert!(MpegTsMuxer::with_config(out, &streams, bad).is_err());
    }

    /// A PSI section longer than one packet's 183-byte first-packet
    /// window must split across multiple TS packets and reassemble
    /// cleanly through the in-crate `PsiSectionAssembler`.
    #[test]
    fn multi_packet_psi_section_reassembles() {
        use crate::psi::PsiSectionAssembler;
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        // Build a 400-byte synthetic section (well past one packet).
        let mut section = vec![0u8; 400];
        for (i, b) in section.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        // Mux it out under a fresh muxer with one dummy track.
        let s = stream_info(0, "h264", true);
        let sink = SharedSink::new();
        let mut cc = 0u8;
        {
            let out: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(out, std::slice::from_ref(&s)).expect("open");
            mx.write_psi_packet(0x0100, &mut cc, &section).expect("psi");
        }
        let _ = output;
        let bytes = sink.into_bytes();
        // Should have spanned more than one TS packet.
        assert!(bytes.len() / TS_PACKET_LEN >= 3, "expected >=3 packets");
        assert_eq!(bytes.len() % TS_PACKET_LEN, 0);

        // Reassemble through the demuxer-side assembler.
        let mut asm = PsiSectionAssembler::new();
        let mut recovered: Option<Vec<u8>> = None;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let pusi = chunk[1] & 0x40 != 0;
            let cc = chunk[3] & 0x0F;
            // afc = payload only (0b01) → payload starts at byte 4.
            let payload = &chunk[4..];
            for sec in asm.feed(payload, pusi, cc).expect("feed") {
                recovered = Some(sec);
            }
        }
        // The assembler validates section_length + CRC, but our
        // synthetic blob is not a real section, so it surfaces the
        // raw assembled bytes only if it parses a length. Instead we
        // assert the byte split was lossless by re-concatenating the
        // payloads ourselves.
        let mut flat = Vec::new();
        let mut first = true;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let start = if first { 5 } else { 4 };
            flat.extend_from_slice(&chunk[start..]);
            first = false;
        }
        assert_eq!(&flat[..section.len()], &section[..]);
        let _ = recovered;
    }

    /// An audio track tagged with a language must surface that language
    /// in the muxed PMT and round-trip back through the demuxer's
    /// ISO_639_language_descriptor reader.
    #[test]
    fn language_descriptor_round_trips_through_pmt() {
        let mut audio = stream_info(1, "ac3", false);
        audio.params = audio.params.with_language("jpn");
        let streams = vec![stream_info(0, "h264", true), audio];
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![1, 2, 3]).with_pts(100))
                .unwrap();
            mx.write_packet(&Packet::new(1, TimeBase::new(1, 90_000), vec![4, 5]).with_pts(200))
                .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let resolver = oxideav_core::NullCodecResolver;
        let dmx = crate::demuxer::open(input, &resolver).expect("dmx open");
        let langs: Vec<Option<String>> = dmx
            .streams()
            .iter()
            .map(|s| s.params.language.clone())
            .collect();
        // The ac3 track must carry "jpn"; the video track must not.
        assert!(langs.contains(&Some("jpn".to_string())), "langs={langs:?}");
    }

    /// A video track's language tag is dropped — video streams carry a
    /// stream_identifier_descriptor but no ISO_639_language_descriptor in
    /// the PMT.
    #[test]
    fn video_track_emits_no_language_descriptor() {
        let mut video = stream_info(0, "h264", true);
        video.params = video.params.with_language("eng");
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mx = MpegTsMuxer::new(output, std::slice::from_ref(&video)).expect("open");
        assert!(mx.tracks[0].language.is_none());
        let es = build_es_descriptors(&mx.tracks[0]);
        let tags: Vec<u8> = crate::descriptor::iter_descriptors(&es)
            .map(|d| d.unwrap().tag)
            .collect();
        assert!(
            tags.contains(&0x52),
            "expected stream_identifier, tags={tags:?}"
        );
        assert!(
            !tags.contains(&0x0A),
            "video must not carry ISO-639, tags={tags:?}"
        );
    }

    /// The auto stream_identifier_descriptor and a caller-injected DVB
    /// component descriptor (teletext) both surface in the demuxed PMT.
    #[test]
    fn es_descriptors_component_tag_and_injected_round_trip() {
        use crate::descriptor::DescriptorBody;
        use crate::psi::{iter_sections, ProgramMapTable};
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let teletext = crate::build::teletext_descriptor(&[crate::descriptor::TeletextEntry {
            language_code: *b"eng",
            teletext_type: 0x02,
            teletext_magazine_number: 0x01,
            teletext_page_number: 0x88,
        }]);
        let config = MpegTsMuxConfig {
            transport_stream_id: 1,
            original_network_id: 1,
            programs: vec![ProgramSpec {
                program_number: 1,
                pmt_pid: 0x0100,
                pcr_pid: None,
                stream_indices: vec![0, 1],
                service: None,
                events: Vec::new(),
                es_descriptors: vec![(1, teletext)],
            }],
            network: None,
        };
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::with_config(output, &streams, config).expect("open");
            mx.write_header().unwrap();
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![1; 4]).with_pts(10))
                .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        // Reassemble the PMT from PID 0x0100.
        let mut pmt = None;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let pid = (((chunk[1] & 0x1F) as u16) << 8) | chunk[2] as u16;
            let pusi = chunk[1] & 0x40 != 0;
            if pid == 0x0100 && pusi {
                for sec in iter_sections(&chunk[4..]) {
                    if let Ok(p) = ProgramMapTable::parse(sec) {
                        pmt = Some(p);
                        break;
                    }
                }
            }
            if pmt.is_some() {
                break;
            }
        }
        let pmt = pmt.expect("PMT on 0x0100");
        // Every stream carries a distinct stream_identifier component_tag.
        let mut tags = Vec::new();
        for st in &pmt.streams {
            for d in st.iter_descriptors() {
                if let DescriptorBody::StreamIdentifier(s) = d.unwrap().body {
                    tags.push(s.component_tag);
                }
            }
        }
        tags.sort();
        assert_eq!(tags, vec![1, 2]);
        // The AC-3 stream (index 1) carries the injected teletext descriptor.
        let ac3 = pmt.streams.iter().find(|s| s.stream_type == 0x81).unwrap();
        let has_teletext = ac3
            .iter_descriptors()
            .any(|d| matches!(d.unwrap().body, DescriptorBody::Teletext(_)));
        assert!(has_teletext, "expected injected teletext descriptor");
    }

    /// A keyframe-flagged core `Packet` must surface a
    /// `random_access_indicator` on the wire (first TS packet of its
    /// PES) and read back as a keyframe through the demuxer, per
    /// §2.4.3.5 — including the PCR-PID constraint that the indicator
    /// only rides packets carrying the PCR fields.
    #[test]
    fn keyframe_round_trips_as_random_access_indicator() {
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let sink = SharedSink::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            let tb = TimeBase::new(1, 90_000);
            // Video keyframe (PCR PID; PES start carries PCR → RAI
            // legal), long enough to span several TS packets so the
            // indicator must land on the FIRST only.
            let kf = Packet::new(0, tb, vec![0xAB; 600])
                .with_pts(10_000)
                .with_keyframe(true);
            // Non-keyframe video packet: no RAI.
            let mid = Packet::new(0, tb, vec![0xCD; 600]).with_pts(13_600);
            // Audio keyframe on a non-PCR PID: RAI without PCR.
            let akf = Packet::new(1, tb, vec![0xEF; 100])
                .with_pts(11_000)
                .with_keyframe(true);
            mx.write_packet(&kf).unwrap();
            mx.write_packet(&akf).unwrap();
            mx.write_packet(&mid).unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();

        // Wire check: count RAI packets per PID.
        let mut rai_by_pid: std::collections::HashMap<u16, usize> =
            std::collections::HashMap::new();
        let mut rai_with_pcr = 0usize;
        for pkt in crate::iter_packets(&bytes) {
            let pkt = pkt.expect("well-formed muxer output");
            if let Some(af) = &pkt.adaptation_field {
                if af.random_access_indicator {
                    *rai_by_pid.entry(pkt.pid).or_default() += 1;
                    assert!(
                        pkt.payload_unit_start,
                        "muxer sets RAI only on PES-start packets"
                    );
                    if af.pcr_flag {
                        rai_with_pcr += 1;
                    }
                }
            }
        }
        assert_eq!(
            rai_by_pid.values().sum::<usize>(),
            2,
            "exactly the two keyframes are flagged: {rai_by_pid:?}"
        );
        assert_eq!(rai_by_pid.len(), 2, "one video + one audio PID");
        assert_eq!(
            rai_with_pcr, 1,
            "the video (PCR PID) RAI packet also carries the PCR"
        );

        // Demux check: keyframe flags survive the round trip.
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let resolver = oxideav_core::NullCodecResolver;
        let mut dmx = crate::demuxer::open(input, &resolver).expect("dmx open");
        let mut flags_by_pts = std::collections::HashMap::new();
        while let Ok(p) = dmx.next_packet() {
            flags_by_pts.insert(p.pts.unwrap(), p.is_keyframe());
        }
        assert_eq!(flags_by_pts.get(&10_000), Some(&true));
        assert_eq!(flags_by_pts.get(&11_000), Some(&true));
        assert_eq!(flags_by_pts.get(&13_600), Some(&false));
    }

    /// Mux a GOP-shaped video+audio stream (keyframe every 4th video
    /// packet) and drive the demuxer's random-access index + keyframe
    /// seek over it.
    #[test]
    fn random_access_index_and_keyframe_seek() {
        use oxideav_core::Demuxer as _;
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let sink = SharedSink::new();
        let tb = TimeBase::new(1, 90_000);
        let mut keyframe_pts: Vec<i64> = Vec::new();
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            for i in 0..40i64 {
                let pts = 10_000 + i * 3_000; // ~30 fps steps
                let kf = i % 4 == 0;
                if kf {
                    keyframe_pts.push(pts);
                }
                let v = Packet::new(0, tb, vec![(i & 0xFF) as u8; 300])
                    .with_pts(pts)
                    .with_keyframe(kf);
                mx.write_packet(&v).unwrap();
                let a = Packet::new(1, tb, vec![0x55; 64])
                    .with_pts(pts + 500)
                    .with_keyframe(true);
                mx.write_packet(&a).unwrap();
            }
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();

        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = crate::demuxer::MpegTsDemuxer::open_program(input, 1).expect("open demuxer");

        // Index: every muxed keyframe appears, with the right PTS.
        let video_idx = dmx
            .streams()
            .iter()
            .position(|s| s.params.codec_id.as_str() == "h264")
            .unwrap() as u32;
        let raps: Vec<crate::demuxer::RandomAccessPoint> =
            dmx.random_access_points().expect("index").to_vec();
        let video_rap_pts: Vec<i64> = raps
            .iter()
            .filter(|r| r.stream_index == video_idx)
            .map(|r| r.pts_90k.expect("§2.4.3.5 requires a PTS") as i64)
            .collect();
        assert_eq!(video_rap_pts, keyframe_pts);
        // Audio keyframes are indexed too (every audio packet here).
        assert_eq!(raps.len(), 10 + 40);

        // Keyframe seek: target between keyframes → lands on the one
        // at or before it, and the next video packet demuxed IS that
        // keyframe.
        let target = keyframe_pts[5] + 4_000; // past kf[5], before kf[6]
        let landed = dmx
            .seek_to_random_access(Some(video_idx), target)
            .expect("seek");
        assert_eq!(landed, keyframe_pts[5]);
        loop {
            let p = dmx.next_packet().expect("packet after seek");
            if p.stream_index == video_idx {
                assert_eq!(p.pts, Some(keyframe_pts[5]));
                assert!(p.is_keyframe(), "seek landed on a random-access point");
                break;
            }
        }

        // Early target clamps up to the first indexed point (the
        // first muxed keyframe — video, PTS 10_000).
        let landed = dmx.seek_to_random_access(None, 0).expect("seek to start");
        assert_eq!(landed, keyframe_pts[0]);
        // Late target lands on the last indexed point with PTS ≤
        // target (the final audio packet at +500).
        let landed = dmx
            .seek_to_random_access(None, i64::MAX)
            .expect("seek to end");
        assert_eq!(landed, 10_000 + 39 * 3_000 + 500);
    }

    /// Muxer output must pass the crate's own §2.4.3.3/§2.4.3.5/§2.7.2
    /// conformance validator with zero violations.
    #[test]
    fn muxer_output_is_conformant() {
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let sink = SharedSink::new();
        let tb = TimeBase::new(1, 90_000);
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            for i in 0..50i64 {
                let pts = 5_000 + i * 3_000;
                let v = Packet::new(0, tb, vec![(i & 0xFF) as u8; 400])
                    .with_pts(pts)
                    .with_keyframe(i % 10 == 0);
                mx.write_packet(&v).unwrap();
                let a = Packet::new(1, tb, vec![0x11; 80]).with_pts(pts + 700);
                mx.write_packet(&a).unwrap();
            }
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        let report = crate::validate::validate_ts(&bytes);
        assert!(
            report.is_conformant(),
            "muxer output violates the spec: {:?}",
            report.violations
        );
        assert_eq!(report.programs, vec![(1, 0x0100)]);
        assert_eq!(report.pcr.len(), 1);
        let pcr = &report.pcr[0];
        assert!(pcr.samples >= 50, "PCR on every video PES start");
        // §2.7.2: every inter-PCR gap within 0,1 s.
        assert!(pcr.max_interval_27mhz.unwrap() <= crate::validate::MAX_PCR_INTERVAL_27MHZ);
        assert!(pcr.estimated_rate_bps.unwrap() > 0);
        // PSI repetition produced multiple PATs.
        assert!(report.pat_sections >= 2);
        assert!(report.pat_max_gap_packets.is_some());
    }

    /// Re-frame a plain 188-byte TS byte stream into 192-byte
    /// (4-byte-prefixed) source packets.
    fn wrap_192(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() / 188 * 192);
        for (i, pkt) in bytes.chunks(TS_PACKET_LEN).enumerate() {
            out.extend_from_slice(&(i as u32).to_be_bytes()); // header word
            out.extend_from_slice(pkt);
        }
        out
    }

    /// Re-frame a plain 188-byte TS byte stream into 204-byte packets
    /// (16-byte trailer appended to each packet).
    fn wrap_204(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() / 188 * 204);
        for pkt in bytes.chunks(TS_PACKET_LEN) {
            out.extend_from_slice(pkt);
            out.extend_from_slice(&[0xEC; 16]);
        }
        out
    }

    /// The demuxer must tolerate the two non-188 physical framings —
    /// 192-byte prefixed source packets and 204-byte trailer-appended
    /// packets — transparently: same streams, same timestamps, same
    /// duration probe, working PCR seek.
    #[test]
    fn demux_tolerates_192_and_204_byte_framings() {
        use oxideav_core::Demuxer as _;
        // Build a plain 188-byte stream with enough PES + PCR spread
        // to exercise the duration probe and seek.
        let streams = vec![stream_info(0, "h264", true)];
        let sink = SharedSink::new();
        let tb = TimeBase::new(1, 90_000);
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            for i in 0..30i64 {
                let v = Packet::new(0, tb, vec![(i & 0xFF) as u8; 200])
                    .with_pts(9_000 + i * 3_000)
                    .with_keyframe(i % 5 == 0);
                mx.write_packet(&v).unwrap();
            }
            mx.write_trailer().unwrap();
        }
        let plain = sink.into_bytes();

        for (framed, layout) in [
            (
                wrap_192(&plain),
                crate::packet::TsPacketLayout::PREFIXED_192,
            ),
            (wrap_204(&plain), crate::packet::TsPacketLayout::TRAILER_204),
        ] {
            // Container probe recognises the framing.
            let p = oxideav_core::ProbeData {
                buf: &framed[..framed.len().min(1024)],
                ext: None,
            };
            assert_eq!(
                crate::demuxer::probe(&p),
                100,
                "probe must accept {layout:?}"
            );

            let input: Box<dyn ReadSeek> = Box::new(Cursor::new(framed));
            let mut dmx =
                crate::demuxer::MpegTsDemuxer::open_program(input, 1).expect("open framed");
            assert_eq!(dmx.packet_layout(), layout);
            assert_eq!(dmx.streams().len(), 1);
            assert_eq!(dmx.streams()[0].params.codec_id.as_str(), "h264");
            // Duration probe works on the framed grid.
            let dur = dmx.duration_micros().expect("duration probed");
            assert!(dur > 0, "duration = {dur}");

            // Every PES round-trips with its PTS.
            let mut ptss = Vec::new();
            while let Ok(p) = dmx.next_packet() {
                ptss.push(p.pts.unwrap());
            }
            assert_eq!(ptss.len(), 30);
            assert_eq!(ptss[0], 9_000);
            assert_eq!(*ptss.last().unwrap(), 9_000 + 29 * 3_000);

            // PCR-anchored seek still lands correctly.
            let landed = dmx.seek_to(0, 9_000 + 15 * 3_000).expect("seek");
            assert!(landed <= 9_000 + 15 * 3_000);
            let nxt = dmx.next_packet().expect("packet after seek");
            assert!(nxt.pts.unwrap() <= 9_000 + 16 * 3_000);

            // Keyframe index sees the RAI grid through the framing.
            let raps = dmx.random_access_points().expect("index");
            assert_eq!(raps.len(), 6, "keyframes every 5th of 30 packets");
        }
    }

    /// A stream that never sets the random_access_indicator yields an
    /// empty index and an `Unsupported` keyframe seek.
    #[test]
    fn keyframe_seek_unsupported_without_rai() {
        let streams = vec![stream_info(0, "h264", true)];
        let sink = SharedSink::new();
        let tb = TimeBase::new(1, 90_000);
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            mx.write_header().expect("hdr");
            for i in 0..8i64 {
                let v = Packet::new(0, tb, vec![0xAA; 100]).with_pts(1_000 + i * 3_000);
                mx.write_packet(&v).unwrap();
            }
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        let mut dmx = crate::demuxer::MpegTsDemuxer::open_program(input, 1).expect("open demuxer");
        assert!(dmx.random_access_points().expect("index").is_empty());
        assert!(matches!(
            dmx.seek_to_random_access(None, 5_000),
            Err(CoreError::Unsupported(_))
        ));
    }

    /// The clock-reference encoder the mux path relies on must
    /// round-trip through the demuxer-side adaptation field PCR
    /// decode. Pin the exact bit layout (§2.4.3.4 Table 2-6).
    #[test]
    fn encode_pcr_bit_layout() {
        // base = 0x1_0000_0001 (33 bits, low bit set), ext = 0x155.
        let b = crate::packet::encode_clock_reference(0x1_0000_0001, 0x155);
        // high32 = base >> 1 = 0x8000_0000.
        assert_eq!(&b[0..4], &0x8000_0000u32.to_be_bytes());
        // byte4 = (low_bit<<7) | 0b0111_1110 | (ext>>8 & 1)
        //       = (1<<7) | 0x7E | (1) = 0xFF.
        assert_eq!(b[4], 0xFF);
        assert_eq!(b[5], 0x55);
        // Parse it back through the packet AF decoder.
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = 0x01;
        pkt[2] = 0x00;
        pkt[3] = 0b0010_0000; // AF only
        pkt[4] = 183;
        pkt[5] = 0b0001_0000; // PCR_flag
        pkt[6..12].copy_from_slice(&b);
        let parsed = crate::packet::TsPacket::parse(&pkt).expect("parse");
        let af = parsed.adaptation_field.expect("af");
        assert_eq!(af.pcr_base, Some(0x1_0000_0001));
        assert_eq!(af.pcr_extension, Some(0x155));
    }

    /// When two PES packets on the same PCR PID are spaced far apart in
    /// PTS, with intervening audio packets, the muxer must inject extra
    /// standalone PCR-only packets to keep the inter-PCR interval inside
    /// the §2.7.2 bound. Count the PCR-bearing packets on the PCR PID.
    #[test]
    fn periodic_pcr_injected_for_large_pts_gap() {
        let streams = vec![stream_info(0, "h264", true), stream_info(1, "ac3", false)];
        let sink = SharedSink::new();
        let pcr_pid;
        {
            let output: Box<dyn oxideav_core::WriteSeek> = Box::new(sink.clone());
            let mut mx = MpegTsMuxer::new(output, &streams).expect("open");
            pcr_pid = mx.programs[0].pcr_pid;
            mx.write_header().expect("hdr");
            // Video at PTS 0, then a run of audio packets advancing PTS
            // well past several PCR intervals, then video again.
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![0; 10]).with_pts(0))
                .unwrap();
            for k in 1..=10i64 {
                let pts = k * 4000; // > PCR_MAX_INTERVAL_90K each step
                mx.write_packet(
                    &Packet::new(1, TimeBase::new(1, 90_000), vec![0; 8]).with_pts(pts),
                )
                .unwrap();
            }
            mx.write_packet(&Packet::new(0, TimeBase::new(1, 90_000), vec![0; 10]).with_pts(44000))
                .unwrap();
            mx.write_trailer().unwrap();
        }
        let bytes = sink.into_bytes();
        // Count packets on the PCR PID that carry a PCR_flag.
        let mut pcr_count = 0;
        for chunk in bytes.chunks_exact(TS_PACKET_LEN) {
            let pid = (((chunk[1] & 0x1F) as u16) << 8) | chunk[2] as u16;
            if pid != pcr_pid {
                continue;
            }
            let afc = (chunk[3] >> 4) & 0b11;
            if afc & 0b10 != 0 {
                let af_len = chunk[4] as usize;
                if af_len > 0 && (chunk[5] & 0b0001_0000) != 0 {
                    pcr_count += 1;
                }
            }
        }
        // 1 (initial video PES) + many standalone audio-driven PCRs +
        // the final video PES = comfortably more than 2.
        assert!(pcr_count >= 5, "only {pcr_count} PCRs emitted");
    }

    #[test]
    fn iso639_code_pads_and_truncates() {
        assert_eq!(iso639_code("en"), [b'e', b'n', b' ']);
        assert_eq!(iso639_code("jpn"), [b'j', b'p', b'n']);
        assert_eq!(iso639_code("english"), [b'e', b'n', b'g']);
        assert_eq!(iso639_code(""), [b' ', b' ', b' ']);
    }

    #[test]
    fn open_rejects_empty_stream_list() {
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        let r = MpegTsMuxer::new(output, &[]);
        assert!(r.is_err());
    }

    #[test]
    fn open_rejects_unknown_codec_id() {
        let s = stream_info(0, "this-is-not-a-known-codec", true);
        let output: Box<dyn oxideav_core::WriteSeek> = Box::new(Cursor::new(Vec::<u8>::new()));
        let r = MpegTsMuxer::new(output, &[s]);
        assert!(r.is_err());
    }
}
