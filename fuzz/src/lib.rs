//! Shared helpers for the oxideav-mpegts fuzz targets.
//!
//! Three pieces live here so the targets stay thin:
//!
//! * [`Recipe`] — a bounded byte reader that turns the fuzz input
//!   into a stream of small integers (never panics, never reads out
//!   of bounds; exhausted input yields zeros so every prefix of a
//!   crashing input is itself a valid recipe).
//! * [`MuxPlan`] / [`MuxPlan::decode`] / [`MuxPlan::run`] — a
//!   structure-aware, valid-by-construction multi-program mux plan:
//!   programs x streams x packets x DVB-SI options x splice /
//!   time-base-discontinuity / CBR / PSI-repetition knobs, exactly
//!   the option surface whose round-trip identity the muxer + demuxer
//!   pair guarantees.
//! * [`exercise_hostile`] — the hostile-bytes battery: conformance
//!   validator, raw packet walk with PSI assembly across fragmented
//!   sections (all PSI + DVB SI tables, descriptor walks), PES
//!   reassembly + header decode, PCR / continuity / PTS trackers,
//!   the §2.4.2 T-STD replay, and the typed demuxer battery (open,
//!   bounded drain, RAP index, all three seek paths).

use std::collections::HashMap;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use oxideav_core::{
    CodecId, CodecParameters, Demuxer as _, Muxer as _, Packet, ReadSeek, StreamInfo, TimeBase,
    WriteSeek,
};

use oxideav_mpegts::demuxer::MpegTsDemuxer;
use oxideav_mpegts::muxer::{
    EventSpec, MpegTsMuxConfig, MpegTsMuxer, NetworkSpec, ProgramSpec, SeamlessSpliceSpec,
    ServiceSpec, SpliceSpec,
};
use oxideav_mpegts::psi::{PsiSectionAssembler, RunningStatus};
use oxideav_mpegts::{
    analyze_tstd, detect_packet_layout, iter_packets, validate_ts, ContinuityTracker, PcrTracker,
    PtsTracker, TStdConfig, TStdStreamModel, TS_PACKET_LEN,
};

// ---------------------------------------------------------------------------
// Recipe reader
// ---------------------------------------------------------------------------

/// Bounded byte reader over the fuzz input. Reads past the end yield
/// `0`, so shrinking a crashing input never changes its meaning
/// mid-parse.
pub struct Recipe<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Recipe<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Recipe { data, pos: 0 }
    }
    pub fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    pub fn u64(&mut self) -> u64 {
        u64::from(self.u32()) << 32 | u64::from(self.u32())
    }
    /// `true` with probability `num/256`.
    pub fn chance(&mut self, num: u16) -> bool {
        u16::from(self.u8()) < num
    }
    /// Remaining unread bytes (used by the mutation target to derive
    /// mutation positions after the fixture recipe is consumed).
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }
}

// ---------------------------------------------------------------------------
// In-memory writer (the muxer consumes its Box<dyn WriteSeek>)
// ---------------------------------------------------------------------------

/// Writer that shares its backing buffer so the finished stream bytes
/// can be recovered after the muxer (which consumes the
/// `Box<dyn WriteSeek>`) is dropped.
#[derive(Clone, Default)]
pub struct SharedBuf(Arc<Mutex<Cursor<Vec<u8>>>>);

impl SharedBuf {
    pub fn into_bytes(self) -> Vec<u8> {
        Arc::try_unwrap(self.0)
            .expect("muxer dropped; sole owner")
            .into_inner()
            .expect("lock poisoned")
            .into_inner()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl Seek for SharedBuf {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.lock().unwrap().seek(pos)
    }
}

// ---------------------------------------------------------------------------
// Hostile-bytes battery
// ---------------------------------------------------------------------------

/// Fixed SI PIDs whose sections get routed to the matching table
/// parsers: PAT, CAT, TSDT, NIT, SDT/BAT, EIT, RST, TDT/TOT, DIT, SIT.
const SI_PIDS: [u16; 10] = [
    0x0000, 0x0001, 0x0002, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x001E, 0x001F,
];

/// Dispatch one complete section (table_id .. CRC) to every parser
/// that plausibly owns it on `pid`, then walk all descriptor loops the
/// typed result exposes. Return values are irrelevant — the battery
/// only cares that nothing panics and nothing allocates past the
/// section-length bound.
fn dispatch_section(pid: u16, section: &[u8], pmt_pids: &mut Vec<u16>, es_pids: &mut Vec<u16>) {
    use oxideav_mpegts::psi::*;
    if pid == 0x0000 {
        if let Ok(pat) = ProgramAssociationTable::parse(section) {
            for &(program_number, pmt_pid) in &pat.programs {
                if program_number != 0 && pmt_pids.len() < 8 && !pmt_pids.contains(&pmt_pid) {
                    pmt_pids.push(pmt_pid);
                }
            }
        }
    }
    if pid == 0x0001 {
        if let Ok(cat) = ConditionalAccessTable::parse(section) {
            for d in cat.iter_descriptors() {
                let _ = d;
            }
        }
    }
    if pid == 0x0002 {
        if let Ok(tsdt) = TransportStreamDescriptionTable::parse(section) {
            for d in tsdt.iter_descriptors() {
                let _ = d;
            }
        }
    }
    if pid == 0x0010 {
        if let Ok(nit) = NetworkInformationTable::parse(section) {
            for d in nit.iter_descriptors() {
                let _ = d;
            }
            for ts in &nit.transport_streams {
                for d in ts.iter_descriptors() {
                    let _ = d;
                }
            }
        }
    }
    if pid == 0x0011 {
        if let Ok(sdt) = ServiceDescriptionTable::parse(section) {
            for svc in &sdt.services {
                for d in svc.iter_descriptors() {
                    let _ = d;
                }
            }
        }
        if let Ok(bat) = BouquetAssociationTable::parse(section) {
            for d in bat.iter_descriptors() {
                let _ = d;
            }
            for ts in &bat.transport_streams {
                for d in ts.iter_descriptors() {
                    let _ = d;
                }
            }
        }
    }
    if pid == 0x0012 {
        if let Ok(eit) = EventInformationTable::parse(section) {
            for ev in &eit.events {
                let _ = ev.start_time;
                let _ = ev.duration.as_seconds();
                for d in ev.iter_descriptors() {
                    let _ = d;
                }
            }
        }
    }
    if pid == 0x0013 {
        let _ = RunningStatusTable::parse(section);
    }
    if pid == 0x0014 {
        let _ = TimeDateTable::parse(section);
        if let Ok(tot) = TimeOffsetTable::parse(section) {
            for d in tot.iter_descriptors() {
                let _ = d;
            }
        }
    }
    if pid == 0x001E {
        let _ = DiscontinuityInformationTable::parse(section);
    }
    if pid == 0x001F {
        if let Ok(sit) = SelectionInformationTable::parse(section) {
            for d in sit.iter_descriptors() {
                let _ = d;
            }
            for svc in &sit.services {
                for d in svc.iter_descriptors() {
                    let _ = d;
                }
            }
        }
    }
    // The ST may ride any SI PID.
    let _ = StuffingTable::parse(section);
    // PMT on a PAT-advertised PID.
    if pmt_pids.contains(&pid) {
        if let Ok(pmt) = ProgramMapTable::parse(section) {
            for d in pmt.iter_program_descriptors() {
                let _ = d;
            }
            for s in &pmt.streams {
                for d in s.iter_descriptors() {
                    let _ = d;
                }
                if es_pids.len() < 8 && !es_pids.contains(&s.elementary_pid) {
                    es_pids.push(s.elementary_pid);
                }
            }
        }
    }
}

/// Raw packet walk: PSI assembly on every SI / PAT-discovered PID,
/// PES reassembly on every PMT-discovered elementary PID, and the
/// three clock observers. Returns the first advertised
/// `program_number` (for the typed demuxer battery).
fn walk_packets(bytes: &[u8]) -> Option<u16> {
    let mut first_program: Option<u16> = None;
    let mut pmt_pids: Vec<u16> = Vec::new();
    let mut es_pids: Vec<u16> = Vec::new();
    let mut si_asm: HashMap<u16, PsiSectionAssembler> = HashMap::new();
    let mut pes_asm: HashMap<u16, oxideav_mpegts::PesReassembler> = HashMap::new();
    let mut cc_trk: HashMap<u16, ContinuityTracker> = HashMap::new();
    let mut pcr_trk = PcrTracker::new();
    let mut pts_trk = PtsTracker::new();
    let mut byte_offset = 0u64;

    for pkt in iter_packets(bytes) {
        let pkt = match pkt {
            Ok(p) => p,
            Err(_) => break, // the iterator halts after the first bad sync
        };
        // Continuity classification (bounded tracker count).
        if cc_trk.len() < 64 || cc_trk.contains_key(&pkt.pid) {
            let disc = pkt
                .adaptation_field
                .as_ref()
                .is_some_and(|af| af.discontinuity_indicator);
            cc_trk.entry(pkt.pid).or_default().observe(
                pkt.continuity_counter,
                !pkt.payload.is_empty(),
                disc,
            );
        }
        // PCR observation on whatever PID carries one first.
        if let Some(af) = &pkt.adaptation_field {
            let _ = pcr_trk.observe(af, byte_offset);
        }
        // PSI assembly on the fixed SI PIDs + PAT-discovered PMT PIDs.
        let is_si = SI_PIDS.contains(&pkt.pid) || pmt_pids.contains(&pkt.pid);
        if is_si && !pkt.payload.is_empty() {
            let asm = si_asm.entry(pkt.pid).or_default();
            if let Ok(sections) =
                asm.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
            {
                for s in &sections {
                    if pkt.pid == 0x0000 && first_program.is_none() {
                        if let Ok(pat) = oxideav_mpegts::ProgramAssociationTable::parse(s) {
                            first_program = pat
                                .programs
                                .iter()
                                .find(|&&(num, _)| num != 0)
                                .map(|&(num, _)| num);
                        }
                    }
                    dispatch_section(pkt.pid, s, &mut pmt_pids, &mut es_pids);
                }
            }
        }
        // PES reassembly on PMT-discovered elementary PIDs.
        if es_pids.contains(&pkt.pid) {
            let asm = pes_asm.entry(pkt.pid).or_default();
            if let Ok(Some(pes)) = asm.feed(&pkt) {
                let _ = pes.trick_mode();
                if let Some(raw) = pes.pts_90k {
                    let _ = pts_trk.observe(raw);
                }
                if let Some(raw) = pes.dts_90k {
                    let _ = oxideav_mpegts::extend_near(raw, pts_trk.extended().unwrap_or(0));
                }
            }
        }
        byte_offset += TS_PACKET_LEN as u64;
    }
    for (_, mut asm) in pes_asm {
        let _ = asm.flush();
    }
    first_program
}

/// Typed demuxer battery: open on a program, drain bounded, build the
/// RAP index, run all three seek paths. Whether a given input opens or
/// errors is the stream's business — panicking is not.
fn demux_battery(bytes: &[u8], program: u16) {
    let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes.to_vec()));
    let Ok(mut dmx) = MpegTsDemuxer::open_program(input, program) else {
        return;
    };
    let _ = dmx.programs().len();
    let _ = dmx.selected_program();
    let _ = dmx.pcr_pid();
    let _ = dmx.last_pcr();
    let _ = dmx.packet_layout();
    let n_streams = dmx.streams().len() as u32;
    // Bounded drain: the input is fuzz-sized, so a few dozen packets
    // cross every reassembly path; anything unbounded is the bug.
    for _ in 0..64 {
        if dmx.next_packet().is_err() {
            break;
        }
    }
    let _ = dmx.random_access_points();
    for s in 0..n_streams.min(2) {
        let _ = dmx.seek_to_random_access(Some(s), 90_000);
        let _ = dmx.seek_to_access_point(s, 45_000);
        let _ = dmx.seek_to(s, 10_000);
    }
    for _ in 0..8 {
        if dmx.next_packet().is_err() {
            break;
        }
    }
}

/// Feed one byte buffer through every hostile-input surface.
pub fn exercise_hostile(bytes: &[u8]) {
    // Conformance validator: two bounded passes, finite tallies.
    let report = validate_ts(bytes);
    let _ = report.is_conformant();
    assert!(report.packets as usize <= bytes.len() / TS_PACKET_LEN + 1);

    // Physical-framing classification.
    let _ = detect_packet_layout(bytes);

    // Raw walk: PSI + PES + clocks.
    let first_program = walk_packets(bytes);

    // T-STD replay over the default muxer PID layout: any input must
    // produce an error or a finite, violation-capped report.
    let config = TStdConfig::single_program(
        0x1011,
        0x0100,
        vec![
            (
                0x1011,
                TStdStreamModel::video_low_main_level(4_000_000, 65_536, 131_072),
            ),
            (0x1012, TStdStreamModel::audio()),
        ],
    );
    if let Ok(report) = analyze_tstd(bytes, &config) {
        assert!(report.modelled_seconds.is_finite());
    }

    // Typed demuxer battery on the first advertised program (and on
    // program 1 when the PAT never surfaced one).
    demux_battery(bytes, first_program.unwrap_or(1));
}

// ---------------------------------------------------------------------------
// Structure-aware mux plan
// ---------------------------------------------------------------------------

/// One planned frame: `(pts, dts, payload_len, keyframe)`.
#[derive(Debug, Clone, Copy)]
pub struct PlannedFrame {
    pub pts: i64,
    pub dts: Option<i64>,
    pub len: usize,
    pub keyframe: bool,
}

/// One planned elementary stream.
#[derive(Debug)]
pub struct PlannedStream {
    pub index: u32,
    pub codec: &'static str,
    pub is_video: bool,
    pub frames: Vec<PlannedFrame>,
    /// Arm `signal_splice_after` before writing frame `k`.
    pub splice_before: Option<(usize, SpliceSpec)>,
}

/// One planned program: `(program_number, pmt_pid, stream slots)`.
#[derive(Debug)]
pub struct PlannedProgram {
    pub program_number: u16,
    pub pmt_pid: u16,
    pub stream_slots: Vec<usize>,
    pub service: bool,
    pub event: bool,
}

/// A decoded, valid-by-construction multi-program mux plan.
#[derive(Debug)]
pub struct MuxPlan {
    pub programs: Vec<PlannedProgram>,
    pub streams: Vec<PlannedStream>,
    pub network: bool,
    /// CBR mux rate (bit/s), `None` for unpaced output.
    pub cbr_rate: Option<u64>,
    /// §2.4.2.3 video `Rmax` declared to the muxer for every video
    /// stream (CBR plans only) — exercises the video transport-buffer
    /// pacing path (`Rxn = 1.2 × Rmax`). Kept far above the planned
    /// per-frame demand so every plan stays deliverable.
    pub video_rmax: Option<u64>,
    pub psi_interval: Option<i64>,
    /// Arm a time-base discontinuity on `(program_number)` before the
    /// `k`-th globally written frame.
    pub discontinuity_before: Option<(u16, usize)>,
}

const VIDEO_CODECS: [&str; 4] = ["mpeg2video", "h264", "hevc", "vc1"];
const AUDIO_CODECS: [&str; 5] = ["pcm_s16be", "ac3", "dts", "truehd", "eac3"];

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

/// Cheap deterministic payload bytes.
pub fn payload(seed: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.wrapping_mul(0x9E37_79B9).wrapping_add(17);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

impl MuxPlan {
    /// Decode a plan from the recipe bytes. Every decoded plan is
    /// valid by construction: the muxer must accept it, its output
    /// must be validator-conformant (and T-STD-conformant in CBR
    /// mode), and the demuxer must round-trip it exactly.
    pub fn decode(r: &mut Recipe) -> MuxPlan {
        let cbr = r.chance(64);
        // CBR keeps the timeline short and the payloads small so the
        // §2.4.2 delivery schedule is trivially satisfiable at the
        // chosen rate (8..24 Mbit/s vs a worst-case instantaneous
        // demand well under 2 Mbit/s).
        let cbr_rate = cbr.then(|| 8_000_000 + u64::from(r.u16()) % 16_000_000);
        let n_programs = 1 + usize::from(r.chance(96));
        let mut programs = Vec::with_capacity(n_programs);
        let mut streams: Vec<PlannedStream> = Vec::new();

        // Optional 33-bit-wrap crossing timeline (non-CBR only: the
        // wrap fixtures ride the plain pacer).
        let wrap_base: i64 = if !cbr && r.chance(48) {
            (1i64 << 33) - 45_000
        } else {
            0
        };

        for p in 0..n_programs {
            let n_streams = 1 + (r.u8() % 3) as usize;
            let mut slots = Vec::with_capacity(n_streams);
            for s in 0..n_streams {
                let idx = streams.len() as u32;
                let is_video = s == 0 && !r.chance(48) || s > 0 && r.chance(64);
                let codec = if is_video {
                    VIDEO_CODECS[(r.u8() as usize) % VIDEO_CODECS.len()]
                } else {
                    AUDIO_CODECS[(r.u8() as usize) % AUDIO_CODECS.len()]
                };
                // Frame cadence: 20..80 ms steps on the 90 kHz base.
                let step = 1_800 + i64::from(r.u8() % 60) * 100;
                let pts0 = wrap_base + i64::from(r.u16() % 9_000);
                let n_frames = 1 + (r.u8() % if cbr { 8 } else { 16 }) as usize;
                let mut frames = Vec::with_capacity(n_frames);
                for k in 0..n_frames {
                    let pts = pts0 + k as i64 * step;
                    let len = if is_video {
                        (r.u16() % if cbr { 1_024 } else { 4_096 }) as usize
                    } else {
                        4 + (r.u8() % 250) as usize
                    };
                    // §2.7.5: DTS, when coded, is strictly below PTS —
                    // and §2.4.3.7 timestamps are unsigned 33-bit, so
                    // never generate a negative DTS (it would ring on
                    // the wire and legitimately come back re-based).
                    let dts = (is_video && r.chance(48) && pts > 0)
                        .then(|| (pts - 1 - i64::from(r.u8())).max(0));
                    frames.push(PlannedFrame {
                        pts,
                        dts,
                        len,
                        keyframe: is_video && (k == 0 || r.chance(96)),
                    });
                }
                // Splice request on a video stream, armed mid-run.
                let splice_before = (is_video && n_frames > 1 && r.chance(64)).then(|| {
                    let at = 1 + (r.u8() as usize) % (n_frames - 1);
                    let seamless = r.chance(128).then(|| SeamlessSpliceSpec {
                        splice_type: r.u8() & 0x0F,
                        dts_next_au: (frames[at].pts + step) as u64 & 0x1_FFFF_FFFF,
                    });
                    (
                        at,
                        SpliceSpec {
                            seamless,
                            post_splice_packets: r.u8() % 4,
                        },
                    )
                });
                streams.push(PlannedStream {
                    index: idx,
                    codec,
                    is_video,
                    frames,
                    splice_before,
                });
                slots.push(idx as usize);
            }
            programs.push(PlannedProgram {
                program_number: (p as u16) + 1,
                pmt_pid: 0x0100 + (p as u16) * 0x10,
                stream_slots: slots,
                service: r.chance(96),
                event: r.chance(64),
            });
        }

        let total_frames: usize = streams.iter().map(|s| s.frames.len()).sum();
        let discontinuity_before = (!cbr && r.chance(48) && total_frames > 1).then(|| {
            let prog = programs[(r.u8() as usize) % programs.len()].program_number;
            (prog, 1 + (r.u8() as usize) % (total_frames - 1))
        });

        MuxPlan {
            programs,
            streams,
            network: r.chance(64),
            // CBR video frames are ≤ 1 KiB every ≥ 20 ms (≤ ~0,5
            // Mbit/s incl. overhead), so a 4 Mbit/s Rmax paces the
            // TB visibly while every frame stays deliverable well
            // inside its decode lead.
            video_rmax: (cbr && r.chance(128)).then_some(4_000_000),
            cbr_rate,
            psi_interval: r.chance(128).then(|| 4_500 + i64::from(r.u8()) * 900),
            discontinuity_before,
        }
    }

    fn config(&self) -> MpegTsMuxConfig {
        let programs = self
            .programs
            .iter()
            .map(|p| ProgramSpec {
                program_number: p.program_number,
                pmt_pid: p.pmt_pid,
                pcr_pid: None,
                stream_indices: p.stream_slots.iter().map(|&s| s as u32).collect(),
                service: p.service.then(|| ServiceSpec {
                    service_type: 0x01,
                    provider_name: b"fuzz provider".to_vec(),
                    service_name: format!("fuzz svc {}", p.program_number).into_bytes(),
                }),
                events: if p.event {
                    vec![EventSpec {
                        event_id: 0x1000 + p.program_number,
                        start_time: oxideav_mpegts::decode_utc_time([0xC0, 0x79, 0x12, 0x45, 0x00]),
                        duration: oxideav_mpegts::psi::EitDuration {
                            hours: 1,
                            minutes: 30,
                            seconds: 0,
                        },
                        running_status: RunningStatus::Running,
                        language: *b"eng",
                        event_name: b"fuzz event".to_vec(),
                        text: b"structure-aware plan".to_vec(),
                    }]
                } else {
                    Vec::new()
                },
                es_descriptors: Vec::new(),
            })
            .collect();
        MpegTsMuxConfig {
            transport_stream_id: 1,
            original_network_id: 1,
            programs,
            network: self.network.then(|| NetworkSpec {
                network_id: 0x3001,
                network_name: b"fuzz net".to_vec(),
                network_descriptors: Vec::new(),
                transport_descriptors: Vec::new(),
            }),
            ..Default::default()
        }
    }

    /// Execute the plan: mux every frame in global PTS order and
    /// return the finished stream bytes. Every step must succeed — a
    /// decoded plan is valid by construction, so an `Err` anywhere is
    /// a muxer bug and the caller panics on it.
    pub fn run(&self) -> Vec<u8> {
        let infos: Vec<StreamInfo> = self
            .streams
            .iter()
            .map(|s| stream_info(s.index, s.codec, s.is_video))
            .collect();
        let buf = SharedBuf::default();
        let ws: Box<dyn WriteSeek> = Box::new(buf.clone());
        let mut mux = MpegTsMuxer::with_config(ws, &infos, self.config())
            .expect("valid plan: with_config must accept");
        if let Some(rate) = self.cbr_rate {
            mux.set_mux_rate(Some(rate));
        }
        if let Some(rmax) = self.video_rmax {
            for s in self.streams.iter().filter(|s| s.is_video) {
                mux.set_video_max_bitrate(s.index, Some(rmax))
                    .expect("valid plan: video Rmax hint");
            }
        }
        mux.set_psi_repetition_interval(self.psi_interval);
        mux.write_header().expect("valid plan: write_header");

        // Global PTS order (stable per stream) — the order the CBR
        // delivery schedule expects.
        let mut order: Vec<(usize, usize)> = Vec::new();
        for (si, s) in self.streams.iter().enumerate() {
            for k in 0..s.frames.len() {
                order.push((si, k));
            }
        }
        order.sort_by_key(|&(si, k)| (self.streams[si].frames[k].pts, si));

        for (written, &(si, k)) in order.iter().enumerate() {
            let s = &self.streams[si];
            let f = s.frames[k];
            if let Some((prog, at)) = self.discontinuity_before {
                if at == written {
                    mux.signal_time_base_discontinuity(prog)
                        .expect("valid plan: discontinuity");
                }
            }
            if let Some((at, spec)) = s.splice_before {
                if at == k {
                    mux.signal_splice_after(s.index, spec)
                        .expect("valid plan: splice");
                }
            }
            let mut pkt = Packet::new(
                s.index,
                TimeBase::new(1, 90_000),
                payload((si as u32) << 16 | k as u32, f.len),
            )
            .with_pts(f.pts);
            pkt.dts = f.dts;
            pkt.flags.keyframe = f.keyframe;
            mux.write_packet(&pkt).expect("valid plan: write_packet");
        }
        mux.write_trailer().expect("valid plan: write_trailer");
        drop(mux);
        buf.into_bytes()
    }

    /// Assert the full round-trip identity contract over `bytes`
    /// (the plan's own mux output).
    #[allow(clippy::type_complexity)]
    pub fn assert_roundtrip(&self, bytes: &[u8]) {
        // 1. The muxer's output is pinned conformant.
        let report = validate_ts(bytes);
        if !report.is_conformant() {
            if let Ok(dir) = std::env::var("MPEGTS_FUZZ_DUMP") {
                let _ = std::fs::write(format!("{dir}/validate_fail.ts"), bytes);
                let _ = std::fs::write(format!("{dir}/validate_fail.plan"), format!("{self:#?}"));
            }
            panic!("muxer output not conformant: {:?}", report.violations);
        }

        // 2. T-STD conformance for single-program CBR plans (the
        //    validator PID layout matches the muxer's assignments).
        if let (Some(rate), 1) = (self.cbr_rate, self.programs.len()) {
            let models: Vec<(u16, TStdStreamModel)> = self
                .streams
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let pid = 0x1011 + i as u16;
                    if s.is_video {
                        // With a declared Rmax the video chain is
                        // modelled at that tighter figure — the
                        // muxer's §2.4.2.3 TB pacing must hold there,
                        // not just at the generous wire rate.
                        let rmax = self.video_rmax.unwrap_or(rate);
                        (
                            pid,
                            TStdStreamModel::video_high_level(rmax, rmax / 2, 1_048_576),
                        )
                    } else {
                        (pid, TStdStreamModel::audio())
                    }
                })
                .collect();
            let config = TStdConfig::single_program(0x1011, self.programs[0].pmt_pid, models);
            match analyze_tstd(bytes, &config) {
                Ok(tstd) => {
                    if !tstd.is_conformant() {
                        if let Ok(dir) = std::env::var("MPEGTS_FUZZ_DUMP") {
                            let _ = std::fs::write(format!("{dir}/tstd_fail.ts"), bytes);
                            let _ = std::fs::write(
                                format!("{dir}/tstd_fail.plan"),
                                format!("{self:#?}"),
                            );
                        }
                        panic!("CBR mux violates T-STD: {tstd:?}");
                    }
                }
                // A one-frame plan can legitimately end after a single
                // PCR; the §2.4.2.2 arrival clock is unreconstructable
                // then and the model refuses rather than guess.
                Err(oxideav_mpegts::TsError::Unsupported(_)) => {}
                Err(e) => panic!("tstd analyzes own mux: {e}"),
            }
        }

        // 3. Exact demux round-trip, per program.
        for prog in &self.programs {
            let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes.to_vec()));
            let mut dmx = MpegTsDemuxer::open_program(input, prog.program_number)
                .expect("own mux output must open");
            // Demux stream i (PMT order) == plan slot i of this program.
            let n = dmx.streams().len();
            assert_eq!(n, prog.stream_slots.len(), "stream count survives");
            let mut got: Vec<Vec<(i64, Option<i64>, usize, bool)>> = vec![Vec::new(); n];
            while let Ok(p) = dmx.next_packet() {
                got[p.stream_index as usize].push((
                    p.pts.expect("every planned frame has a PTS"),
                    p.dts,
                    p.data.len(),
                    p.flags.keyframe,
                ));
            }
            for (di, &slot) in prog.stream_slots.iter().enumerate() {
                let want: Vec<(i64, Option<i64>, usize, bool)> = self.streams[slot]
                    .frames
                    .iter()
                    .map(|f| (f.pts, f.dts, f.len, f.keyframe))
                    .collect();
                assert_eq!(
                    got[di], want,
                    "stream {slot} (program {}) round-trip",
                    prog.program_number
                );
            }
        }
    }

    /// Total frames across all streams.
    pub fn total_frames(&self) -> usize {
        self.streams.iter().map(|s| s.frames.len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Mutation program (structured_mutate target)
// ---------------------------------------------------------------------------

/// Apply a bounded, fuzz-directed mutation program to a writer-shaped
/// fixture: sync-byte kills, header flips, PSI-payload / CRC-region
/// flips, packet drops and duplicates, truncation, and 192/204
/// reframing. Returns the mutant.
pub fn mutate(base: &[u8], ops: &mut Recipe) -> Vec<u8> {
    let mut m = base.to_vec();
    let n_ops = 1 + (ops.u8() % 8) as usize;
    for _ in 0..n_ops {
        if m.is_empty() {
            break;
        }
        let n_pkts = m.len() / TS_PACKET_LEN;
        match ops.u8() % 8 {
            // Arbitrary byte flip.
            0 => {
                let pos = ops.u32() as usize % m.len();
                m[pos] ^= ops.u8().max(1);
            }
            // Sync-byte kill on a packet boundary (resync path).
            1 if n_pkts > 0 => {
                let k = ops.u32() as usize % n_pkts;
                m[k * TS_PACKET_LEN] = ops.u8();
            }
            // 4-byte TS header flip (PID / flags / CC arithmetic).
            2 if n_pkts > 0 => {
                let k = ops.u32() as usize % n_pkts;
                let off = k * TS_PACKET_LEN + 1 + (ops.u8() as usize) % 3;
                m[off] ^= ops.u8().max(1);
            }
            // Section-header flip: the first bytes after the
            // pointer_field of a PUSI PSI packet (table_id /
            // section_length / version arithmetic).
            3 if n_pkts > 0 => {
                let start = ops.u32() as usize % n_pkts;
                for k in 0..n_pkts {
                    let off = ((start + k) % n_pkts) * TS_PACKET_LEN;
                    let pid = u16::from(m[off + 1] & 0x1F) << 8 | u16::from(m[off + 2]);
                    let pusi = m[off + 1] & 0x40 != 0;
                    let has_payload = m[off + 3] & 0x10 != 0;
                    if pusi && has_payload && (pid < 0x0020 || (0x0100..0x1000).contains(&pid)) {
                        let hdr = off + 5 + (ops.u8() as usize) % 8;
                        if hdr < off + TS_PACKET_LEN {
                            m[hdr] ^= ops.u8().max(1);
                        }
                        break;
                    }
                }
            }
            // CRC-region flip: one of the last bytes of a PSI packet's
            // payload (CRC-32 trailers live at section ends).
            4 if n_pkts > 0 => {
                let k = ops.u32() as usize % n_pkts;
                let off = k * TS_PACKET_LEN + TS_PACKET_LEN - 1 - (ops.u8() as usize) % 8;
                m[off] ^= ops.u8().max(1);
            }
            // Drop one packet (continuity-counter gap on every PID).
            5 if n_pkts > 1 => {
                let k = ops.u32() as usize % n_pkts;
                m.drain(k * TS_PACKET_LEN..(k + 1) * TS_PACKET_LEN);
            }
            // Duplicate one packet (§2.4.3.3 duplicate-cap paths).
            6 if n_pkts > 0 && m.len() < 1 << 20 => {
                let k = ops.u32() as usize % n_pkts;
                let pkt: Vec<u8> = m[k * TS_PACKET_LEN..(k + 1) * TS_PACKET_LEN].to_vec();
                let at = (k + 1) * TS_PACKET_LEN;
                m.splice(at..at, pkt);
            }
            // Truncate to an arbitrary (usually unaligned) length.
            _ => {
                let cut = ops.u32() as usize % (m.len() + 1);
                m.truncate(cut);
            }
        }
    }
    // Optional physical reframing of whatever survived the mutations.
    match ops.u8() % 4 {
        1 => {
            // 192-byte source packets: 4-byte prefix per packet.
            let mut framed = Vec::with_capacity(m.len() / TS_PACKET_LEN * 192);
            for (i, chunk) in m.chunks(TS_PACKET_LEN).enumerate() {
                framed.extend_from_slice(&(i as u32).to_be_bytes());
                framed.extend_from_slice(chunk);
            }
            framed
        }
        2 => {
            // 204-byte packets: 16-byte trailer per packet.
            let mut framed = Vec::with_capacity(m.len() / TS_PACKET_LEN * 204);
            for chunk in m.chunks(TS_PACKET_LEN) {
                framed.extend_from_slice(chunk);
                if chunk.len() == TS_PACKET_LEN {
                    framed.extend_from_slice(&[ops.u8(); 16]);
                }
            }
            framed
        }
        _ => m,
    }
}
