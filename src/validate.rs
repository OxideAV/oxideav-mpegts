//! Transport-stream conformance validation per ISO/IEC 13818-1.
//!
//! [`validate_ts`] walks a complete TS byte buffer twice — a PSI
//! discovery pass (PAT → PMTs, so the PCR PIDs are known) and a
//! packet-level check pass — and produces a [`TsValidationReport`]
//! summarising the stream's health against the normative rules a
//! multiplexer must uphold:
//!
//! * **§2.4.3.3 continuity counters** — increments per payload packet,
//!   at most one duplicate per CC value, no increment on
//!   `adaptation_field_control` `'00'` / `'10'`.
//! * **§2.4.3.3 / Table 2-5 adaptation field control** — the reserved
//!   `'00'` value (decoders shall discard such packets).
//! * **§2.4.3.5 adaptation field lengths** — `adaptation_field_length`
//!   must be 183 when the AF control is `'10'` and at most 182 when
//!   it is `'11'`.
//! * **§2.4.3.5 field pairings** — the OPCR shall be coded only in
//!   packets that also carry a PCR; `seamless_splice_flag` shall not
//!   be set when `splicing_point_flag` is not; on a PCR PID the
//!   `random_access_indicator` may only ride packets carrying the PCR
//!   fields.
//! * **§2.7.2 PCR frequency** — at most 0,1 s between consecutive
//!   PCRs of a program's PCR PID (unsignalled gaps only; a
//!   `discontinuity_indicator` legitimises the jump).
//! * **§2.4.4 PSI integrity** — PAT / PMT sections must CRC-verify;
//!   section lengths must not overrun their payloads.
//!
//! The transport rate is estimated from the byte distance between the
//! first and last PCR of each PCR PID against their 27 MHz tick span
//! (the §2.4.2.2 delivery model), and the PAT repetition interval is
//! reported so a caller can judge tune-in latency.
//!
//! All state is bounded: per-PID records are capped by the 13-bit PID
//! space, violations are counted (not accumulated as lists), and PSI
//! reassembly inherits `PsiSectionAssembler`'s 1024-byte section cap.

use std::collections::{BTreeMap, BTreeSet};

use crate::clock::{ContinuityEvent, ContinuityTracker};
use crate::packet::{detect_packet_layout, TsPacket, TsPacketLayout};
use crate::psi::{ProgramAssociationTable, ProgramMapTable, PsiSectionAssembler, PAT_PID};

/// The §2.7.2 upper bound on the interval between consecutive PCRs of
/// one program's PCR PID: 0,1 s = 2 700 000 ticks of the 27 MHz clock.
pub const MAX_PCR_INTERVAL_27MHZ: u64 = 2_700_000;

/// The null PID (Table 2-3); its packets are padding and exempt from
/// continuity-counter rules.
const NULL_PID: u16 = 0x1FFF;

/// Per-kind violation tallies. Every field counts occurrences of one
/// normative rule being broken; a fully conformant stream reports zero
/// everywhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViolationCounts {
    /// Packets whose `adaptation_field_control` is the reserved `'00'`
    /// (Table 2-5 — decoders shall discard these).
    pub reserved_afc: u64,
    /// Adaptation-field length outside its §2.4.3.5 bound —
    /// `adaptation_field_length != 183` with AF control `'10'`, or
    /// `> 182` with `'11'` (the latter also surfaces as an
    /// unparseable packet when the AF overruns the packet).
    pub bad_af_length: u64,
    /// Adaptation fields carrying an OPCR without a PCR (§2.4.3.5).
    pub opcr_without_pcr: u64,
    /// Adaptation-field extensions with `seamless_splice_flag` set in
    /// a packet whose `splicing_point_flag` is clear (§2.4.3.5).
    pub seamless_splice_without_splicing_point: u64,
    /// `random_access_indicator` on a PCR PID in a packet that does
    /// not carry the PCR fields (§2.4.3.5). Only checkable once the
    /// PMTs have named the PCR PIDs (the discovery pass runs first, so
    /// the whole buffer is covered).
    pub rai_without_pcr_on_pcr_pid: u64,
    /// Continuity-counter errors per §2.4.3.3 — dropped packets and
    /// over-cap duplicates (a second duplicate of the same CC).
    pub continuity_errors: u64,
    /// Packets flagged with `transport_error_indicator` (§2.4.3.3 — at
    /// least one uncorrectable bit error).
    pub transport_error_packets: u64,
    /// Unsignalled inter-PCR gaps beyond the §2.7.2 0,1 s bound on a
    /// PCR PID.
    pub pcr_interval_exceeded: u64,
    /// PAT / PMT sections that failed to parse — bad CRC, truncated
    /// or overrunning `section_length`, wrong `table_id`.
    pub bad_psi_sections: u64,
    /// §2.4.3.5 `splice_countdown` values that contradict the count
    /// of payload packets since the previous annotated packet on the
    /// PID (a positive value counts the remaining same-PID payload
    /// packets to the splicing point; negatives count past it —
    /// duplicates and payload-less packets excluded).
    pub splice_countdown_inconsistent: u64,
    /// §2.4.3.5 seamless-splice run breaks: once `seamless_splice`
    /// is signalled with a positive countdown it must appear — with
    /// identical `splice_type` and `DTS_next_AU` — on every
    /// subsequent packet of the PID whose `splicing_point_flag` is
    /// set, through the countdown-zero packet.
    pub seamless_splice_run_broken: u64,
    /// §2.4.3.5: `splice_type` shall be `'0000'` when the PID's PMT
    /// `stream_type` classifies it as audio.
    pub nonzero_splice_type_on_audio: u64,
}

impl ViolationCounts {
    /// `true` when every tally is zero.
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

/// Per-PID packet statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PidReport {
    /// Packets seen on this PID.
    pub packets: u64,
    /// Packets with a non-zero `transport_scrambling_control`.
    pub scrambled: u64,
    /// §2.4.3.3 continuity errors (drops + over-cap duplicates).
    pub continuity_errors: u64,
    /// Spec-permitted duplicates (first repeat of a CC value).
    pub duplicates: u64,
}

/// PCR health for one PCR PID (§2.4.2.2 / §2.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrReport {
    /// The PCR PID (as named by one or more PMTs).
    pub pid: u16,
    /// PCR samples observed.
    pub samples: u64,
    /// Largest interval between consecutive PCRs, in 27 MHz ticks
    /// (`None` with fewer than two samples). Compare against
    /// [`MAX_PCR_INTERVAL_27MHZ`]; signalled discontinuities reset the
    /// interval measurement instead of inflating it.
    pub max_interval_27mhz: Option<u64>,
    /// Time-base discontinuities signalled via the
    /// `discontinuity_indicator` on this PID (§2.4.3.5).
    pub signalled_discontinuities: u64,
    /// Transport-rate estimate in bits/second from the byte span
    /// between the first and last PCR against their tick span
    /// (§2.4.2.2 delivery model). `None` with fewer than two samples
    /// or across a signalled discontinuity.
    pub estimated_rate_bps: Option<u64>,
}

/// Everything [`validate_ts`] learned about a stream.
#[derive(Debug, Clone, Default)]
pub struct TsValidationReport {
    /// Physical packet framing the buffer was walked with (`None`
    /// when no consistent sync grid was found — the report then
    /// covers zero packets).
    pub layout: Option<TsPacketLayout>,
    /// Whole packets examined.
    pub packets: u64,
    /// Packets that failed to parse (bad sync byte mid-stream,
    /// truncated adaptation field, …).
    pub unparseable_packets: u64,
    /// Null-PID (0x1FFF) padding packets.
    pub null_packets: u64,
    /// `(program_number, pmt_pid)` pairs advertised by the PAT
    /// (network entries excluded).
    pub programs: Vec<(u16, u16)>,
    /// One record per distinct PCR PID named by a PMT.
    pub pcr: Vec<PcrReport>,
    /// Per-PID statistics, keyed by PID.
    pub pids: BTreeMap<u16, PidReport>,
    /// Normative-rule violation tallies.
    pub violations: ViolationCounts,
    /// Complete PAT sections seen.
    pub pat_sections: u64,
    /// Largest gap between consecutive PAT section starts, in packets
    /// (`None` with fewer than two PATs). With the rate estimate this
    /// yields the tune-in latency figure.
    pub pat_max_gap_packets: Option<u64>,
}

impl TsValidationReport {
    /// `true` when the stream broke no checked rule and every packet
    /// parsed.
    pub fn is_conformant(&self) -> bool {
        self.violations.is_clean() && self.unparseable_packets == 0
    }
}

/// Internal per-PCR-PID accumulator.
#[derive(Debug, Clone, Copy)]
struct PcrState {
    pid: u16,
    samples: u64,
    /// Last PCR in 27 MHz ticks + the byte offset of its packet.
    last: Option<(u64, u64)>,
    /// First PCR of the current continuous (no signalled
    /// discontinuity) run, for the rate estimate.
    anchor: Option<(u64, u64)>,
    max_interval: Option<u64>,
    signalled_discontinuities: u64,
    /// Discontinuity announced; the next PCR re-anchors silently.
    pending_discontinuity: bool,
}

impl PcrState {
    fn new(pid: u16) -> Self {
        Self {
            pid,
            samples: 0,
            last: None,
            anchor: None,
            max_interval: None,
            signalled_discontinuities: 0,
            pending_discontinuity: false,
        }
    }
}

/// Validate a complete transport-stream byte buffer. See the module
/// docs for the rule set. The buffer must start on a packet boundary;
/// trailing partial-packet bytes are ignored.
pub fn validate_ts(bytes: &[u8]) -> TsValidationReport {
    let mut report = TsValidationReport::default();
    let layout = match detect_packet_layout(bytes) {
        Some(l) => l,
        None => return report,
    };
    report.layout = Some(layout);
    let psize = layout.packet_size;

    // ---- Pass 1: PSI discovery (PAT → PMTs → PCR PIDs). ----
    let mut pat_assembler = PsiSectionAssembler::new();
    let mut pmt_assemblers: BTreeMap<u16, PsiSectionAssembler> = BTreeMap::new();
    let mut pmt_pids: BTreeSet<u16> = BTreeSet::new();
    let mut pcr_states: Vec<PcrState> = Vec::new();
    let mut audio_pids: BTreeSet<u16> = BTreeSet::new();
    let mut pat_packet_indices: Vec<u64> = Vec::new();

    let mut idx: u64 = 0;
    for chunk in bytes.chunks_exact(psize) {
        let window = layout.window(chunk);
        if let Ok(pkt) = TsPacket::parse(window) {
            if pkt.pid == PAT_PID && !pkt.payload.is_empty() {
                if pkt.payload_unit_start {
                    pat_packet_indices.push(idx);
                }
                if let Ok(sections) =
                    pat_assembler.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
                {
                    for section in &sections {
                        match ProgramAssociationTable::parse(section) {
                            Ok(pat) => {
                                report.pat_sections += 1;
                                for (prog, pid) in &pat.programs {
                                    if *prog == 0 {
                                        continue; // network PID entry
                                    }
                                    if !report.programs.iter().any(|(p, _)| p == prog) {
                                        report.programs.push((*prog, *pid));
                                    }
                                    pmt_pids.insert(*pid);
                                }
                            }
                            Err(_) => report.violations.bad_psi_sections += 1,
                        }
                    }
                }
            } else if pmt_pids.contains(&pkt.pid) && !pkt.payload.is_empty() {
                let asm = pmt_assemblers.entry(pkt.pid).or_default();
                if let Ok(sections) =
                    asm.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
                {
                    for section in &sections {
                        match ProgramMapTable::parse(section) {
                            Ok(pmt) => {
                                if pmt.pcr_pid != NULL_PID
                                    && !pcr_states.iter().any(|s| s.pid == pmt.pcr_pid)
                                {
                                    pcr_states.push(PcrState::new(pmt.pcr_pid));
                                }
                                for stream in &pmt.streams {
                                    if crate::StreamType::from_raw(stream.stream_type).is_audio() {
                                        audio_pids.insert(stream.elementary_pid);
                                    }
                                }
                            }
                            Err(_) => report.violations.bad_psi_sections += 1,
                        }
                    }
                }
            }
        }
        idx += 1;
    }
    report.pat_max_gap_packets = pat_packet_indices
        .windows(2)
        .map(|w| w[1] - w[0])
        .max()
        .filter(|_| pat_packet_indices.len() >= 2);

    // ---- Pass 2: packet-level checks. ----
    let mut cc_trackers: BTreeMap<u16, ContinuityTracker> = BTreeMap::new();
    // §2.4.3.5 splice-signalling coherence, per PID: the countdown at
    // the last annotated packet, the payload packets seen since, and
    // the locked seamless pair while a positive run is in flight.
    #[derive(Default)]
    struct SpliceRun {
        /// `(countdown_at_last_annotation, payload_packets_since)`.
        last: Option<(i32, i32)>,
        /// `(splice_type, DTS_next_AU)` locked by the active run.
        seamless: Option<(u8, u64)>,
    }
    let mut splice_runs: BTreeMap<u16, SpliceRun> = BTreeMap::new();
    let mut offset: u64 = 0;
    for chunk in bytes.chunks_exact(psize) {
        let window = layout.window(chunk);
        report.packets += 1;

        // Raw header bits first — the reserved AF control keeps the
        // packet parseable enough to classify even when `parse` also
        // succeeds.
        if window[0] != crate::packet::TS_SYNC_BYTE {
            report.unparseable_packets += 1;
            offset += psize as u64;
            continue;
        }
        let afc = (window[3] >> 4) & 0b11;
        if afc == 0b00 {
            report.violations.reserved_afc += 1;
        }

        let pkt = match TsPacket::parse(window) {
            Ok(p) => p,
            Err(_) => {
                report.unparseable_packets += 1;
                offset += psize as u64;
                continue;
            }
        };

        if pkt.pid == NULL_PID {
            report.null_packets += 1;
            offset += psize as u64;
            continue;
        }

        let pid_report = report.pids.entry(pkt.pid).or_default();
        pid_report.packets += 1;
        if pkt.transport_scrambling_control != 0 {
            pid_report.scrambled += 1;
        }
        if pkt.transport_error {
            report.violations.transport_error_packets += 1;
        }

        let discontinuity = pkt
            .adaptation_field
            .as_ref()
            .is_some_and(|af| af.discontinuity_indicator);

        // §2.4.3.3 continuity counter.
        let has_payload = (afc & 0b01) != 0;
        let tracker = cc_trackers.entry(pkt.pid).or_default();
        let cc_event = tracker.observe(pkt.continuity_counter, has_payload, discontinuity);
        match cc_event {
            ContinuityEvent::Dropped { .. } => {
                pid_report.continuity_errors += 1;
                report.violations.continuity_errors += 1;
            }
            ContinuityEvent::Duplicate => pid_report.duplicates += 1,
            _ => {}
        }

        // §2.4.3.5 splice-signalling coherence. The countdown counts
        // same-PID payload packets, duplicates and payload-less
        // packets excluded.
        {
            let run = splice_runs.entry(pkt.pid).or_default();
            let counts = has_payload && cc_event != ContinuityEvent::Duplicate;
            if counts {
                if let Some((_, since)) = &mut run.last {
                    *since += 1;
                }
            }
            let countdown = pkt
                .adaptation_field
                .as_ref()
                .and_then(|af| af.splice_countdown)
                .map(i32::from);
            let seamless_pair = pkt
                .adaptation_field
                .as_ref()
                .and_then(|af| af.adaptation_field_extension.as_ref())
                .and_then(|ext| match (ext.splice_type, ext.dts_next_au) {
                    (Some(t), Some(d)) => Some((t, d)),
                    _ => None,
                });
            let expected = run.last.map(|(c, since)| c - since);
            if let Some(c) = countdown {
                match expected {
                    // A fresh positive countdown may start once the
                    // previous run's splicing point has passed.
                    Some(e) if e < 0 && c > 0 => {}
                    Some(e) if c != e => {
                        report.violations.splice_countdown_inconsistent += 1;
                    }
                    _ => {}
                }
                // Seamless-run continuation (§2.4.3.5: once set with a
                // positive countdown, set — with identical values —
                // until the countdown-zero packet inclusive).
                match (&run.seamless, seamless_pair) {
                    (Some(locked), Some(pair)) if *locked != pair => {
                        report.violations.seamless_splice_run_broken += 1;
                    }
                    (Some(_), None) => {
                        report.violations.seamless_splice_run_broken += 1;
                    }
                    (None, Some(pair)) if c > 0 => run.seamless = Some(pair),
                    _ => {}
                }
                if let Some((splice_type, _)) = seamless_pair {
                    if splice_type != 0 && audio_pids.contains(&pkt.pid) {
                        report.violations.nonzero_splice_type_on_audio += 1;
                    }
                }
                if c <= 0 {
                    // The splicing point is reached (or behind us) —
                    // the seamless obligation ends here.
                    run.seamless = None;
                }
                run.last = Some((c, 0));
            } else if let Some(e) = expected {
                if e < -128 {
                    // Stale: no annotation for longer than the field
                    // could describe.
                    run.last = None;
                    run.seamless = None;
                } else if e == 0 && counts && run.seamless.is_some() {
                    // The packet where the countdown reaches zero must
                    // still carry the seamless fields — reaching it
                    // unannotated breaks the run.
                    report.violations.seamless_splice_run_broken += 1;
                    run.seamless = None;
                }
            }
        }

        if let Some(af) = &pkt.adaptation_field {
            // §2.4.3.5 AF length bounds per AF control value.
            let bad_len = match afc {
                0b10 => af.length != 183,
                0b11 => af.length > 182,
                _ => false,
            };
            if bad_len {
                report.violations.bad_af_length += 1;
            }
            // §2.4.3.5 OPCR pairing.
            if af.opcr_flag && !af.pcr_flag {
                report.violations.opcr_without_pcr += 1;
            }
            // §2.4.3.5 seamless-splice pairing.
            if let Some(ext) = &af.adaptation_field_extension {
                if ext.seamless_splice_flag && !af.splicing_point_flag {
                    report.violations.seamless_splice_without_splicing_point += 1;
                }
            }
            // §2.4.3.5 RAI-on-PCR-PID pairing + §2.7.2 PCR cadence.
            if let Some(state) = pcr_states.iter_mut().find(|s| s.pid == pkt.pid) {
                if af.random_access_indicator && !af.pcr_flag {
                    report.violations.rai_without_pcr_on_pcr_pid += 1;
                }
                if discontinuity {
                    state.signalled_discontinuities += 1;
                    state.pending_discontinuity = true;
                }
                if let (Some(base), ext_val) = (af.pcr_base, af.pcr_extension.unwrap_or(0)) {
                    // §2.4.3.4 bounds program_clock_reference_extension to
                    // 0..=299, but the 9-bit wire field can carry up to 511;
                    // a hostile extension pushes `ticks` past the modulus and
                    // a later in-range PCR would underflow the wrap delta.
                    // Fold into range so the interval math stays total — the
                    // stream is nonconforming either way.
                    let ticks = (base * 300 + u64::from(ext_val)) % crate::PCR_MODULUS_27MHZ;
                    state.samples += 1;
                    if state.pending_discontinuity || state.last.is_none() {
                        // New time base (or first sample): re-anchor,
                        // no interval measured across the break.
                        state.pending_discontinuity = false;
                        state.anchor = Some((ticks, offset));
                    } else if let Some((prev_ticks, _)) = state.last {
                        let modulus = crate::PCR_MODULUS_27MHZ;
                        let delta = (ticks + modulus - prev_ticks) % modulus;
                        state.max_interval = Some(state.max_interval.unwrap_or(0).max(delta));
                        if delta > MAX_PCR_INTERVAL_27MHZ {
                            report.violations.pcr_interval_exceeded += 1;
                        }
                    }
                    state.last = Some((ticks, offset));
                }
            }
        }
        offset += psize as u64;
    }

    report.pcr = pcr_states
        .iter()
        .map(|s| PcrReport {
            pid: s.pid,
            samples: s.samples,
            max_interval_27mhz: s.max_interval,
            signalled_discontinuities: s.signalled_discontinuities,
            estimated_rate_bps: match (s.anchor, s.last) {
                (Some((t0, o0)), Some((t1, o1))) if o1 > o0 && t1 != t0 => {
                    let modulus = crate::PCR_MODULUS_27MHZ;
                    let ticks = (t1 + modulus - t0) % modulus;
                    if ticks == 0 {
                        None
                    } else {
                        // bits × 27 MHz / ticks, in 128-bit to dodge
                        // overflow on long spans.
                        let bits = (o1 - o0) as u128 * 8;
                        u64::try_from(bits * 27_000_000 / ticks as u128).ok()
                    }
                }
                _ => None,
            },
        })
        .collect();

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;
    use crate::packet::{AdaptationFieldSpec, TS_PACKET_LEN, TS_SYNC_BYTE};

    /// Build one 188-byte TS packet.
    fn ts_packet(
        pid: u16,
        pusi: bool,
        cc: u8,
        afc: u8,
        af: Option<&[u8]>,
        payload: &[u8],
        psi: bool,
    ) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = (if pusi { 0b0100_0000 } else { 0 }) | ((pid >> 8) as u8 & 0x1F);
        pkt[2] = pid as u8;
        pkt[3] = (afc << 4) | (cc & 0x0F);
        let mut off = 4usize;
        if let Some(af_bytes) = af {
            pkt[off..off + af_bytes.len()].copy_from_slice(af_bytes);
            off += af_bytes.len();
        }
        if psi && pusi {
            pkt[off] = 0; // pointer_field
            off += 1;
        }
        pkt[off..off + payload.len()].copy_from_slice(payload);
        // PSI stuffing stays 0xFF; PES-side callers size their AF so
        // the payload fills the packet exactly.
        pkt
    }

    /// Assemble a minimal single-program TS: PAT, PMT (PCR PID =
    /// video PID 0x101), then `n_pes` one-packet video PES units with
    /// a PCR on each PES start, ~30 ms apart (inside the §2.7.2
    /// bound).
    fn clean_stream(n_pes: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let pat = build::build_pat(1, 0, &[(1, 0x0100)]);
        out.extend_from_slice(&ts_packet(0x0000, true, 0, 0b01, None, &pat, true));
        let pmt = build::build_pmt(
            1,
            0,
            0x0101,
            &[],
            &[build::PmtStreamEntry {
                stream_type: 0x1B,
                elementary_pid: 0x0101,
                es_info: Vec::new(),
            }],
        );
        out.extend_from_slice(&ts_packet(0x0100, true, 0, 0b01, None, &pmt, true));

        // Tiny video PES with no timestamps: 6-byte header + flags.
        let pes: &[u8] = &[
            0x00,
            0x00,
            0x01,
            0xE0,
            0x00,
            0x08, // PES_packet_length = 8
            0b1000_0000,
            0b0000_0000,
            0x00, // no optional fields
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE, // payload
        ];
        for i in 0..n_pes {
            // PCR every packet, 30 ms (810_000 ticks) apart.
            let base = (i as u64) * 2_700; // 90 kHz: 30 ms
            let af = AdaptationFieldSpec::with_pcr(base, 0)
                .encode(Some(TS_PACKET_LEN - 4 - pes.len()))
                .unwrap();
            out.extend_from_slice(&ts_packet(
                0x0101,
                true,
                (i % 16) as u8,
                0b11,
                Some(&af),
                pes,
                false,
            ));
        }
        out
    }

    /// One payload packet on `pid` with optional splice fields, AF
    /// stuffed so the payload fills the packet.
    fn splice_pkt(
        pid: u16,
        cc: u8,
        countdown: Option<i8>,
        seamless: Option<(u8, u64)>,
        payload_len: usize,
    ) -> [u8; TS_PACKET_LEN] {
        let spec = AdaptationFieldSpec {
            splice_countdown: countdown,
            extension: seamless.map(|(t, d)| crate::AdaptationFieldExtensionSpec {
                seamless_splice: Some((t, d)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let af = spec.encode(Some(TS_PACKET_LEN - 4 - payload_len)).unwrap();
        ts_packet(
            pid,
            false,
            cc,
            0b11,
            Some(&af),
            &vec![0xAB; payload_len],
            false,
        )
    }

    /// §2.4.3.5 splice_countdown progression: exact counts (with
    /// sparse annotation) pass; a value contradicting the payload
    /// packet count is flagged.
    #[test]
    fn splice_countdown_progression_checked() {
        let pid = 0x0102;
        // Consistent: 3, (unannotated), 1, 0, -1.
        let mut bytes = clean_stream(2);
        for (i, (c, s)) in [
            (Some(3i8), None),
            (None, None),
            (Some(1), None),
            (Some(0), None),
            (Some(-1), None),
        ]
        .into_iter()
        .enumerate()
        {
            bytes.extend_from_slice(&splice_pkt(pid, i as u8, c, s, 32));
        }
        let report = validate_ts(&bytes);
        assert_eq!(report.violations.splice_countdown_inconsistent, 0);
        assert!(report.is_conformant(), "{:?}", report.violations);

        // Inconsistent: 2 then 0 with only one payload packet between.
        let mut bytes = clean_stream(2);
        bytes.extend_from_slice(&splice_pkt(pid, 0, Some(2), None, 32));
        bytes.extend_from_slice(&splice_pkt(pid, 1, Some(0), None, 32));
        let report = validate_ts(&bytes);
        assert_eq!(report.violations.splice_countdown_inconsistent, 1);
        assert!(!report.is_conformant());
    }

    /// §2.4.3.5 seamless-splice continuation: dropping the fields (or
    /// changing their values) mid-run is flagged; a clean run is not.
    #[test]
    fn seamless_splice_run_continuity_checked() {
        let pid = 0x0102;
        let pair = Some((0x3u8, 48_000u64));
        // Clean run: 2, 1, 0 all carrying the same pair.
        let mut bytes = clean_stream(2);
        for (i, c) in [2i8, 1, 0].into_iter().enumerate() {
            bytes.extend_from_slice(&splice_pkt(pid, i as u8, Some(c), pair, 32));
        }
        let report = validate_ts(&bytes);
        assert_eq!(report.violations.seamless_splice_run_broken, 0);
        assert!(report.is_conformant(), "{:?}", report.violations);

        // Broken run: the fields vanish on the countdown-1 packet.
        let mut bytes = clean_stream(2);
        bytes.extend_from_slice(&splice_pkt(pid, 0, Some(2), pair, 32));
        bytes.extend_from_slice(&splice_pkt(pid, 1, Some(1), None, 32));
        let report = validate_ts(&bytes);
        assert_eq!(report.violations.seamless_splice_run_broken, 1);

        // Broken run: DTS_next_AU changes mid-run.
        let mut bytes = clean_stream(2);
        bytes.extend_from_slice(&splice_pkt(pid, 0, Some(2), pair, 32));
        bytes.extend_from_slice(&splice_pkt(pid, 1, Some(1), Some((0x3, 50_000)), 32));
        let report = validate_ts(&bytes);
        assert_eq!(report.violations.seamless_splice_run_broken, 1);
    }

    /// §2.4.3.5: a non-zero splice_type on a PMT-typed audio PID is
    /// flagged.
    #[test]
    fn nonzero_splice_type_on_audio_checked() {
        let mut out = Vec::new();
        let pat = build::build_pat(1, 0, &[(1, 0x0100)]);
        out.extend_from_slice(&ts_packet(0x0000, true, 0, 0b01, None, &pat, true));
        let pmt = build::build_pmt(
            1,
            0,
            0x0102,
            &[],
            &[build::PmtStreamEntry {
                stream_type: 0x03, // MPEG-1 audio
                elementary_pid: 0x0102,
                es_info: Vec::new(),
            }],
        );
        out.extend_from_slice(&ts_packet(0x0100, true, 0, 0b01, None, &pmt, true));
        out.extend_from_slice(&splice_pkt(0x0102, 0, Some(1), Some((0x2, 900)), 32));
        out.extend_from_slice(&splice_pkt(0x0102, 1, Some(0), Some((0x2, 900)), 32));
        let report = validate_ts(&out);
        assert_eq!(report.violations.nonzero_splice_type_on_audio, 2);
        assert!(!report.is_conformant());

        // splice_type 0 on the same audio PID is fine.
        let mut out = Vec::new();
        let pat = build::build_pat(1, 0, &[(1, 0x0100)]);
        out.extend_from_slice(&ts_packet(0x0000, true, 0, 0b01, None, &pat, true));
        let pmt = build::build_pmt(
            1,
            0,
            0x0102,
            &[],
            &[build::PmtStreamEntry {
                stream_type: 0x03,
                elementary_pid: 0x0102,
                es_info: Vec::new(),
            }],
        );
        out.extend_from_slice(&ts_packet(0x0100, true, 0, 0b01, None, &pmt, true));
        out.extend_from_slice(&splice_pkt(0x0102, 0, Some(1), Some((0x0, 900)), 32));
        out.extend_from_slice(&splice_pkt(0x0102, 1, Some(0), Some((0x0, 900)), 32));
        let report = validate_ts(&out);
        assert_eq!(report.violations.nonzero_splice_type_on_audio, 0);
    }

    #[test]
    fn clean_stream_validates_conformant() {
        let bytes = clean_stream(8);
        let report = validate_ts(&bytes);
        assert!(
            report.is_conformant(),
            "violations: {:?}",
            report.violations
        );
        assert_eq!(report.layout, Some(TsPacketLayout::STANDARD));
        assert_eq!(report.packets, 10);
        assert_eq!(report.programs, vec![(1, 0x0100)]);
        assert_eq!(report.pcr.len(), 1);
        let pcr = &report.pcr[0];
        assert_eq!(pcr.pid, 0x0101);
        assert_eq!(pcr.samples, 8);
        // 30 ms spacing = 810_000 ticks of 27 MHz.
        assert_eq!(pcr.max_interval_27mhz, Some(810_000));
        assert!(pcr.estimated_rate_bps.unwrap() > 0);
        assert_eq!(report.pat_sections, 1);
        assert_eq!(report.pids[&0x0101].packets, 8);
    }

    #[test]
    fn cc_gap_and_transport_error_flagged() {
        let mut bytes = clean_stream(6);
        // Corrupt the CC of the 4th PES packet (packet index 5):
        // bump it by 2.
        let p = 5 * TS_PACKET_LEN;
        bytes[p + 3] = (bytes[p + 3] & 0xF0) | ((bytes[p + 3].wrapping_add(2)) & 0x0F);
        // Set transport_error_indicator on the last packet.
        let q = 7 * TS_PACKET_LEN;
        bytes[q + 1] |= 0b1000_0000;
        let report = validate_ts(&bytes);
        assert!(!report.is_conformant());
        // The CC bump breaks the chain twice (jump forward, then the
        // next packet's original CC no longer follows).
        assert!(report.violations.continuity_errors >= 1);
        assert_eq!(report.violations.transport_error_packets, 1);
        assert!(report.pids[&0x0101].continuity_errors >= 1);
    }

    #[test]
    fn pcr_gap_beyond_bound_flagged_unless_signalled() {
        // Two PES packets whose PCRs sit 200 ms apart — over the
        // §2.7.2 0,1 s bound.
        let mut out = Vec::new();
        let pat = build::build_pat(1, 0, &[(1, 0x0100)]);
        out.extend_from_slice(&ts_packet(0x0000, true, 0, 0b01, None, &pat, true));
        let pmt = build::build_pmt(
            1,
            0,
            0x0101,
            &[],
            &[build::PmtStreamEntry {
                stream_type: 0x1B,
                elementary_pid: 0x0101,
                es_info: Vec::new(),
            }],
        );
        out.extend_from_slice(&ts_packet(0x0100, true, 0, 0b01, None, &pmt, true));
        let pes: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x00, 0x04, 0b1000_0000, 0, 0, 0x42];
        for (i, base) in [(0u8, 0u64), (1, 18_000)] {
            // 18_000 ticks of 90 kHz = 200 ms.
            let af = AdaptationFieldSpec::with_pcr(base, 0)
                .encode(Some(TS_PACKET_LEN - 4 - pes.len()))
                .unwrap();
            out.extend_from_slice(&ts_packet(0x0101, true, i, 0b11, Some(&af), pes, false));
        }
        let report = validate_ts(&out);
        assert_eq!(report.violations.pcr_interval_exceeded, 1);
        assert_eq!(report.pcr[0].max_interval_27mhz, Some(5_400_000));

        // Same stream, but the second PCR announces a discontinuity —
        // the gap is then legitimate.
        let mut out2 = out.clone();
        let last = 3 * TS_PACKET_LEN;
        // Set discontinuity_indicator inside the AF flags byte.
        out2[last + 5] |= 0b1000_0000;
        let report2 = validate_ts(&out2);
        assert_eq!(report2.violations.pcr_interval_exceeded, 0);
        assert_eq!(report2.pcr[0].signalled_discontinuities, 1);
    }

    #[test]
    fn out_of_range_pcr_extension_then_small_pcr_stays_total() {
        // §2.4.3.4 bounds pcr_extension to 0..=299, but the 9-bit wire
        // field carries up to 511. A max-base + ext=511 sample used to
        // push `ticks` past the modulus, and the next in-range PCR
        // underflowed the wrap-delta subtraction. Validation must stay
        // total and keep counting on such nonconforming input.
        let mut out = Vec::new();
        let pat = build::build_pat(1, 0, &[(1, 0x0100)]);
        out.extend_from_slice(&ts_packet(0x0000, true, 0, 0b01, None, &pat, true));
        let pmt = build::build_pmt(
            1,
            0,
            0x0101,
            &[],
            &[build::PmtStreamEntry {
                stream_type: 0x1B,
                elementary_pid: 0x0101,
                es_info: Vec::new(),
            }],
        );
        out.extend_from_slice(&ts_packet(0x0100, true, 0, 0b01, None, &pmt, true));
        let pes: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x00, 0x04, 0b1000_0000, 0, 0, 0x42];
        for (i, (base, ext)) in [((1u64 << 33) - 1, 511u16), (0, 0)].into_iter().enumerate() {
            let af = AdaptationFieldSpec::with_pcr(base, ext)
                .encode(Some(TS_PACKET_LEN - 4 - pes.len()))
                .unwrap();
            out.extend_from_slice(&ts_packet(0x0101, true, i as u8, 0b11, Some(&af), pes, false));
        }
        let report = validate_ts(&out);
        let pcr = report.pcr.iter().find(|p| p.pid == 0x0101).expect("pcr pid tracked");
        assert_eq!(pcr.samples, 2);
    }

    #[test]
    fn af_pairing_violations_flagged() {
        let mut out = clean_stream(2);

        // Packet with OPCR but no PCR: AF flags byte = OPCR only.
        let mut af = vec![0u8; 9];
        af[0] = 8; // adaptation_field_length
        af[1] = 0b0000_1000; // OPCR_flag only
                             // 6 OPCR bytes (any) + trailing stuffing byte already zeroed.
        out.extend_from_slice(&ts_packet(
            0x0101,
            false,
            2,
            0b11,
            Some(&af),
            &[0xAB; 175],
            false,
        ));

        // Packet whose AF extension sets seamless_splice without
        // splicing_point_flag.
        // length, extension-only flags, ext length,
        // seamless_splice_flag, then DTS bytes + markers.
        let mut af2 = vec![8u8, 0b0000_0001, 6, 0b0010_0000];
        af2.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x01]);
        out.extend_from_slice(&ts_packet(
            0x0101,
            false,
            3,
            0b11,
            Some(&af2),
            &[0xCD; 175],
            false,
        ));

        // RAI on the PCR PID without a PCR.
        let af3 = vec![1u8, 0b0100_0000];
        out.extend_from_slice(&ts_packet(
            0x0101,
            false,
            4,
            0b11,
            Some(&af3),
            &[0xEF; 182],
            false,
        ));

        // AF-only packet with a length under 183.
        let af4 = AdaptationFieldSpec::default().encode(Some(20)).unwrap();
        out.extend_from_slice(&ts_packet(0x0101, false, 4, 0b10, Some(&af4), &[], false));

        let report = validate_ts(&out);
        assert_eq!(report.violations.opcr_without_pcr, 1);
        assert_eq!(report.violations.seamless_splice_without_splicing_point, 1);
        assert_eq!(report.violations.rai_without_pcr_on_pcr_pid, 1);
        assert_eq!(report.violations.bad_af_length, 1);
    }

    #[test]
    fn reserved_afc_and_null_packets_classified() {
        let mut bytes = clean_stream(2);
        // A null packet (afc must be '01' per §2.4.3.3).
        bytes.extend_from_slice(&ts_packet(
            NULL_PID,
            false,
            0,
            0b01,
            None,
            &[0xFF; 10],
            false,
        ));
        // A packet with the reserved AF control '00'.
        bytes.extend_from_slice(&ts_packet(0x0101, false, 2, 0b00, None, &[], false));
        let report = validate_ts(&bytes);
        assert_eq!(report.null_packets, 1);
        assert_eq!(report.violations.reserved_afc, 1);
    }

    #[test]
    fn corrupt_psi_crc_counted() {
        let mut bytes = clean_stream(2);
        // Flip a byte inside the PAT body (packet 0, after the
        // pointer field) so its CRC no longer matches.
        bytes[4 + 1 + 3] ^= 0xFF;
        let report = validate_ts(&bytes);
        assert_eq!(report.violations.bad_psi_sections, 1);
        // The PAT never parsed → no programs discovered, and the
        // report says so rather than crashing.
        assert!(report.programs.is_empty());
        assert_eq!(report.pat_sections, 0);
    }

    #[test]
    fn garbage_and_truncation_are_bounded() {
        // Pure garbage: no layout, empty report.
        let report = validate_ts(&[0xAB; 4096]);
        assert_eq!(report.layout, None);
        assert_eq!(report.packets, 0);

        // A clean stream with a truncated tail packet: the partial
        // chunk is ignored, everything before it still validates.
        let mut bytes = clean_stream(4);
        bytes.extend_from_slice(&[0x47, 0x01, 0x01]); // 3 stray bytes
        let report = validate_ts(&bytes);
        assert_eq!(report.packets, 6);
        assert!(report.is_conformant(), "{:?}", report.violations);

        // Mid-stream corruption: overwrite one whole packet with
        // garbage (past the 8-packet layout-detection window) — it
        // counts as unparseable, the rest still parses.
        let mut bytes = clean_stream(10);
        let p = 9 * TS_PACKET_LEN;
        for b in &mut bytes[p..p + TS_PACKET_LEN] {
            *b = 0x00;
        }
        let report = validate_ts(&bytes);
        assert_eq!(report.packets, 12);
        assert_eq!(report.unparseable_packets, 1);
        assert!(!report.is_conformant());
    }

    #[test]
    fn validates_192_byte_framing() {
        // Re-frame a clean stream as 192-byte source packets; the
        // validator must detect the layout and report identically.
        let plain = clean_stream(4);
        let mut framed = Vec::new();
        for pkt in plain.chunks(TS_PACKET_LEN) {
            framed.extend_from_slice(&[0, 0, 0, 0]);
            framed.extend_from_slice(pkt);
        }
        let report = validate_ts(&framed);
        assert_eq!(report.layout, Some(TsPacketLayout::PREFIXED_192));
        assert_eq!(report.packets, 6);
        assert!(report.is_conformant(), "{:?}", report.violations);
        assert_eq!(report.pcr[0].samples, 4);
    }
}

