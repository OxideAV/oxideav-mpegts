//! Transport Stream system target decoder — the **T-STD** buffer
//! model of ISO/IEC 13818-1 §2.4.2.
//!
//! The T-STD is the conceptual decoder the spec uses to *define*
//! Transport Stream conformance: bytes enter at a piecewise-constant
//! rate reconstructed from the PCR fields (§2.4.2.2 equations 2-1 to
//! 2-5), flow through a fixed 512-byte transport buffer per
//! elementary stream (`TBn`, §2.4.2.3), and land either in a main
//! buffer `Bn` (audio / system data) or in the multiplexing buffer
//! `MBn` that leaks into the elementary-stream buffer `EBn` (video),
//! from which whole access units are removed instantaneously at their
//! decode time (§2.4.2.4). A conformant stream keeps every buffer
//! inside the §2.4.2.6 constraints:
//!
//! * `TBn` / `TBsys` never overflow and empty at least once a second;
//! * `Bn` neither overflows nor underflows; `Bsys` never overflows;
//! * with the leak method, `MBn` never overflows and empties at least
//!   once a second; `EBn` never underflows;
//! * no byte spends more than one second in the decoder buffers
//!   (`tdn(j) − t(i) ≤ 1 s`).
//!
//! [`analyze_tstd`] replays a whole stream (any physical framing)
//! through this model and reports every violation. The model is
//! *fluid*: byte flows are treated as piecewise-linear in time, which
//! matches the spec's per-byte schedule to within one byte. Three
//! scope choices are documented rather than modelled:
//!
//! * Access units are **PES-granular** — each PES packet carrying a
//!   PTS/DTS starts an access unit removed at that decode time, and
//!   timestamp-less continuation PES packets extend it. A PES packet
//!   carrying several coded frames after one timestamp is treated as
//!   one access unit (frame boundaries are elementary-stream syntax
//!   this container crate does not parse).
//! * Video transfers use the §2.4.2.3 **leak method** only; the
//!   `vbv_delay` method needs picture-layer fields from the video
//!   elementary stream.
//! * Arrival times before the first PCR extrapolate the first
//!   interval's transport rate backward (the spec leaves `t(i)`
//!   defined only between PCR pairs); after the last PCR the last
//!   rate extends forward.
//!
//! Buffer sizes and rates that ISO/IEC 13818-1 fixes are provided as
//! constants; the ones it defines by formula over the video profile /
//! level tables of ISO/IEC 13818-2 ([`TStdStreamModel::video_low_main_level`],
//! [`TStdStreamModel::video_high_level`]) take the caller's `Rmax` /
//! VBV figures as inputs.

use std::collections::VecDeque;

use crate::packet::{detect_packet_layout, TsPacket};
use crate::TsError;

/// §2.4.2.3: "The transport buffer size is fixed at 512 bytes."
pub const TB_SIZE: usize = 512;
/// §2.4.2.3: "The main buffer Bsys for system data is of size
/// BSsys = 1536 bytes."
pub const BSYS_SIZE: usize = 1536;
/// §2.4.2.3 `Rxn` for non-ADTS audio: 2 × 10⁶ bit/s.
pub const AUDIO_RX_BPS: u64 = 2_000_000;
/// §2.4.2.3 `BSn` for non-ADTS audio: 3584 bytes.
pub const AUDIO_MAIN_BUFFER_SIZE: usize = 3584;
/// §2.4.2.3 `Rxsys`: 1 × 10⁶ bit/s.
pub const RXSYS_BPS: u64 = 1_000_000;
/// Equation 2-7 floor: `Rsys = max(80000, transport_rate × 8 / 500)`.
pub const RSYS_MIN_BPS: u64 = 80_000;
/// §2.4.2.6: maximum delay of any byte through the T-STD buffers.
pub const MAX_TSTD_DELAY_SECONDS: f64 = 1.0;

/// Fluid-model comparison slack: one byte, and one microsecond.
const BYTE_EPS: f64 = 1.0;
const TIME_EPS: f64 = 1e-6;

/// The downstream shape of one elementary stream's T-STD branch.
#[derive(Debug, Clone, PartialEq)]
pub enum TStdBranch {
    /// Audio / system-style: `TBn → Bn`, whole access units removed
    /// at their decode time (§2.4.2.3 "Buffer BSn").
    Main {
        /// `BSn` in bytes.
        buffer_size: usize,
    },
    /// Video: `TBn → MBn → EBn` with the §2.4.2.3 leak method.
    Video {
        /// Leak rate `Rbxn` in bit/s (`Rmax` for Low/Main level).
        rbx_bps: u64,
        /// `MBSn` in bytes (see the §2.4.2.3 formulas).
        mb_size: usize,
        /// `EBSn` in bytes — the stream's `vbv_buffer_size`.
        eb_size: usize,
    },
}

/// T-STD parameters for one elementary stream.
#[derive(Debug, Clone, PartialEq)]
pub struct TStdStreamModel {
    /// Transport-buffer drain rate `Rxn` in bit/s.
    pub rx_bps: u64,
    /// The downstream buffer chain.
    pub branch: TStdBranch,
}

impl TStdStreamModel {
    /// §2.4.2.3 non-ADTS audio: `Rxn = 2 Mbit/s`, `BSn = 3584` bytes.
    pub fn audio() -> Self {
        Self {
            rx_bps: AUDIO_RX_BPS,
            branch: TStdBranch::Main {
                buffer_size: AUDIO_MAIN_BUFFER_SIZE,
            },
        }
    }

    /// §2.4.2.3 video at Low or Main level. `rmax_bps` is
    /// `Rmax[profile, level]` and `vbv_max_bytes` is
    /// `VBVmax[profile, level]` (both from the ISO/IEC 13818-2
    /// tables, supplied by the caller); `vbv_buffer_size_bytes` is the
    /// value coded in the sequence header. Applies:
    ///
    /// * `Rxn  = 1.2 × Rmax`
    /// * `Rbxn = Rmax`
    /// * `MBSn = BSmux + BSoh + VBVmax − vbv_buffer_size` with
    ///   `BSoh = Rmax / 750 / 8` bytes and `BSmux = 0.004 s × Rmax`
    /// * `EBSn = vbv_buffer_size`
    pub fn video_low_main_level(
        rmax_bps: u64,
        vbv_buffer_size_bytes: usize,
        vbv_max_bytes: usize,
    ) -> Self {
        let bsoh = (rmax_bps / 750 / 8) as usize;
        let bsmux = (rmax_bps / 250 / 8) as usize; // 0.004 s × Rmax
        Self {
            rx_bps: rmax_bps + rmax_bps / 5,
            branch: TStdBranch::Video {
                rbx_bps: rmax_bps,
                mb_size: bsmux + bsoh + vbv_max_bytes.saturating_sub(vbv_buffer_size_bytes),
                eb_size: vbv_buffer_size_bytes,
            },
        }
    }

    /// §2.4.2.3 video at High-1440 or High level:
    /// `MBSn = BSmux + BSoh` (no VBV headroom term) and
    /// `Rbxn = min(1.05 × Res, Rmax)` — `res_bps` is the elementary
    /// stream's actual rate `Res`, or pass `rmax_bps` to keep the
    /// upper bound.
    pub fn video_high_level(rmax_bps: u64, res_bps: u64, vbv_buffer_size_bytes: usize) -> Self {
        let bsoh = (rmax_bps / 750 / 8) as usize;
        let bsmux = (rmax_bps / 250 / 8) as usize;
        Self {
            rx_bps: rmax_bps + rmax_bps / 5,
            branch: TStdBranch::Video {
                rbx_bps: (res_bps + res_bps / 20).min(rmax_bps),
                mb_size: bsmux + bsoh,
                eb_size: vbv_buffer_size_bytes,
            },
        }
    }
}

/// Configuration for one [`analyze_tstd`] run — the T-STD decodes one
/// program at a time (§2.4.2.2).
#[derive(Debug, Clone, Default)]
pub struct TStdConfig {
    /// The program's `PCR_PID` — drives the §2.4.2.2 arrival clock.
    pub pcr_pid: u16,
    /// `(PID, model)` for every elementary stream to model.
    pub streams: Vec<(u16, TStdStreamModel)>,
    /// PIDs routed to the system branch (`TBsys → Bsys`): §2.4.2.3
    /// names PID 0, PID 1, and the selected program's
    /// `program_map_PID`. The NIT PID is explicitly *not* transferred.
    pub system_pids: Vec<u16>,
}

impl TStdConfig {
    /// Convenience: a single-program configuration with the §2.4.2.3
    /// system routing (PAT PID 0, CAT PID 1, the program's PMT PID).
    pub fn single_program(
        pcr_pid: u16,
        pmt_pid: u16,
        streams: Vec<(u16, TStdStreamModel)>,
    ) -> Self {
        Self {
            pcr_pid,
            streams,
            system_pids: vec![0x0000, 0x0001, pmt_pid],
        }
    }
}

/// One §2.4.2.6 rule violation. At most one record per `(rule, PID)`
/// pair is kept (the first, with the worst figure updated in place);
/// [`TStdReport::violation_events`] counts every occurrence.
#[derive(Debug, Clone, PartialEq)]
pub enum TStdViolation {
    /// `TBn` (or `TBsys` for `pid == None`… reported with its PID
    /// here) exceeded its fixed 512-byte size.
    TbOverflow { pid: u16, peak_bytes: u64 },
    /// `TBn` stayed non-empty for more than one second (§2.4.2.6
    /// "shall empty at least once every second").
    TbBusyOverOneSecond { pid: u16, seconds: f64 },
    /// `Bn` exceeded `BSn` (audio / system-data main buffer).
    MainOverflow {
        pid: u16,
        peak_bytes: u64,
        limit: usize,
    },
    /// An access unit was not completely present in `Bn` at its
    /// decode time — the stream delivers its bytes too late.
    MainUnderflow {
        pid: u16,
        decode_time: f64,
        missing_bytes: u64,
    },
    /// `MBn` exceeded `MBSn` (video multiplexing buffer, leak method).
    MbOverflow {
        pid: u16,
        peak_bytes: u64,
        limit: usize,
    },
    /// `MBn` stayed non-empty for more than one second.
    MbBusyOverOneSecond { pid: u16, seconds: f64 },
    /// An access unit was not completely present in `EBn` at its
    /// decode time (leak-method `EBn` underflow).
    EbUnderflow {
        pid: u16,
        decode_time: f64,
        missing_bytes: u64,
    },
    /// A byte spent more than one second in the T-STD buffers
    /// (`tdn(j) − t(i) > 1 s`, §2.4.2.6).
    DelayOverOneSecond {
        pid: u16,
        decode_time: f64,
        delay_seconds: f64,
    },
    /// `Bsys` exceeded its fixed 1536-byte size.
    BsysOverflow { peak_bytes: u64 },
}

impl TStdViolation {
    /// `(discriminant, pid)` key for the once-per-rule-per-PID cap.
    fn key(&self) -> (u8, u16) {
        match self {
            TStdViolation::TbOverflow { pid, .. } => (0, *pid),
            TStdViolation::TbBusyOverOneSecond { pid, .. } => (1, *pid),
            TStdViolation::MainOverflow { pid, .. } => (2, *pid),
            TStdViolation::MainUnderflow { pid, .. } => (3, *pid),
            TStdViolation::MbOverflow { pid, .. } => (4, *pid),
            TStdViolation::MbBusyOverOneSecond { pid, .. } => (5, *pid),
            TStdViolation::EbUnderflow { pid, .. } => (6, *pid),
            TStdViolation::DelayOverOneSecond { pid, .. } => (7, *pid),
            TStdViolation::BsysOverflow { .. } => (8, 0),
        }
    }
}

/// Per-stream occupancy statistics.
#[derive(Debug, Clone, Default)]
pub struct TStdChainStats {
    /// The elementary PID (or the first system PID for the system
    /// chain).
    pub pid: u16,
    /// Peak `TBn` occupancy in bytes.
    pub peak_tb_bytes: u64,
    /// Peak downstream occupancy — `Bn` (main), `MBn` (video), or
    /// `Bsys` (system chain).
    pub peak_main_bytes: u64,
    /// Peak `EBn` occupancy (video chains only).
    pub peak_eb_bytes: u64,
    /// Access units removed (main / video chains).
    pub access_units: u64,
    /// Worst observed byte delay through the chain, in seconds.
    pub max_delay_seconds: f64,
}

/// The outcome of one [`analyze_tstd`] replay.
#[derive(Debug, Clone, Default)]
pub struct TStdReport {
    /// First violation per `(rule, PID)`, worst figure kept.
    pub violations: Vec<TStdViolation>,
    /// Total number of violating events (uncapped).
    pub violation_events: u64,
    /// Per-chain statistics (elementary streams, then the system
    /// chain when configured).
    pub chains: Vec<TStdChainStats>,
    /// PCR samples the arrival clock was reconstructed from.
    pub pcr_samples: usize,
    /// Modelled span in seconds (first to last byte arrival).
    pub modelled_seconds: f64,
}

impl TStdReport {
    /// `true` when the stream satisfied every modelled §2.4.2.6
    /// condition.
    pub fn is_conformant(&self) -> bool {
        self.violations.is_empty()
    }

    fn record(&mut self, v: TStdViolation) {
        self.violation_events += 1;
        let key = v.key();
        for existing in &mut self.violations {
            if existing.key() == key {
                // Keep the worst figure for the rule.
                merge_worse(existing, &v);
                return;
            }
        }
        self.violations.push(v);
    }
}

/// Update `a` in place with the worse of the two figures.
fn merge_worse(a: &mut TStdViolation, b: &TStdViolation) {
    use TStdViolation::*;
    match (a, b) {
        (TbOverflow { peak_bytes: pa, .. }, TbOverflow { peak_bytes: pb, .. })
        | (MainOverflow { peak_bytes: pa, .. }, MainOverflow { peak_bytes: pb, .. })
        | (MbOverflow { peak_bytes: pa, .. }, MbOverflow { peak_bytes: pb, .. })
        | (BsysOverflow { peak_bytes: pa }, BsysOverflow { peak_bytes: pb }) => {
            *pa = (*pa).max(*pb)
        }
        (TbBusyOverOneSecond { seconds: sa, .. }, TbBusyOverOneSecond { seconds: sb, .. })
        | (MbBusyOverOneSecond { seconds: sa, .. }, MbBusyOverOneSecond { seconds: sb, .. }) => {
            *sa = sa.max(*sb)
        }
        (
            MainUnderflow {
                missing_bytes: ma, ..
            },
            MainUnderflow {
                missing_bytes: mb, ..
            },
        )
        | (
            EbUnderflow {
                missing_bytes: ma, ..
            },
            EbUnderflow {
                missing_bytes: mb, ..
            },
        ) => *ma = (*ma).max(*mb),
        (
            DelayOverOneSecond {
                delay_seconds: da, ..
            },
            DelayOverOneSecond {
                delay_seconds: db, ..
            },
        ) => *da = da.max(*db),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// §2.4.2.2 arrival clock — t(i) from the PCR fields.
// ---------------------------------------------------------------------------

/// Full PCR modulus: the 33-bit base rides a ×300 extension.
const PCR_MODULUS_27MHZ: u64 = (1u64 << 33) * 300;

/// One piecewise-constant-rate interval of the arrival schedule.
#[derive(Debug, Clone, Copy)]
struct RateInterval {
    /// Logical byte position (188-byte grid) the interval starts at.
    start_pos: u64,
    /// Arrival-clock time of `start_pos`, in seconds.
    start_time: f64,
    /// Transport rate in bytes/second (equation 2-5).
    rate: f64,
    /// Maps a decode timestamp on this interval's time base onto the
    /// arrival clock: `td = extended_90k / 90000 + pts_offset`.
    pts_offset: f64,
    /// Extended 90 kHz PCR base at the interval start — the reference
    /// [`crate::clock::extend_near`] extends raw PES timestamps
    /// against.
    pcr_ref_90k: u64,
}

/// The reconstructed §2.4.2.2 arrival schedule.
#[derive(Debug)]
struct ArrivalClock {
    intervals: Vec<RateInterval>,
    /// Cursor for monotone lookups.
    cursor: usize,
}

impl ArrivalClock {
    /// Build the schedule from the PCR samples on `pcr_pid`.
    /// `samples` are `(logical_byte_pos_of_pcr_byte, raw_pcr_27mhz,
    /// discontinuity)` in stream order.
    fn build(samples: &[(u64, u64, bool)]) -> Result<Self, TsError> {
        if samples.len() < 2 {
            return Err(TsError::Unsupported(
                "T-STD model needs at least two PCRs on the PCR_PID",
            ));
        }
        let mut intervals = Vec::with_capacity(samples.len());
        let mut time_acc = 0.0f64;
        let mut ext_pcr = samples[0].1; // extended 27 MHz timeline
        let mut prev_rate: Option<f64> = None;
        for w in samples.windows(2) {
            let (pos0, _, _) = w[0];
            let (pos1, raw1, disc) = w[1];
            let bytes = (pos1 - pos0) as f64;
            if bytes <= 0.0 {
                continue;
            }
            let (dt, rate) = if disc {
                // §2.4.2.2: across a signalled time-base discontinuity
                // the transport rate between the last and next-to-last
                // PCR of the old base applies.
                let rate = prev_rate.ok_or(TsError::Unsupported(
                    "T-STD model: discontinuity before any rate is established",
                ))?;
                (bytes / rate, rate)
            } else {
                let delta =
                    (raw1 + PCR_MODULUS_27MHZ - (ext_pcr % PCR_MODULUS_27MHZ)) % PCR_MODULUS_27MHZ;
                if delta == 0 {
                    return Err(TsError::Unsupported(
                        "T-STD model: repeated PCR value on the PCR_PID",
                    ));
                }
                let dt = delta as f64 / 27_000_000.0;
                (dt, bytes / dt)
            };
            let ext_next = if disc {
                // New time base re-anchors at the raw value.
                raw1
            } else {
                ext_pcr
                    + ((raw1 + PCR_MODULUS_27MHZ - (ext_pcr % PCR_MODULUS_27MHZ))
                        % PCR_MODULUS_27MHZ)
            };
            let pcr_ref_90k = ext_pcr / 300;
            intervals.push(RateInterval {
                start_pos: pos0,
                start_time: time_acc,
                rate,
                pts_offset: time_acc - (ext_pcr as f64 / 27_000_000.0),
                pcr_ref_90k,
            });
            time_acc += dt;
            ext_pcr = ext_next;
            prev_rate = Some(rate);
        }
        if intervals.is_empty() {
            return Err(TsError::Unsupported(
                "T-STD model: no usable PCR interval on the PCR_PID",
            ));
        }
        Ok(Self {
            intervals,
            cursor: 0,
        })
    }

    /// Interval covering logical byte `pos` (monotone queries).
    fn interval_at(&mut self, pos: u64) -> &RateInterval {
        while self.cursor + 1 < self.intervals.len()
            && self.intervals[self.cursor + 1].start_pos <= pos
        {
            self.cursor += 1;
        }
        &self.intervals[self.cursor]
    }

    /// Arrival time of logical byte `pos` (equation 2-4; the first /
    /// last interval's rate extrapolates beyond the PCR span).
    fn time_of(&mut self, pos: u64) -> f64 {
        let iv = *self.interval_at(pos);
        if pos >= iv.start_pos {
            iv.start_time + (pos - iv.start_pos) as f64 / iv.rate
        } else {
            iv.start_time - (iv.start_pos - pos) as f64 / iv.rate
        }
    }

    /// Map a raw 33-bit 90 kHz decode timestamp seen at byte `pos`
    /// onto the arrival clock.
    fn decode_time_at(&mut self, pos: u64, raw_90k: u64) -> f64 {
        let iv = *self.interval_at(pos);
        let ext = crate::clock::extend_near(raw_90k, iv.pcr_ref_90k);
        ext as f64 / 90_000.0 + iv.pts_offset
    }

    /// Transport rate (bytes/s) applicable at byte `pos`.
    fn rate_at(&mut self, pos: u64) -> f64 {
        self.interval_at(pos).rate
    }
}

// ---------------------------------------------------------------------------
// Fluid FIFO with a constant drain — the TB stage.
// ---------------------------------------------------------------------------

/// Constant-drain fluid FIFO (`TBn` / `TBsys`). Tracks the virtual
/// completion clock, peak backlog, and busy stretches.
#[derive(Debug)]
struct FluidFifo {
    /// Drain rate in bytes/second.
    rate: f64,
    /// Time at which everything queued so far will have exited.
    virtual_done: f64,
    /// Start of the current busy stretch, or `None` while empty.
    busy_since: Option<f64>,
    /// Peak backlog in bytes.
    peak: f64,
    /// Longest busy stretch in seconds.
    longest_busy: f64,
}

impl FluidFifo {
    fn new(rate_bps: u64) -> Self {
        Self {
            rate: rate_bps as f64 / 8.0,
            virtual_done: f64::NEG_INFINITY,
            busy_since: None,
            peak: 0.0,
            longest_busy: 0.0,
        }
    }

    /// Feed `bytes` arriving linearly over `[t0, t1]`; returns the
    /// `(exit_start, exit_end)` window at which they leave.
    fn push(&mut self, t0: f64, t1: f64, bytes: f64) -> (f64, f64) {
        debug_assert!(t1 >= t0);
        if bytes <= 0.0 {
            let t = self.virtual_done.max(t0);
            return (t, t);
        }
        // Busy-stretch bookkeeping: an idle gap before this run closes
        // the previous stretch.
        match self.busy_since {
            Some(since) => {
                if self.virtual_done < t0 - TIME_EPS {
                    self.longest_busy = self.longest_busy.max(self.virtual_done - since);
                    self.busy_since = Some(t0);
                }
            }
            None => self.busy_since = Some(t0),
        }
        let start = self.virtual_done.max(t0);
        let end = t1.max(start + bytes / self.rate);
        // Peak backlog occurs at the arrival end of the run.
        let backlog_at_t1 = (end - t1) * self.rate;
        self.peak = self.peak.max(backlog_at_t1);
        self.virtual_done = end;
        if let Some(since) = self.busy_since {
            self.longest_busy = self.longest_busy.max(end - since);
        }
        (start, end)
    }
}

// ---------------------------------------------------------------------------
// Downstream branches.
// ---------------------------------------------------------------------------

/// A byte run delivered into a downstream buffer over `[t0, t1]`.
#[derive(Debug, Clone, Copy)]
struct Run {
    t0: f64,
    t1: f64,
    bytes: f64,
}

/// Piecewise-linear cumulative-arrival tracker: answers "how many
/// bytes arrived by time t" for monotone queries, dropping spent runs.
#[derive(Debug, Default)]
struct CumulativeIn {
    runs: VecDeque<Run>,
    /// Bytes of runs fully before the query frontier.
    settled: f64,
}

impl CumulativeIn {
    fn push(&mut self, t0: f64, t1: f64, bytes: f64) {
        if bytes > 0.0 {
            self.runs.push_back(Run { t0, t1, bytes });
        }
    }

    /// Cumulative bytes arrived by `t`. Queries must be monotone.
    fn arrived_by(&mut self, t: f64) -> f64 {
        while let Some(front) = self.runs.front() {
            if front.t1 <= t {
                self.settled += front.bytes;
                self.runs.pop_front();
            } else {
                break;
            }
        }
        let mut total = self.settled;
        for run in &self.runs {
            if run.t0 >= t {
                break;
            }
            let span = run.t1 - run.t0;
            let frac = if span <= 0.0 {
                1.0
            } else {
                ((t - run.t0) / span).clamp(0.0, 1.0)
            };
            total += run.bytes * frac;
        }
        total
    }

    /// Cumulative bytes once every queued run has fully arrived.
    fn final_total(&self) -> f64 {
        self.settled + self.runs.iter().map(|r| r.bytes).sum::<f64>()
    }

    /// Arrival-completion time of the `target`-th cumulative byte, or
    /// `None` when not yet queued.
    fn time_of_cumulative(&self, target: f64) -> Option<f64> {
        let mut acc = self.settled;
        if target <= acc {
            // Already settled — the exact instant is forgotten; report
            // the earliest still-tracked time.
            return Some(self.runs.front().map_or(f64::NEG_INFINITY, |r| r.t0));
        }
        for run in &self.runs {
            if target <= acc + run.bytes {
                let frac = (target - acc) / run.bytes;
                return Some(run.t0 + (run.t1 - run.t0) * frac);
            }
            acc += run.bytes;
        }
        None
    }
}

/// One pending access-unit removal.
#[derive(Debug, Clone, Copy)]
struct AccessUnit {
    /// Decode time on the arrival clock.
    decode_time: f64,
    /// Bytes removed from the branch's main buffer (PES header +
    /// payload for `Bn`; payload only for `EBn`).
    bytes: f64,
    /// T-STD input arrival time of the unit's first byte (drives the
    /// §2.4.2.6 delay bound).
    first_input_time: f64,
}

/// Audio / system-data main buffer `Bn`.
#[derive(Debug)]
struct MainBranch {
    buffer_size: usize,
    inflow: CumulativeIn,
    removed: f64,
    required: f64,
    pending: VecDeque<AccessUnit>,
    peak: f64,
}

impl MainBranch {
    fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            inflow: CumulativeIn::default(),
            removed: 0.0,
            required: 0.0,
            pending: VecDeque::new(),
            peak: 0.0,
        }
    }

    /// Process every pending removal with `decode_time ≤ frontier`.
    fn drain(
        &mut self,
        frontier: f64,
        pid: u16,
        report: &mut TStdReport,
        stats: &mut TStdChainStats,
    ) {
        while let Some(au) = self.pending.front().copied() {
            if au.decode_time > frontier {
                break;
            }
            self.pending.pop_front();
            let arrived = self.inflow.arrived_by(au.decode_time);
            let fullness = arrived - self.removed;
            self.peak = self.peak.max(fullness);
            if fullness > self.buffer_size as f64 + BYTE_EPS {
                report.record(TStdViolation::MainOverflow {
                    pid,
                    peak_bytes: fullness as u64,
                    limit: self.buffer_size,
                });
            }
            self.required += au.bytes;
            if arrived + BYTE_EPS < self.required {
                report.record(TStdViolation::MainUnderflow {
                    pid,
                    decode_time: au.decode_time,
                    missing_bytes: (self.required - arrived) as u64,
                });
            }
            let delay = au.decode_time - au.first_input_time;
            stats.max_delay_seconds = stats.max_delay_seconds.max(delay);
            if delay > MAX_TSTD_DELAY_SECONDS + TIME_EPS {
                report.record(TStdViolation::DelayOverOneSecond {
                    pid,
                    decode_time: au.decode_time,
                    delay_seconds: delay,
                });
            }
            self.removed = self.required.min(arrived);
            stats.access_units += 1;
        }
    }

    /// End-of-stream: run every remaining removal, then check the
    /// final fullness peak.
    fn finish(&mut self, pid: u16, report: &mut TStdReport, stats: &mut TStdChainStats) {
        self.drain(f64::INFINITY, pid, report, stats);
        let fullness = self.inflow.final_total() - self.removed;
        self.peak = self.peak.max(fullness);
        if fullness > self.buffer_size as f64 + BYTE_EPS {
            report.record(TStdViolation::MainOverflow {
                pid,
                peak_bytes: fullness as u64,
                limit: self.buffer_size,
            });
        }
        stats.peak_main_bytes = self.peak as u64;
    }
}

/// Video `MBn → EBn` chain (leak method).
#[derive(Debug)]
struct VideoBranch {
    /// Leak rate `Rbxn` in bytes/second.
    rbx: f64,
    mb_size: usize,
    eb_size: usize,
    /// Runs delivered into `MBn` (TB exit windows), with their class.
    mb_in: CumulativeIn,
    /// Header bytes among the MB inflow, cumulative, keyed by the
    /// same ordering: `(cum_in_threshold, header_bytes)` — when the
    /// transfer clock passes `cum_in_threshold` bytes, `header_bytes`
    /// of them were headers (discarded, not entering `EBn`).
    header_marks: VecDeque<(f64, f64)>,
    /// Cumulative bytes queued into `MBn` so far (arrival order).
    queued: f64,
    /// Cumulative bytes transferred out of `MBn` (headers + payload).
    transferred: f64,
    /// Cumulative payload bytes into `EBn`.
    eb_in: f64,
    /// Cumulative payload bytes removed from `EBn`.
    eb_removed: f64,
    eb_required: f64,
    /// Transfer clock — the leak has caught up with the queue until
    /// this time.
    proc_time: f64,
    pending: VecDeque<AccessUnit>,
    mb_peak: f64,
    eb_peak: f64,
    mb_busy_since: Option<f64>,
    mb_longest_busy: f64,
}

impl VideoBranch {
    fn new(rbx_bps: u64, mb_size: usize, eb_size: usize) -> Self {
        Self {
            rbx: rbx_bps as f64 / 8.0,
            mb_size,
            eb_size,
            mb_in: CumulativeIn::default(),
            header_marks: VecDeque::new(),
            queued: 0.0,
            transferred: 0.0,
            eb_in: 0.0,
            eb_removed: 0.0,
            eb_required: 0.0,
            proc_time: f64::NEG_INFINITY,
            pending: VecDeque::new(),
            mb_peak: 0.0,
            eb_peak: 0.0,
            mb_busy_since: None,
            mb_longest_busy: 0.0,
        }
    }

    /// Queue a run into `MBn`. `header` marks PES header bytes, which
    /// are discarded at transfer time instead of entering `EBn`
    /// (§2.4.2.3: header bytes preceding a transferred payload byte
    /// are removed instantaneously — the fluid model lets them ride
    /// the leak, a sub-millisecond approximation at `Rbx`).
    fn push(&mut self, t0: f64, t1: f64, bytes: f64, header: bool) {
        if bytes <= 0.0 {
            return;
        }
        self.mb_in.push(t0, t1, bytes);
        self.queued += bytes;
        if header {
            self.header_marks.push_back((self.queued, bytes));
        }
    }

    /// Advance the leak up to `frontier`, interleaving EB removals.
    fn advance(
        &mut self,
        frontier: f64,
        pid: u16,
        report: &mut TStdReport,
        stats: &mut TStdChainStats,
    ) {
        loop {
            let next_decode = self.pending.front().map(|au| au.decode_time);
            let step_to = match next_decode {
                Some(td) if td <= frontier => td,
                _ => frontier,
            };
            self.leak_until(step_to, pid, report);
            match next_decode {
                Some(td) if td <= frontier => {
                    let au = self.pending.pop_front().expect("peeked");
                    self.eb_required += au.bytes;
                    if self.eb_in + BYTE_EPS < self.eb_required {
                        report.record(TStdViolation::EbUnderflow {
                            pid,
                            decode_time: td,
                            missing_bytes: (self.eb_required - self.eb_in) as u64,
                        });
                    }
                    self.eb_removed = self.eb_required.min(self.eb_in);
                    let delay = td - au.first_input_time;
                    stats.max_delay_seconds = stats.max_delay_seconds.max(delay);
                    if delay > MAX_TSTD_DELAY_SECONDS + TIME_EPS {
                        report.record(TStdViolation::DelayOverOneSecond {
                            pid,
                            decode_time: td,
                            delay_seconds: delay,
                        });
                    }
                    stats.access_units += 1;
                }
                _ => break,
            }
        }
    }

    /// Run the `MBn → EBn` leak from `proc_time` to `t`, honouring
    /// `EBn`-full back-pressure (§2.4.2.3: "If EBn is full, data are
    /// not removed from MBn").
    fn leak_until(&mut self, t: f64, pid: u16, report: &mut TStdReport) {
        if self.proc_time == f64::NEG_INFINITY {
            self.proc_time = t;
            return;
        }
        while self.proc_time < t - TIME_EPS {
            let now = self.proc_time;
            let available = self.mb_in.arrived_by(now) - self.transferred;
            let eb_fullness = self.eb_in - self.eb_removed;
            let eb_room = self.eb_size as f64 - eb_fullness;
            // MB fullness peaks whenever the leak stalls or lags.
            let mb_fullness = self.mb_in.arrived_by(now) - self.transferred;
            self.mb_peak = self.mb_peak.max(mb_fullness);
            // Busy-stretch bookkeeping.
            if mb_fullness > BYTE_EPS {
                if self.mb_busy_since.is_none() {
                    self.mb_busy_since = Some(now);
                }
            } else if let Some(since) = self.mb_busy_since.take() {
                self.mb_longest_busy = self.mb_longest_busy.max(now - since);
            }
            if eb_room <= BYTE_EPS {
                // Stalled until the next removal (handled by the
                // caller); everything arriving meanwhile queues in MB.
                let end_fullness = self.mb_in.arrived_by(t) - self.transferred;
                self.mb_peak = self.mb_peak.max(end_fullness);
                if self.mb_busy_since.is_none() && end_fullness > BYTE_EPS {
                    self.mb_busy_since = Some(now);
                }
                self.proc_time = t;
                break;
            }
            if available <= BYTE_EPS {
                // Leak is keeping pace with arrivals: it transfers
                // whatever arrives until `t` (arrival rate ≤ Rbx), or
                // as much as fits in EB.
                let arriving = self.mb_in.arrived_by(t) - self.transferred - available;
                let take = arriving.min(eb_room.max(0.0));
                self.transfer(take.max(0.0));
                if take + BYTE_EPS < arriving {
                    // EB filled mid-stretch; find the fill time and
                    // continue stalled from there.
                    let target = self.transferred; // after transfer()
                    if let Some(tt) = self.mb_in.time_of_cumulative(target) {
                        self.proc_time = tt.max(now);
                        continue;
                    }
                }
                self.proc_time = t;
                break;
            }
            // Backlogged: transfer at Rbx until t, backlog exhausted,
            // or EB full.
            let span = t - now;
            let by_rate = self.rbx * span;
            let take = by_rate.min(available).min(eb_room);
            self.transfer(take);
            let dt = take / self.rbx;
            self.proc_time = now + dt.max(TIME_EPS);
        }
        let mb_fullness = self.mb_in.arrived_by(t) - self.transferred;
        self.mb_peak = self.mb_peak.max(mb_fullness);
        if mb_fullness > self.mb_size as f64 + BYTE_EPS {
            report.record(TStdViolation::MbOverflow {
                pid,
                peak_bytes: mb_fullness as u64,
                limit: self.mb_size,
            });
        }
        if let Some(since) = self.mb_busy_since {
            self.mb_longest_busy = self.mb_longest_busy.max(t - since);
        }
        self.proc_time = self.proc_time.max(t);
    }

    /// Move `bytes` out of `MBn`, splitting them into discarded
    /// header bytes and `EBn` payload per the queued marks.
    fn transfer(&mut self, bytes: f64) {
        if bytes <= 0.0 {
            return;
        }
        let start = self.transferred;
        let end = start + bytes;
        let mut header_bytes = 0.0;
        while let Some(&(threshold, hbytes)) = self.header_marks.front() {
            if threshold - hbytes >= end {
                break;
            }
            // Portion of this header run inside [start, end].
            let run_start = threshold - hbytes;
            let overlap = (end.min(threshold) - start.max(run_start)).max(0.0);
            header_bytes += overlap;
            if threshold <= end {
                self.header_marks.pop_front();
            } else {
                break;
            }
        }
        self.transferred = end;
        self.eb_in += bytes - header_bytes;
        let eb_fullness = self.eb_in - self.eb_removed;
        self.eb_peak = self.eb_peak.max(eb_fullness);
    }

    fn finish(&mut self, pid: u16, report: &mut TStdReport, stats: &mut TStdChainStats) {
        // Let the leak run long enough to move everything queued.
        let drain_time = self.proc_time.max(0.0) + self.queued / self.rbx + 2.0;
        self.advance(drain_time, pid, report, stats);
        if self.mb_longest_busy > MAX_TSTD_DELAY_SECONDS + TIME_EPS {
            report.record(TStdViolation::MbBusyOverOneSecond {
                pid,
                seconds: self.mb_longest_busy,
            });
        }
        stats.peak_main_bytes = self.mb_peak as u64;
        stats.peak_eb_bytes = self.eb_peak as u64;
    }
}

/// System-data branch: `TBsys → Bsys`, continuous `Rsys` drain
/// (equation 2-7), overflow check only (§2.4.2.6).
#[derive(Debug)]
struct SysBranch {
    fullness: f64,
    last_time: f64,
    peak: f64,
}

impl SysBranch {
    fn new() -> Self {
        Self {
            fullness: 0.0,
            last_time: f64::NEG_INFINITY,
            peak: 0.0,
        }
    }

    /// Feed a run into `Bsys`; `rsys` is the drain rate (bytes/s)
    /// applicable around this run's time.
    fn push(&mut self, t0: f64, t1: f64, bytes: f64, rsys: f64, report: &mut TStdReport) {
        if self.last_time == f64::NEG_INFINITY {
            self.last_time = t0;
        }
        // Drain the idle gap.
        let gap = (t0 - self.last_time).max(0.0);
        self.fullness = (self.fullness - rsys * gap).max(0.0);
        // Net fill over the run window; the fluid net-fill may
        // under-account a mid-run peak by at most `rsys × span`,
        // which is a handful of bytes at `Rsys`.
        let span = (t1 - t0).max(0.0);
        self.fullness = (self.fullness + bytes - rsys * span).max(0.0);
        self.peak = self.peak.max(self.fullness);
        if self.fullness > BSYS_SIZE as f64 + BYTE_EPS {
            report.record(TStdViolation::BsysOverflow {
                peak_bytes: self.fullness as u64,
            });
        }
        self.last_time = t1;
    }
}

// ---------------------------------------------------------------------------
// PES byte classification.
// ---------------------------------------------------------------------------

/// Byte class within a TS payload on an elementary PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteClass {
    /// PES packet header bytes.
    Header,
    /// PES payload (elementary-stream) bytes.
    Payload,
}

/// Incremental PES scanner: classifies payload bytes into header /
/// payload runs and reports access-unit starts.
#[derive(Debug, Default)]
struct PesScanner {
    /// Bytes of PES header still expected (may span TS packets).
    header_pending: usize,
    /// Collected header bytes while the fixed/optional header length
    /// is still unknown.
    header_buf: Vec<u8>,
    /// `true` between a PUSI and the resolution of the full header
    /// length.
    sizing: bool,
    started: bool,
}

/// One classified run within a TS payload.
#[derive(Debug, Clone, Copy)]
struct ClassifiedRun {
    /// Offset within the fed payload slice.
    offset: usize,
    len: usize,
    class: ByteClass,
    /// A decode timestamp announced by the header this run completes
    /// (raw 33-bit 90 kHz; DTS when coded, else PTS).
    decode_ts: Option<u64>,
}

impl PesScanner {
    /// Classify one TS payload. `pusi` marks a PES start. Header
    /// bytes consumed while the header length is still being resolved
    /// are emitted as `Header` runs in *every* payload they appear in
    /// (a PES header may span TS packets); the run that resolves the
    /// timestamp area carries `decode_ts`.
    fn feed(&mut self, payload: &[u8], pusi: bool, out: &mut Vec<ClassifiedRun>) {
        out.clear();
        if pusi {
            self.header_pending = 0;
            self.header_buf.clear();
            self.sizing = true;
            self.started = true;
        }
        if !self.started {
            return;
        }
        let mut pos = 0usize;
        while pos < payload.len() {
            if self.sizing {
                let run_start = pos;
                let mut decode_ts = None;
                while pos < payload.len() && self.sizing {
                    self.header_buf.push(payload[pos]);
                    pos += 1;
                    let n = self.header_buf.len();
                    if n < 6 {
                        continue;
                    }
                    let stream_id = self.header_buf[3];
                    if !crate::pes::has_optional_pes_header(stream_id) {
                        // Exactly the 6 fixed bytes, no timestamps.
                        self.sizing = false;
                        self.header_pending = 0;
                        break;
                    }
                    if n < 9 {
                        continue;
                    }
                    let hdr_len = self.header_buf[8] as usize;
                    let flags2 = self.header_buf[7];
                    let ts_want: usize = match flags2 >> 6 {
                        0b10 => 5,
                        0b11 => 10,
                        _ => 0,
                    };
                    if n < 9 + hdr_len.min(ts_want) {
                        continue;
                    }
                    decode_ts = match flags2 >> 6 {
                        // §2.4.3.7: the DTS (when coded) is the decode
                        // time; it follows the 5 PTS bytes.
                        0b10 if hdr_len >= 5 => Some(read_ts33(&self.header_buf[9..14])),
                        0b11 if hdr_len >= 10 => Some(read_ts33(&self.header_buf[14..19])),
                        _ => None,
                    };
                    self.header_pending = (9 + hdr_len).saturating_sub(n);
                    self.sizing = false;
                }
                if pos > run_start {
                    out.push(ClassifiedRun {
                        offset: run_start,
                        len: pos - run_start,
                        class: ByteClass::Header,
                        decode_ts,
                    });
                }
            } else if self.header_pending > 0 {
                let take = self.header_pending.min(payload.len() - pos);
                out.push(ClassifiedRun {
                    offset: pos,
                    len: take,
                    class: ByteClass::Header,
                    decode_ts: None,
                });
                self.header_pending -= take;
                pos += take;
            } else {
                out.push(ClassifiedRun {
                    offset: pos,
                    len: payload.len() - pos,
                    class: ByteClass::Payload,
                    decode_ts: None,
                });
                pos = payload.len();
            }
        }
    }
}

/// Read a 33-bit timestamp from the 5-byte `'xxxx'` marker form
/// (§2.4.3.7).
fn read_ts33(b: &[u8]) -> u64 {
    (((b[0] >> 1) as u64 & 0x7) << 30)
        | ((b[1] as u64) << 22)
        | (((b[2] >> 1) as u64) << 15)
        | ((b[3] as u64) << 7)
        | ((b[4] >> 1) as u64)
}

// ---------------------------------------------------------------------------
// The analyzer.
// ---------------------------------------------------------------------------

/// One modelled elementary chain.
struct Chain {
    pid: u16,
    tb: FluidFifo,
    branch: ChainBranch,
    scanner: PesScanner,
    /// The open (still-arriving) access unit.
    open_au: Option<OpenAu>,
    stats: TStdChainStats,
}

enum ChainBranch {
    Main(MainBranch),
    Video(VideoBranch),
}

#[derive(Debug, Clone, Copy)]
struct OpenAu {
    decode_time: f64,
    first_input_time: f64,
    /// Accumulated bytes in the branch's removal metric.
    bytes: f64,
}

impl Chain {
    /// Close the open AU and queue its removal.
    fn close_au(&mut self) {
        if let Some(au) = self.open_au.take() {
            let unit = AccessUnit {
                decode_time: au.decode_time,
                bytes: au.bytes,
                first_input_time: au.first_input_time,
            };
            match &mut self.branch {
                ChainBranch::Main(b) => b.pending.push_back(unit),
                ChainBranch::Video(b) => b.pending.push_back(unit),
            }
        }
    }
}

/// Replay `bytes` (a whole transport stream in any physical framing)
/// through the §2.4.2 T-STD model for one program.
///
/// The arrival clock is reconstructed from the PCRs on
/// `config.pcr_pid` (§2.4.2.2); each configured elementary PID runs
/// the `TBn → Bn` or `TBn → MBn → EBn` chain with the §2.4.2.6
/// checks; `config.system_pids` share the `TBsys → Bsys` chain.
/// Errors with [`TsError::Unsupported`] when no packet layout or too
/// few PCRs are found.
pub fn analyze_tstd(bytes: &[u8], config: &TStdConfig) -> Result<TStdReport, TsError> {
    let layout = detect_packet_layout(bytes)
        .ok_or(TsError::Unsupported("T-STD model: no TS packet layout"))?;
    let psize = layout.packet_size;

    // ---- Pass 1: PCR samples on the PCR_PID (§2.4.2.2). ----
    let mut samples: Vec<(u64, u64, bool)> = Vec::new();
    let mut logical_pos = 0u64;
    let mut pending_discontinuity = false;
    for chunk in bytes.chunks_exact(psize) {
        let window = layout.window(chunk);
        if let Ok(pkt) = TsPacket::parse(window) {
            if pkt.pid == config.pcr_pid {
                if let Some(af) = &pkt.adaptation_field {
                    if af.discontinuity_indicator {
                        pending_discontinuity = true;
                    }
                    if let (Some(base), ext) = (af.pcr_base, af.pcr_extension.unwrap_or(0)) {
                        // Byte index of the last bit of PCR_base:
                        // 4-byte TS header + AF length/flags bytes +
                        // the fifth PCR byte.
                        let pos = logical_pos + 4 + 2 + 4;
                        samples.push((pos, base * 300 + ext as u64, pending_discontinuity));
                        pending_discontinuity = false;
                    }
                }
            }
        }
        logical_pos += crate::TS_PACKET_LEN as u64;
    }
    let mut clock = ArrivalClock::build(&samples)?;

    let mut report = TStdReport {
        pcr_samples: samples.len(),
        ..Default::default()
    };

    // ---- Pass 2: replay every packet through its chain. ----
    let mut chains: Vec<Chain> = config
        .streams
        .iter()
        .map(|(pid, model)| Chain {
            pid: *pid,
            tb: FluidFifo::new(model.rx_bps),
            branch: match &model.branch {
                TStdBranch::Main { buffer_size } => {
                    ChainBranch::Main(MainBranch::new(*buffer_size))
                }
                TStdBranch::Video {
                    rbx_bps,
                    mb_size,
                    eb_size,
                } => ChainBranch::Video(VideoBranch::new(*rbx_bps, *mb_size, *eb_size)),
            },
            scanner: PesScanner::default(),
            open_au: None,
            stats: TStdChainStats {
                pid: *pid,
                ..Default::default()
            },
        })
        .collect();
    let mut tbsys = if config.system_pids.is_empty() {
        None
    } else {
        Some((FluidFifo::new(RXSYS_BPS), SysBranch::new()))
    };

    let mut logical_pos = 0u64;
    let mut runs: Vec<ClassifiedRun> = Vec::new();
    let mut first_time = f64::INFINITY;
    let mut last_time = f64::NEG_INFINITY;
    for chunk in bytes.chunks_exact(psize) {
        let window = layout.window(chunk);
        let pkt = match TsPacket::parse(window) {
            Ok(p) => p,
            Err(_) => {
                logical_pos += crate::TS_PACKET_LEN as u64;
                continue;
            }
        };
        let t0 = clock.time_of(logical_pos);
        let t1 = clock.time_of(logical_pos + crate::TS_PACKET_LEN as u64);
        first_time = first_time.min(t0);
        last_time = last_time.max(t1);

        if let Some(chain) = chains.iter_mut().find(|c| c.pid == pkt.pid) {
            // Process removals up to this arrival before feeding more.
            match &mut chain.branch {
                ChainBranch::Main(b) => b.drain(t0, chain.pid, &mut report, &mut chain.stats),
                ChainBranch::Video(b) => b.advance(t0, chain.pid, &mut report, &mut chain.stats),
            }
            // Whole packets enter TBn (§2.4.2.3), including the TS
            // header and adaptation field; only PES bytes leave
            // toward the main / multiplexing buffer, in FIFO order.
            let span = t1 - t0;
            let frac = |byte: usize| t0 + span * byte as f64 / crate::TS_PACKET_LEN as f64;
            if pkt.payload.is_empty() {
                chain.tb.push(t0, t1, crate::TS_PACKET_LEN as f64);
            } else {
                let payload_offset = crate::TS_PACKET_LEN - pkt.payload.len();
                // TS header + adaptation field: drained, then
                // discarded ("other bytes are not [delivered]").
                chain
                    .tb
                    .push(t0, frac(payload_offset), payload_offset as f64);
                chain
                    .scanner
                    .feed(pkt.payload, pkt.payload_unit_start, &mut runs);
                for run in &runs {
                    let abs0 = payload_offset + run.offset;
                    let abs1 = abs0 + run.len;
                    let (rt0, rt1) = (frac(abs0), frac(abs1));
                    let (es, ee) = chain.tb.push(rt0, rt1, run.len as f64);
                    // Access-unit bookkeeping: a header announcing a
                    // decode timestamp starts a new unit.
                    if let Some(ts) = run.decode_ts {
                        chain.close_au();
                        let td = clock.decode_time_at(logical_pos, ts);
                        chain.open_au = Some(OpenAu {
                            decode_time: td,
                            first_input_time: rt0,
                            bytes: 0.0,
                        });
                    }
                    let metric_bytes = match (&chain.branch, run.class) {
                        // Bn holds PES headers until the AU removal
                        // (§2.4.2.3 audio rule).
                        (ChainBranch::Main(_), _) => run.len as f64,
                        // EBn receives payload only.
                        (ChainBranch::Video(_), ByteClass::Payload) => run.len as f64,
                        (ChainBranch::Video(_), ByteClass::Header) => 0.0,
                    };
                    if let Some(au) = &mut chain.open_au {
                        au.bytes += metric_bytes;
                    }
                    match &mut chain.branch {
                        ChainBranch::Main(b) => b.inflow.push(es, ee, run.len as f64),
                        ChainBranch::Video(b) => {
                            b.push(es, ee, run.len as f64, run.class == ByteClass::Header)
                        }
                    }
                }
            }
        } else if config.system_pids.contains(&pkt.pid) {
            if let Some((tb, bsys)) = &mut tbsys {
                let (es, ee) = tb.push(t0, t1, crate::TS_PACKET_LEN as f64);
                let rate = clock.rate_at(logical_pos);
                let rsys = ((rate * 8.0) / 500.0).max(RSYS_MIN_BPS as f64) / 8.0;
                bsys.push(es, ee, crate::TS_PACKET_LEN as f64, rsys, &mut report);
            }
        }
        logical_pos += crate::TS_PACKET_LEN as u64;
    }

    // ---- Wrap up: close AUs, run tail removals, collect checks. ----
    for chain in &mut chains {
        chain.close_au();
        let pid = chain.pid;
        if chain.tb.peak > TB_SIZE as f64 + BYTE_EPS {
            report.record(TStdViolation::TbOverflow {
                pid,
                peak_bytes: chain.tb.peak as u64,
            });
        }
        if chain.tb.longest_busy > MAX_TSTD_DELAY_SECONDS + TIME_EPS {
            report.record(TStdViolation::TbBusyOverOneSecond {
                pid,
                seconds: chain.tb.longest_busy,
            });
        }
        chain.stats.peak_tb_bytes = chain.tb.peak as u64;
        match &mut chain.branch {
            ChainBranch::Main(b) => b.finish(pid, &mut report, &mut chain.stats),
            ChainBranch::Video(b) => b.finish(pid, &mut report, &mut chain.stats),
        }
        report.chains.push(chain.stats.clone());
    }
    if let Some((tb, bsys)) = &tbsys {
        let pid = *config.system_pids.first().unwrap_or(&0);
        if tb.peak > TB_SIZE as f64 + BYTE_EPS {
            report.record(TStdViolation::TbOverflow {
                pid,
                peak_bytes: tb.peak as u64,
            });
        }
        if tb.longest_busy > MAX_TSTD_DELAY_SECONDS + TIME_EPS {
            report.record(TStdViolation::TbBusyOverOneSecond {
                pid,
                seconds: tb.longest_busy,
            });
        }
        report.chains.push(TStdChainStats {
            pid,
            peak_tb_bytes: tb.peak as u64,
            peak_main_bytes: bsys.peak as u64,
            ..Default::default()
        });
    }
    if last_time > first_time {
        report.modelled_seconds = last_time - first_time;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdaptationFieldSpec, TS_PACKET_LEN, TS_SYNC_BYTE};

    const PCR_PID: u16 = 0x0100;
    const AUDIO_PID: u16 = 0x0101;
    const VIDEO_PID: u16 = 0x0102;

    /// 27 MHz ticks per 188-byte packet at exactly 1 Mbit/s.
    const TICKS_1MBIT: u64 = 188 * 8 * 27; // 40608

    /// Assemble one 188-byte TS packet.
    fn ts_pkt(
        pid: u16,
        cc: u8,
        pusi: bool,
        af: Option<AdaptationFieldSpec>,
        payload: &[u8],
    ) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = (if pusi { 0x40 } else { 0 }) | ((pid >> 8) as u8 & 0x1F);
        pkt[2] = pid as u8;
        let body = TS_PACKET_LEN - 4;
        match af {
            None if payload.len() == body => {
                pkt[3] = 0b0001_0000 | (cc & 0x0F);
                pkt[4..].copy_from_slice(payload);
            }
            None if payload.is_empty() => {
                // AF-only stuffing packet.
                pkt[3] = 0b0010_0000 | (cc & 0x0F);
                let af = AdaptationFieldSpec::default().encode(Some(body)).unwrap();
                pkt[4..4 + af.len()].copy_from_slice(&af);
            }
            None => {
                // Stuff via an empty AF so the payload lands at the tail.
                pkt[3] = 0b0011_0000 | (cc & 0x0F);
                let af = AdaptationFieldSpec::default()
                    .encode(Some(body - payload.len()))
                    .unwrap();
                pkt[4..4 + af.len()].copy_from_slice(&af);
                pkt[4 + af.len()..].copy_from_slice(payload);
            }
            Some(spec) if payload.is_empty() => {
                pkt[3] = 0b0010_0000 | (cc & 0x0F);
                let af = spec.encode(Some(body)).unwrap();
                pkt[4..4 + af.len()].copy_from_slice(&af);
            }
            Some(spec) => {
                pkt[3] = 0b0011_0000 | (cc & 0x0F);
                let af = spec.encode(Some(body - payload.len())).unwrap();
                pkt[4..4 + af.len()].copy_from_slice(&af);
                pkt[4 + af.len()..].copy_from_slice(payload);
            }
        }
        pkt
    }

    /// AF-only PCR carrier packet.
    fn pcr_pkt(cc: u8, pcr_27mhz: u64) -> [u8; TS_PACKET_LEN] {
        let wrapped = pcr_27mhz % ((1u64 << 33) * 300);
        let base = wrapped / 300;
        let ext = (wrapped % 300) as u16;
        ts_pkt(
            PCR_PID,
            cc,
            false,
            Some(AdaptationFieldSpec::with_pcr(base, ext)),
            &[],
        )
    }

    /// Null (stuffing) packet on PID 0x1FFF.
    fn null_pkt() -> [u8; TS_PACKET_LEN] {
        ts_pkt(0x1FFF, 0, false, None, &[0xFFu8; 184])
    }

    /// A bounded audio PES (stream_id 0xC0) with a PTS.
    fn audio_pes(pts_90k: u64, payload_len: usize) -> Vec<u8> {
        crate::pes::PesHeaderSpec {
            stream_id: 0xC0,
            pts_90k: Some(pts_90k & 0x1_FFFF_FFFF),
            ..Default::default()
        }
        .encode(&vec![0xA5u8; payload_len])
        .unwrap()
    }

    /// An unbounded video PES (stream_id 0xE0) with PTS (+ optional DTS).
    fn video_pes(pts_90k: u64, dts_90k: Option<u64>, payload_len: usize) -> Vec<u8> {
        crate::pes::PesHeaderSpec {
            stream_id: 0xE0,
            pts_90k: Some(pts_90k & 0x1_FFFF_FFFF),
            dts_90k: dts_90k.map(|d| d & 0x1_FFFF_FFFF),
            unbounded_length: true,
            ..Default::default()
        }
        .encode(&vec![0x3Cu8; payload_len])
        .unwrap()
    }

    /// Fragment PES bytes into TS packets on `pid` (PUSI on first).
    fn pes_to_ts(pid: u16, cc: &mut u8, pes: &[u8]) -> Vec<[u8; TS_PACKET_LEN]> {
        let mut out = Vec::new();
        let mut first = true;
        for chunk in pes.chunks(TS_PACKET_LEN - 4) {
            out.push(ts_pkt(pid, *cc, first, None, chunk));
            *cc = (*cc + 1) & 0x0F;
            first = false;
        }
        out
    }

    fn audio_config() -> TStdConfig {
        TStdConfig {
            pcr_pid: PCR_PID,
            streams: vec![(AUDIO_PID, TStdStreamModel::audio())],
            system_pids: Vec::new(),
        }
    }

    /// Concatenate packets and bracket them between two PCRs so the
    /// §2.4.2.2 clock sees `ticks_per_packet` per 188 bytes.
    fn assemble(middle: &[[u8; TS_PACKET_LEN]], pcr0: u64, ticks_per_packet: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&pcr_pkt(0, pcr0));
        for p in middle {
            out.extend_from_slice(p);
        }
        let total_packets = (middle.len() + 1) as u64;
        out.extend_from_slice(&pcr_pkt(1, pcr0 + total_packets * ticks_per_packet));
        out
    }

    /// A comfortably-paced audio stream at 1 Mbit/s is conformant.
    #[test]
    fn conformant_audio_stream_passes() {
        let pcr0 = 27_000_000; // t = 1 s on the PCR time base
                               // PTS ≈ 0.2 s after the head of the stream.
        let pts = pcr0 / 300 + 18_000;
        let mut cc = 0;
        let mut middle = pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 350));
        for _ in 0..10 {
            middle.push(null_pkt());
        }
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report.is_conformant(), "{:?}", report.violations);
        assert_eq!(report.pcr_samples, 2);
        let stats = &report.chains[0];
        assert_eq!(stats.pid, AUDIO_PID);
        assert_eq!(stats.access_units, 1);
        assert!(stats.peak_tb_bytes <= TB_SIZE as u64);
        assert!(stats.peak_main_bytes > 0);
        assert!((stats.max_delay_seconds - 0.2).abs() < 0.01);
    }

    /// Back-to-back audio packets at ~40 Mbit/s exceed the 512-byte
    /// transport buffer (Rx = 2 Mbit/s cannot keep up).
    #[test]
    fn tb_overflow_flagged_at_high_transport_rate() {
        let pcr0 = 27_000_000;
        let pts = pcr0 / 300 + 9_000;
        let mut cc = 0;
        // 4 full TS packets of one PES → 752 back-to-back bytes.
        let middle = pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 700));
        assert_eq!(middle.len(), 4);
        let ts = assemble(&middle, pcr0, TICKS_1MBIT / 40);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, TStdViolation::TbOverflow { pid, .. } if *pid == AUDIO_PID)));
    }

    /// A PTS earlier than the data's arrival is a Bn underflow.
    #[test]
    fn main_underflow_flagged_for_late_data() {
        let pcr0 = 27_000_000;
        // Decode time 0.5 s BEFORE the PCR head.
        let pts = pcr0 / 300 - 45_000;
        let mut cc = 0;
        let middle = pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 350));
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, TStdViolation::MainUnderflow { pid, .. } if *pid == AUDIO_PID)));
    }

    /// More buffered audio than BSn = 3584 bytes is a Bn overflow.
    #[test]
    fn main_overflow_flagged_for_hoarded_audio() {
        let pcr0 = 27_000_000;
        let mut cc = 0;
        let mut middle = Vec::new();
        // 8 PES × 700 bytes, all decoding 0.9 s after the head: the
        // 5.7 KB pile-up exceeds the 3584-byte main buffer.
        for _ in 0..8 {
            middle.extend(pes_to_ts(
                AUDIO_PID,
                &mut cc,
                &audio_pes(pcr0 / 300 + 81_000, 700),
            ));
        }
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, TStdViolation::MainOverflow { pid, .. } if *pid == AUDIO_PID)));
    }

    /// A decode time more than one second after arrival breaks the
    /// §2.4.2.6 delay bound.
    #[test]
    fn delay_over_one_second_flagged() {
        let pcr0 = 27_000_000;
        let pts = pcr0 / 300 + 2 * 90_000; // 2 s after the head
        let mut cc = 0;
        let middle = pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 350));
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report.violations.iter().any(
            |v| matches!(v, TStdViolation::DelayOverOneSecond { pid, .. } if *pid == AUDIO_PID)
        ));
    }

    /// Video: a 50 KB access unit cannot leak into EBn at
    /// Rbx = 1 Mbit/s within 0.1 s — EBn underflows at the decode
    /// time.
    #[test]
    fn eb_underflow_flagged_for_slow_leak() {
        let pcr0 = 27_000_000;
        let pts = pcr0 / 300 + 9_000; // 0.1 s after the head
        let mut cc = 0;
        let middle = pes_to_ts(VIDEO_PID, &mut cc, &video_pes(pts, None, 50_000));
        // Deliver fast (10 Mbit/s) so arrival is not the bottleneck.
        let ts = assemble(&middle, pcr0, TICKS_1MBIT / 10);
        let config = TStdConfig {
            pcr_pid: PCR_PID,
            streams: vec![(
                VIDEO_PID,
                TStdStreamModel::video_low_main_level(1_000_000, 65_536, 131_072),
            )],
            system_pids: Vec::new(),
        };
        let report = analyze_tstd(&ts, &config).expect("analyze");
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, TStdViolation::EbUnderflow { pid, .. } if *pid == VIDEO_PID)));
    }

    /// A modestly-paced video stream with per-frame PES passes the
    /// full video chain.
    #[test]
    fn conformant_video_stream_passes() {
        let pcr0 = 27_000_000;
        let mut cc = 0;
        let mut middle = Vec::new();
        // 5 frames of 2 KB at 25 fps, each decoding 0.3 s after the
        // stream head + its frame slot.
        for k in 0..5u64 {
            let pts = pcr0 / 300 + 27_000 + k * 3_600;
            middle.extend(pes_to_ts(VIDEO_PID, &mut cc, &video_pes(pts, None, 2_048)));
            // Space frames out with nulls (~0.04 s each at 4 Mbit/s).
            for _ in 0..8 {
                middle.push(null_pkt());
            }
        }
        let ts = assemble(&middle, pcr0, TICKS_1MBIT / 4);
        let config = TStdConfig {
            pcr_pid: PCR_PID,
            streams: vec![(
                VIDEO_PID,
                TStdStreamModel::video_low_main_level(4_000_000, 131_072, 262_144),
            )],
            system_pids: Vec::new(),
        };
        let report = analyze_tstd(&ts, &config).expect("analyze");
        assert!(report.is_conformant(), "{:?}", report.violations);
        let stats = &report.chains[0];
        assert_eq!(stats.access_units, 5);
        assert!(stats.peak_eb_bytes > 0);
    }

    /// The arrival clock survives a PCR wrap (the 33+9-bit field wraps
    /// every ~26.5 h) without inventing a rate spike.
    #[test]
    fn arrival_clock_survives_pcr_wrap() {
        let modulus: u64 = (1 << 33) * 300;
        let pcr0 = modulus - TICKS_1MBIT * 5; // wraps mid-stream
        let pts = ((pcr0 / 300) + 18_000) & 0x1_FFFF_FFFF;
        let mut cc = 0;
        let mut middle = pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 350));
        for _ in 0..10 {
            middle.push(null_pkt());
        }
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report.is_conformant(), "{:?}", report.violations);
        // 13 packets at 1 Mbit/s ≈ 19.6 ms.
        assert!((report.modelled_seconds - 0.0196).abs() < 0.002);
    }

    /// A signalled time-base discontinuity re-anchors decode times on
    /// the new base and carries the old transport rate across the gap
    /// (§2.4.2.2).
    #[test]
    fn discontinuity_reanchors_time_base() {
        let pcr0 = 27_000_000;
        let mut out = Vec::new();
        out.extend_from_slice(&pcr_pkt(0, pcr0));
        out.extend_from_slice(&pcr_pkt(1, pcr0 + 2 * TICKS_1MBIT));
        // New time base: 1000 s, signalled.
        let new_base = 27_000_000_000;
        let disc = AdaptationFieldSpec {
            discontinuity_indicator: true,
            pcr: Some((new_base / 300, (new_base % 300) as u16)),
            ..Default::default()
        };
        out.extend_from_slice(&ts_pkt(PCR_PID, 2, false, Some(disc), &[]));
        // Audio decoding 0.2 s into the new base.
        let pts = new_base / 300 + 18_000;
        let mut cc = 0;
        for p in pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 350)) {
            out.extend_from_slice(&p);
        }
        out.extend_from_slice(&pcr_pkt(3, new_base + 4 * TICKS_1MBIT));
        let report = analyze_tstd(&out, &audio_config()).expect("analyze");
        assert!(report.is_conformant(), "{:?}", report.violations);
        assert_eq!(report.chains[0].access_units, 1);
        assert!((report.chains[0].max_delay_seconds - 0.2).abs() < 0.01);
    }

    /// PSI packets route through TBsys → Bsys; a plausible PSI load
    /// stays inside the 1536-byte Bsys.
    #[test]
    fn system_branch_models_psi_load() {
        let pcr0 = 27_000_000;
        let mut middle = Vec::new();
        // A PAT-ish payload burst on PID 0.
        for _ in 0..3 {
            middle.push(ts_pkt(0x0000, 0, false, None, &[0x00u8; 184]));
        }
        for _ in 0..10 {
            middle.push(null_pkt());
        }
        let mut config = audio_config();
        config.system_pids = vec![0x0000, 0x0001, 0x0100];
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &config).expect("analyze");
        assert!(report.is_conformant(), "{:?}", report.violations);
        // The system chain reports its stats last.
        let sys = report.chains.last().unwrap();
        // At a transport rate equal to Rxsys the TBsys backlog stays
        // ~zero; Bsys accumulates against the slower Rsys drain.
        assert!(sys.peak_tb_bytes <= TB_SIZE as u64);
        assert!(sys.peak_main_bytes > 0);
        assert!(sys.peak_main_bytes <= BSYS_SIZE as u64);
    }

    /// Fewer than two PCRs on the PCR_PID is unsupported.
    #[test]
    fn too_few_pcrs_is_unsupported() {
        let mut out = Vec::new();
        out.extend_from_slice(&pcr_pkt(0, 27_000_000));
        out.extend_from_slice(&null_pkt());
        assert!(analyze_tstd(&out, &audio_config()).is_err());
    }

    /// Split PES envelopes (timestamp-less continuations) extend the
    /// open access unit instead of starting a new one.
    #[test]
    fn continuation_pes_extends_access_unit() {
        let pcr0 = 27_000_000;
        let pts = pcr0 / 300 + 27_000;
        let mut cc = 0;
        let mut middle = pes_to_ts(AUDIO_PID, &mut cc, &audio_pes(pts, 350));
        // A continuation PES with no timestamp on the same PID.
        let cont = crate::pes::PesHeaderSpec {
            stream_id: 0xC0,
            ..Default::default()
        }
        .encode(&[0x5Au8; 300])
        .unwrap();
        middle.extend(pes_to_ts(AUDIO_PID, &mut cc, &cont));
        for _ in 0..10 {
            middle.push(null_pkt());
        }
        let ts = assemble(&middle, pcr0, TICKS_1MBIT);
        let report = analyze_tstd(&ts, &audio_config()).expect("analyze");
        assert!(report.is_conformant(), "{:?}", report.violations);
        assert_eq!(report.chains[0].access_units, 1);
    }
}
