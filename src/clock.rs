//! Program Clock Reference (PCR) recovery and continuity tracking per
//! ISO/IEC 13818-1.
//!
//! Two parallel-but-related concerns live here:
//!
//! 1. **PCR recovery** ([`Pcr`], [`PcrTracker`]). §2.4.2.2 carries one
//!    27 MHz system clock sample per program inside the adaptation
//!    field of TS packets whose PID matches a PMT's `PCR_PID`. A
//!    callable tracker watches each PCR sample on a given PID, detects
//!    **time-base discontinuities** (signalled by the
//!    `discontinuity_indicator` per §2.4.3.4 / §2.4.3.5 *or* by a PCR
//!    jump that exceeds a tolerance window), and surfaces per-sample
//!    **jitter** + an **instantaneous bitrate** estimate.
//!
//! 2. **Continuity counter** ([`ContinuityTracker`]). §2.4.3.2 carries
//!    a 4-bit per-PID counter that increments on every packet
//!    contributing a payload. Real-world streams drop packets, send
//!    spec-permitted duplicates, and (rarely) re-order packets — this
//!    tracker classifies every observed packet against the previous
//!    one on the same PID so a demuxer can react (zero a reassembler
//!    on a drop, skip a duplicate without emitting it twice).
//!
//! Neither tracker mutates input bytes; both are pure observers over
//! the [`crate::TsPacket`] field set. The demuxer wires them in as the
//! per-stream front door — the trackers themselves stay testable in
//! isolation.
//!
//! ## PCR encoding (§2.4.2.2, equations 2-1/2-2/2-3)
//!
//! A PCR field is 48 bits in the adaptation field, split into:
//!
//! ```text
//! program_clock_reference_base       33 bits  (1/300 of 27 MHz = 90 kHz)
//! reserved                            6 bits  (all 1s)
//! program_clock_reference_extension   9 bits  (1/27 MHz, range 0..299)
//! ```
//!
//! The full 27 MHz sample value is
//! `PCR = PCR_base × 300 + PCR_extension`. The base wraps every
//! 2^33 / 90 000 ≈ 95443.72 s (~ 26.5 hours) and the full
//! 27 MHz value wraps every (2^33 × 300) / 27_000_000 = same window.
//!
//! ## Jitter (§2.4.2.2 + §2.4.2.3 tolerance)
//!
//! Real-world re-multiplexers preserve PCR samples but disturb their
//! arrival schedule; the spec states a ±500 ns tolerance on PCR values
//! themselves, but PES + buffer scheduling tolerates much more on a
//! per-sample arrival basis. We model **PCR jitter** as the signed
//! difference, in 27 MHz ticks, between the observed PCR delta and the
//! delta predicted by the instantaneous bitrate `R` computed from the
//! previous pair of PCRs:
//!
//! ```text
//! R     = (PCR_{i-1} - PCR_{i-2}) / (byte_offset_{i-1} - byte_offset_{i-2})
//! ΔPCR* = R × (byte_offset_i - byte_offset_{i-1})
//! jitter_i = (PCR_i - PCR_{i-1}) - ΔPCR*       [27 MHz ticks]
//! ```
//!
//! The tracker keeps a small ring of recent jitter samples so callers
//! can ask for peak / running-average / current values without
//! reading the running state directly.
//!
//! ## Discontinuity surface
//!
//! Both trackers classify their observations into the same shape:
//!
//! * **`None` returned from `observe`** — input was continuous /
//!   predicted; no caller action needed.
//! * **`Some(PcrEvent::Discontinuity { reason })`** — a time-base
//!   discontinuity has been crossed; downstream PTS/DTS values from
//!   *after* this PCR live in a new time-base relative to the prior
//!   ones. The reason carries enough info to log + decide whether to
//!   reset codec-side buffers.
//! * **`Some(ContinuityEvent::{Dropped, Duplicate, OutOfOrder,
//!   Discontinuity})`** — what the CC tracker noticed. `Dropped` is
//!   the "wake up, packets were lost" signal; the others are
//!   spec-permitted.

use crate::AdaptationField;

// ----------------------------------------------------------------------
// PCR value type
// ----------------------------------------------------------------------

/// 27 MHz Program Clock Reference sample. Stored as the composed
/// `base × 300 + extension` value so callers can do plain integer
/// arithmetic and ask for either component back when needed.
///
/// The full 27 MHz value uses 42 bits; we store it in a `u64` and
/// expose modular subtraction so wraparound at `2^33 × 300` ticks
/// (≈ 26.5 hours) is correct without callers having to think about
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pcr {
    /// Composed 27 MHz value: `base × 300 + extension`.
    /// Range is `0 ..= (2^33 - 1) × 300 + 299`.
    pub ticks_27mhz: u64,
}

/// Modulus of the composed 27 MHz PCR value — one full wrap.
///
/// Equal to `(1 << 33) × 300 = 2_576_980_377_600`. After the PCR
/// value reaches this it wraps back to 0.
pub const PCR_MODULUS_27MHZ: u64 = (1u64 << 33) * 300;

/// Spec-defined PCR tolerance — ±500 ns at 27 MHz is ±13.5 ticks.
/// We round to 14 ticks as the conservative integer bound.
///
/// Source: ISO/IEC 13818-1 §2.4.2.2 ("The PCR tolerance is ±500 ns").
pub const PCR_TOLERANCE_27MHZ: u32 = 14;

impl Pcr {
    /// Build from the 33-bit base + 9-bit extension as they sit in
    /// the adaptation field.
    pub fn from_base_ext(base_90khz: u64, extension: u16) -> Self {
        Self {
            ticks_27mhz: (base_90khz & ((1u64 << 33) - 1)) * 300 + (extension as u64 % 300),
        }
    }

    /// Build from an already-composed 27 MHz tick count.
    pub fn from_ticks_27mhz(ticks: u64) -> Self {
        Self {
            ticks_27mhz: ticks % PCR_MODULUS_27MHZ,
        }
    }

    /// 33-bit `program_clock_reference_base` half (90 kHz).
    pub fn base_90khz(self) -> u64 {
        self.ticks_27mhz / 300
    }

    /// 9-bit `program_clock_reference_extension` half (0..=299).
    pub fn extension(self) -> u16 {
        (self.ticks_27mhz % 300) as u16
    }

    /// Difference `self - other`, in 27 MHz ticks, on the modular
    /// PCR ring (i.e. wraps correctly when `other` is greater than
    /// `self` by less than half the modulus).
    ///
    /// Result is signed: positive when `self` is "after" `other`.
    pub fn delta_ticks(self, other: Pcr) -> i64 {
        let half = (PCR_MODULUS_27MHZ / 2) as i64;
        let m = PCR_MODULUS_27MHZ as i64;
        let raw = self.ticks_27mhz as i64 - other.ticks_27mhz as i64;
        if raw > half {
            raw - m
        } else if raw < -half {
            raw + m
        } else {
            raw
        }
    }
}

// ----------------------------------------------------------------------
// PCR tracker
// ----------------------------------------------------------------------

/// Why a [`PcrTracker`] reported a discontinuity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscontinuityReason {
    /// Stream signalled it explicitly — adaptation field carried
    /// `discontinuity_indicator = 1` on a PCR-bearing packet.
    /// §2.4.3.5: "In the packet in which the system time-base
    /// discontinuity occurs."
    Signalled,
    /// No explicit signal but the observed PCR jump exceeded
    /// [`PcrTracker::max_jitter_27mhz`] (≫ ±500 ns spec tolerance).
    /// Some real-world muxers drop the indicator on a clean
    /// re-mux, and the only evidence is the jump itself.
    JumpExceedsTolerance {
        /// Observed delta in 27 MHz ticks; signed.
        observed_delta: i64,
        /// Predicted delta from the running bitrate estimate.
        predicted_delta: i64,
    },
}

/// Outcome of feeding one packet to a [`PcrTracker`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PcrEvent {
    /// Packet carried a PCR and it was within the tolerance window —
    /// `jitter_27mhz` is the signed residual against the running
    /// bitrate's prediction (0 on the first two samples — see
    /// [`PcrTracker`] for the formula).
    Sample {
        pcr: Pcr,
        /// Signed jitter in 27 MHz ticks against the predicted
        /// arrival time. 0 until the third PCR (the first lets us
        /// remember a value, the second lets us bootstrap the rate,
        /// the third is the first one we can compare).
        jitter_27mhz: i64,
        /// Instantaneous bitrate estimate (bits per second). 0 on
        /// the first PCR; thereafter the rate computed from the
        /// previous pair of PCRs and the byte offsets between them.
        bitrate_bps: u64,
    },
    /// Either the adaptation field set `discontinuity_indicator = 1`
    /// or the PCR jump exceeded `max_jitter_27mhz`. The internal
    /// running rate has been reset; the next two PCR samples will
    /// bootstrap a fresh estimate.
    Discontinuity {
        pcr: Pcr,
        reason: DiscontinuityReason,
    },
}

/// Per-PCR-PID PCR recovery + discontinuity detector.
///
/// Construct one per `PCR_PID` and call [`PcrTracker::observe`] for
/// every TS
/// packet on that PID. Packets without a PCR are silently ignored
/// (the tracker still reads them for the `discontinuity_indicator`
/// flag, since §2.4.3.5 allows the indicator to be set in packets
/// *prior* to the one carrying the new PCR).
///
/// The tracker keeps the last PCR + byte-offset to compute the
/// instantaneous bitrate, and the *previous* pair so a fresh sample
/// can have its jitter computed without a second sample arriving.
#[derive(Debug, Clone)]
pub struct PcrTracker {
    /// Threshold (in 27 MHz ticks) beyond which an unsignalled jump
    /// is reported as a discontinuity. Defaults to 100 ms × 27000 =
    /// 2 700 000 ticks. The spec says ±500 ns is the *spec*
    /// tolerance; real-world re-mux jitter is far higher (tens of
    /// milliseconds) so we use a window large enough to ignore
    /// schedule wobble but small enough to catch a clean time-base
    /// reset.
    pub max_jitter_27mhz: u32,
    /// Last observed PCR + its byte offset in the stream (caller-
    /// supplied via [`observe`]).
    last: Option<(Pcr, u64)>,
    /// Second-to-last observed PCR + byte offset; needed to
    /// extrapolate the predicted arrival time for the current sample.
    prev: Option<(Pcr, u64)>,
    /// Sticky flag for the §2.4.3.5 "indicator may be set on multiple
    /// packets up to and including the one with the new PCR" case.
    /// When set, the next PCR observed is treated as the new
    /// time-base anchor regardless of its delta.
    pending_signalled_discontinuity: bool,
}

impl PcrTracker {
    /// Default jitter window: 100 ms.
    ///
    /// At 27 MHz that's 2 700 000 ticks. Comfortably above the
    /// ±500 ns spec PCR tolerance but tight enough that a clean
    /// re-mux time-base reset (which jumps by seconds or hours)
    /// fires the discontinuity path.
    pub const DEFAULT_MAX_JITTER_27MHZ: u32 = 2_700_000;

    /// Build a tracker with the default jitter window.
    pub fn new() -> Self {
        Self::with_jitter_window(Self::DEFAULT_MAX_JITTER_27MHZ)
    }

    /// Build a tracker with a custom jitter window (27 MHz ticks).
    pub fn with_jitter_window(max_jitter_27mhz: u32) -> Self {
        Self {
            max_jitter_27mhz,
            last: None,
            prev: None,
            pending_signalled_discontinuity: false,
        }
    }

    /// Observe one packet's adaptation field.
    ///
    /// `byte_offset` is the position of this packet's first byte in
    /// the contiguous TS stream. It only needs to be monotonic; the
    /// tracker uses differences, not absolute values. Typical
    /// callers pass `bytes_read - 188`.
    ///
    /// Returns `None` when the packet had no PCR and no pending
    /// discontinuity to commit.
    pub fn observe(&mut self, af: &AdaptationField<'_>, byte_offset: u64) -> Option<PcrEvent> {
        // The discontinuity indicator may appear on packets *before*
        // the one with the new PCR, per §2.4.3.5. Accumulate the
        // flag and only act when the next PCR actually arrives.
        if af.discontinuity_indicator {
            self.pending_signalled_discontinuity = true;
        }
        let (base, ext) = match (af.pcr_base, af.pcr_extension) {
            (Some(b), Some(e)) => (b, e),
            _ => return None,
        };
        let pcr = Pcr::from_base_ext(base, ext);

        // Signalled discontinuity wins over arithmetic — even a
        // microscopic PCR jump is a reset if the encoder said so.
        if self.pending_signalled_discontinuity {
            self.pending_signalled_discontinuity = false;
            self.last = Some((pcr, byte_offset));
            self.prev = None;
            return Some(PcrEvent::Discontinuity {
                pcr,
                reason: DiscontinuityReason::Signalled,
            });
        }

        let event = match (self.prev, self.last) {
            // First-ever PCR. Bootstrap. Jitter 0, bitrate 0.
            (None, None) => PcrEvent::Sample {
                pcr,
                jitter_27mhz: 0,
                bitrate_bps: 0,
            },
            // Second PCR. We can compute a bitrate but not a jitter
            // residual yet (no prior rate to compare against).
            (None, Some((last_pcr, last_off))) => {
                let dpcr = pcr.delta_ticks(last_pcr);
                let dbytes = byte_offset.saturating_sub(last_off);
                let bitrate = compute_bitrate_bps(dpcr, dbytes);
                PcrEvent::Sample {
                    pcr,
                    jitter_27mhz: 0,
                    bitrate_bps: bitrate,
                }
            }
            // Third+ PCR. Predict the arrival delta from the prior
            // pair's rate; compare with what we got.
            (Some((prev_pcr, prev_off)), Some((last_pcr, last_off))) => {
                let prev_dpcr = last_pcr.delta_ticks(prev_pcr);
                let prev_dbytes = last_off.saturating_sub(prev_off).max(1);
                let cur_dbytes = byte_offset.saturating_sub(last_off);
                // Predicted delta = prev_dpcr × cur_dbytes / prev_dbytes.
                // Use i128 to avoid overflow on long-running streams.
                let predicted_delta =
                    ((prev_dpcr as i128) * (cur_dbytes as i128) / (prev_dbytes as i128)) as i64;
                let observed_delta = pcr.delta_ticks(last_pcr);
                let jitter = observed_delta - predicted_delta;
                if jitter.unsigned_abs() > self.max_jitter_27mhz as u64 {
                    // Unsignalled jump. Reset and report.
                    self.last = Some((pcr, byte_offset));
                    self.prev = None;
                    return Some(PcrEvent::Discontinuity {
                        pcr,
                        reason: DiscontinuityReason::JumpExceedsTolerance {
                            observed_delta,
                            predicted_delta,
                        },
                    });
                }
                let bitrate = compute_bitrate_bps(observed_delta, cur_dbytes);
                PcrEvent::Sample {
                    pcr,
                    jitter_27mhz: jitter,
                    bitrate_bps: bitrate,
                }
            }
            // (Some, None) shouldn't happen — we always write `last`
            // before `prev` advances. Treat as bootstrap.
            (Some(_), None) => PcrEvent::Sample {
                pcr,
                jitter_27mhz: 0,
                bitrate_bps: 0,
            },
        };

        self.prev = self.last;
        self.last = Some((pcr, byte_offset));
        Some(event)
    }

    /// Most recent PCR sample, if any.
    pub fn last_pcr(&self) -> Option<Pcr> {
        self.last.map(|(p, _)| p)
    }

    /// Discard accumulated state — useful after the demuxer
    /// independently detects an EOF + restart (e.g. an HLS
    /// discontinuity boundary between two segments).
    pub fn reset(&mut self) {
        self.last = None;
        self.prev = None;
        self.pending_signalled_discontinuity = false;
    }
}

impl Default for PcrTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Bitrate (bits per second) from a `(delta_pcr_27mhz, delta_bytes)`
/// pair. Returns 0 on degenerate inputs.
fn compute_bitrate_bps(delta_pcr_27mhz: i64, delta_bytes: u64) -> u64 {
    if delta_pcr_27mhz <= 0 || delta_bytes == 0 {
        return 0;
    }
    // bits / second = (bytes × 8) × 27_000_000 / delta_pcr_27mhz.
    // Use u128 to keep the numerator from overflowing on multi-MB
    // gaps between PCRs.
    let num = (delta_bytes as u128) * 8 * 27_000_000;
    let den = delta_pcr_27mhz as u128;
    (num / den) as u64
}

// ----------------------------------------------------------------------
// Continuity counter tracker
// ----------------------------------------------------------------------

/// Outcome of feeding one packet to a [`ContinuityTracker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityEvent {
    /// CC differs from previous by exactly 1 mod 16 (or this is the
    /// first packet) — the expected case.
    Continuous,
    /// CC matched the previous packet's value. §2.4.3.3: "duplicate
    /// packets may be sent as two, and only two, consecutive TS
    /// packets". The current packet may be discarded if the previous
    /// one was already emitted.
    Duplicate,
    /// CC did not increment (`adaptation_field_control` was `'00'`
    /// or `'10'`). Spec-permitted; not a drop.
    NoPayload,
    /// CC jumped by more than 1 — at least one packet was lost.
    /// Reported delta is `(current - previous - 1) mod 16`, i.e.
    /// the minimum number of packets we know are missing (the
    /// counter is only 4 bits so larger losses are
    /// indistinguishable).
    Dropped { gap: u8 },
    /// `discontinuity_indicator = 1` on this packet — §2.4.3.4 says
    /// the CC may be discontinuous and we should not interpret the
    /// gap as a drop.
    Discontinuity,
}

/// Per-PID continuity-counter tracker per ISO/IEC 13818-1 §2.4.3.3.
///
/// We track only the last **payload-bearing** packet's CC; the spec
/// rule "the continuity_counter shall not be incremented when the
/// adaptation_field_control of the packet equals '00' or '10'" means
/// payload-less packets carry whatever CC the most recent payload
/// packet had, and the next payload packet's expected CC is one more
/// than that.
#[derive(Debug, Default, Clone)]
pub struct ContinuityTracker {
    /// 4-bit CC of the most recent payload-bearing packet, or `None`
    /// before any has been seen (and after a `Discontinuity` reset).
    last_payload_cc: Option<u8>,
    /// True iff the last payload-bearing packet's CC was already used
    /// in a duplicate (i.e. we've seen the original + one duplicate
    /// already). §2.4.3.3 caps duplicates at *one* — a third identical
    /// CC is a drop, not a second duplicate.
    duplicate_already_seen: bool,
}

impl ContinuityTracker {
    /// Build an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one TS packet's CC + adaptation-field info.
    ///
    /// `cc` is the packet's `continuity_counter`,
    /// `has_payload` is true when `adaptation_field_control` has the
    /// payload bit (`0b01` or `0b11`), and
    /// `discontinuity_indicator` is the adaptation field's flag
    /// (false when there is no adaptation field).
    pub fn observe(
        &mut self,
        cc: u8,
        has_payload: bool,
        discontinuity_indicator: bool,
    ) -> ContinuityEvent {
        let cc = cc & 0x0F;
        if discontinuity_indicator {
            // Indicator clears any prior state; treat this packet
            // as the new anchor.
            if has_payload {
                self.last_payload_cc = Some(cc);
            } else {
                self.last_payload_cc = None;
            }
            self.duplicate_already_seen = false;
            return ContinuityEvent::Discontinuity;
        }
        if !has_payload {
            // §2.4.3.3: CC does not increment on these packets. We
            // don't move the anchor.
            return ContinuityEvent::NoPayload;
        }
        let prev = match self.last_payload_cc {
            None => {
                self.last_payload_cc = Some(cc);
                self.duplicate_already_seen = false;
                return ContinuityEvent::Continuous;
            }
            Some(p) => p,
        };
        let expected = (prev + 1) & 0x0F;
        if cc == expected {
            self.last_payload_cc = Some(cc);
            self.duplicate_already_seen = false;
            ContinuityEvent::Continuous
        } else if cc == prev && !self.duplicate_already_seen {
            // First duplicate after the original — spec-permitted.
            self.duplicate_already_seen = true;
            ContinuityEvent::Duplicate
        } else {
            // Any other CC, including a second duplicate, is a drop.
            let gap = cc.wrapping_sub(expected) & 0x0F;
            self.last_payload_cc = Some(cc);
            self.duplicate_already_seen = false;
            // gap is "current - expected" mod 16. A drop of N
            // packets gives gap = N (with N >= 1 by construction
            // here — equal would have hit the Continuous branch).
            // We report `gap` as the minimum-known missing count.
            ContinuityEvent::Dropped { gap: gap.max(1) }
        }
    }

    /// Discard accumulated state.
    pub fn reset(&mut self) {
        self.last_payload_cc = None;
        self.duplicate_already_seen = false;
    }
}

// ----------------------------------------------------------------------
// PTS / DTS timestamp unwrapping
// ----------------------------------------------------------------------

/// Modulus of a PES presentation / decode timestamp — the 33-bit
/// `PTS` / `DTS` field (§2.4.3.7) wraps at `2^33` 90 kHz ticks.
///
/// `2^33 / 90_000 ≈ 95443.72 s ≈ 26.5 h`, the same window the composed
/// 27 MHz PCR value wraps over.
pub const TIMESTAMP_MODULUS_90KHZ: u64 = 1u64 << 33;

/// Half the timestamp modulus — the threshold past which a raw-timestamp
/// step is interpreted as a wrap (forward) or a backward jump rather
/// than ordinary forward progress. A step larger than this in the
/// "backward" direction is read as a `2^33` forward wrap; a step larger
/// than this in the "forward" direction is read as a backward
/// discontinuity.
const TIMESTAMP_WRAP_THRESHOLD_90KHZ: u64 = TIMESTAMP_MODULUS_90KHZ / 2;

/// Classification of one PTS or DTS observation on a PID, returned by
/// [`PtsTracker::observe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampEvent {
    /// The first timestamp seen on the PID — establishes the anchor.
    First,
    /// The raw timestamp advanced normally (allowing for a single
    /// `2^33` wrap). The decoded value is the **extended**, monotonically
    /// non-decreasing 90 kHz timestamp.
    Forward,
    /// The 33-bit field wrapped past `2^33`; the extended timestamp
    /// continues to increase. Reported separately so a caller can note
    /// the wrap for diagnostics.
    Wrapped,
    /// The raw timestamp moved backward by more than half the modulus —
    /// a genuine discontinuity (stream splice / seek) rather than a
    /// wrap. The tracker re-anchors on the new value; the extended
    /// timestamp is reset to the raw value.
    Backward,
}

/// Per-PID PTS / DTS unwrapper per ISO/IEC 13818-1 §2.4.3.7.
///
/// PES timestamps are 33-bit 90 kHz values that wrap every ~26.5 hours.
/// A demuxer that hands raw 33-bit values to a muxer produces a
/// non-monotonic timeline at the wrap; this tracker watches the raw
/// values on one PID and produces a **64-bit extended** timestamp that
/// keeps counting across wraps, while flagging genuine backward
/// discontinuities (a splice / seek) so the caller can re-base instead
/// of fabricating a 26-hour jump.
///
/// One tracker instance is kept per PID, typically one for PTS and a
/// second for DTS (the two advance independently — DTS ≤ PTS within a
/// frame, but the unwrap logic is identical).
#[derive(Debug, Default, Clone)]
pub struct PtsTracker {
    /// Number of completed `2^33` wraps accumulated so far.
    wrap_count: u64,
    /// Most recent **raw** 33-bit timestamp, or `None` before the first
    /// observation (and after a `reset`).
    last_raw: Option<u64>,
    /// Extended-timeline hint installed by [`Self::seed`]; consumed by
    /// the first `observe` after the seed to pick the wrap epoch whose
    /// extended value lies nearest the hint.
    seed_hint: Option<u64>,
}

impl PtsTracker {
    /// Build an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one raw 33-bit timestamp and return its classification.
    ///
    /// The input is masked to 33 bits, so passing an already-extended
    /// value is harmless. After this call [`Self::extended`] returns the
    /// unwrapped 90 kHz timestamp for the just-observed value.
    pub fn observe(&mut self, raw_timestamp: u64) -> TimestampEvent {
        let raw = raw_timestamp & (TIMESTAMP_MODULUS_90KHZ - 1);
        let prev = match self.last_raw {
            None => {
                self.last_raw = Some(raw);
                if let Some(hint) = self.seed_hint.take() {
                    self.wrap_count = nearest_epoch(raw, hint);
                }
                return TimestampEvent::First;
            }
            Some(p) => p,
        };
        self.last_raw = Some(raw);

        if raw >= prev {
            let forward = raw - prev;
            if forward > TIMESTAMP_WRAP_THRESHOLD_90KHZ {
                // A large forward raw step is really a backward jump
                // around the ring: the value went down then wrapped.
                // Treat it as a genuine discontinuity, re-anchoring.
                self.wrap_count = 0;
                TimestampEvent::Backward
            } else {
                TimestampEvent::Forward
            }
        } else {
            let backward = prev - raw;
            if backward > TIMESTAMP_WRAP_THRESHOLD_90KHZ {
                // The raw value dropped by more than half the ring — the
                // 33-bit field wrapped forward past 2^33.
                self.wrap_count += 1;
                TimestampEvent::Wrapped
            } else {
                // A small genuine backward step — discontinuity.
                self.wrap_count = 0;
                TimestampEvent::Backward
            }
        }
    }

    /// The extended (unwrapped) 64-bit 90 kHz timestamp for the most
    /// recently observed raw value, or `None` before the first
    /// observation.
    ///
    /// Equal to `wrap_count × 2^33 + last_raw`.
    pub fn extended(&self) -> Option<u64> {
        self.last_raw
            .map(|raw| self.wrap_count * TIMESTAMP_MODULUS_90KHZ + raw)
    }

    /// The most recent raw 33-bit timestamp, or `None` before the first
    /// observation.
    pub fn last_raw(&self) -> Option<u64> {
        self.last_raw
    }

    /// Number of `2^33` wraps accumulated since the last anchor.
    pub fn wrap_count(&self) -> u64 {
        self.wrap_count
    }

    /// Discard accumulated state.
    pub fn reset(&mut self) {
        self.wrap_count = 0;
        self.last_raw = None;
        self.seed_hint = None;
    }

    /// Reset the tracker and install an **extended-timeline hint** for
    /// the next observation — the seek-continuity companion to
    /// [`Self::reset`].
    ///
    /// A demuxer that repositions its byte cursor (a seek) knows the
    /// extended 90 kHz time of the landing point (e.g. from the PCR it
    /// landed on) but must discard the raw-timestamp history, which no
    /// longer precedes the next observation. A plain `reset` would
    /// re-anchor the extended timeline at the next raw value — so a
    /// stream that had wrapped past `2^33` would suddenly report small
    /// post-wrap raw values, tearing the timeline the caller seeked
    /// along. `seed` instead makes the first `observe` after it pick
    /// the wrap epoch `k` whose extended value `k × 2^33 + raw` lies
    /// nearest `extended_hint`, so the emitted timeline stays on the
    /// same extended axis across the seek. Subsequent observations
    /// unwrap from there exactly as after any first observation.
    pub fn seed(&mut self, extended_hint: u64) {
        self.reset();
        self.seed_hint = Some(extended_hint);
    }
}

/// Wrap-epoch count `k ≥ 0` minimising the distance between
/// `k × 2^33 + raw` and `hint` — how [`PtsTracker::seed`] re-enters an
/// extended timeline from a raw 33-bit observation. The minimising `k`
/// is `hint / 2^33` or that plus one (the hint's own epoch, or the next
/// when `raw` sits just past a wrap the hint precedes); both candidates
/// are compared and one epoch below is considered too so a raw value
/// just *before* a wrap boundary the hint follows resolves backward
/// correctly.
fn nearest_epoch(raw: u64, hint: u64) -> u64 {
    let m = TIMESTAMP_MODULUS_90KHZ;
    let base = hint / m;
    let mut best_k = 0u64;
    let mut best_d = u64::MAX;
    for k in [base.saturating_sub(1), base, base + 1] {
        let ext = k * m + raw;
        let d = ext.abs_diff(hint);
        if d < best_d {
            best_d = d;
            best_k = k;
        }
    }
    best_k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AdaptationField;

    fn af_with_pcr(base: u64, ext: u16, discontinuity: bool) -> AdaptationField<'static> {
        AdaptationField {
            length: 7,
            discontinuity_indicator: discontinuity,
            random_access_indicator: false,
            elementary_stream_priority_indicator: false,
            pcr_flag: true,
            opcr_flag: false,
            splicing_point_flag: false,
            transport_private_data_flag: false,
            adaptation_field_extension_flag: false,
            pcr_base: Some(base),
            pcr_extension: Some(ext),
            opcr_base: None,
            opcr_extension: None,
            splice_countdown: None,
            transport_private_data: None,
            adaptation_field_extension: None,
            raw: &[],
        }
    }

    fn af_no_pcr(discontinuity: bool) -> AdaptationField<'static> {
        AdaptationField {
            length: 1,
            discontinuity_indicator: discontinuity,
            random_access_indicator: false,
            elementary_stream_priority_indicator: false,
            pcr_flag: false,
            opcr_flag: false,
            splicing_point_flag: false,
            transport_private_data_flag: false,
            adaptation_field_extension_flag: false,
            pcr_base: None,
            pcr_extension: None,
            opcr_base: None,
            opcr_extension: None,
            splice_countdown: None,
            transport_private_data: None,
            adaptation_field_extension: None,
            raw: &[],
        }
    }

    #[test]
    fn pcr_round_trips_base_ext() {
        let p = Pcr::from_base_ext(0x1_2345_6789, 200);
        assert_eq!(p.base_90khz(), 0x1_2345_6789);
        assert_eq!(p.extension(), 200);
        let q = Pcr::from_ticks_27mhz(p.ticks_27mhz);
        assert_eq!(p, q);
    }

    #[test]
    fn pcr_delta_handles_wraparound() {
        // A PCR just past 0 minus a PCR just below the modulus should
        // give a small positive delta (i.e. the new sample is just
        // after the wrap).
        let near_max = Pcr::from_ticks_27mhz(PCR_MODULUS_27MHZ - 1000);
        let just_after = Pcr::from_ticks_27mhz(500);
        // 500 - (-1000) = 1500 forward across the wrap.
        assert_eq!(just_after.delta_ticks(near_max), 1500);
        // Reverse delta should be the negative of that.
        assert_eq!(near_max.delta_ticks(just_after), -1500);
    }

    #[test]
    fn pcr_tracker_bootstraps_quietly() {
        // First sample → 0 jitter, 0 bitrate.
        // Second sample → 0 jitter, but bitrate computable.
        // Third sample → real jitter relative to the prior pair's rate.
        let mut t = PcrTracker::new();
        // 1 Mbit/s = 1_000_000 bps = 125_000 bytes/s.
        // At 27 MHz that's 27_000_000 / 125_000 = 216 ticks per byte.
        let pcr1 = Pcr::from_ticks_27mhz(0);
        let pcr2 = Pcr::from_ticks_27mhz(216 * 1880); // 10 TS packets later
        let pcr3 = Pcr::from_ticks_27mhz(216 * 1880 * 2);
        let af1 = af_with_pcr(pcr1.base_90khz(), pcr1.extension(), false);
        let af2 = af_with_pcr(pcr2.base_90khz(), pcr2.extension(), false);
        let af3 = af_with_pcr(pcr3.base_90khz(), pcr3.extension(), false);
        let e1 = t.observe(&af1, 0).unwrap();
        match e1 {
            PcrEvent::Sample { jitter_27mhz, .. } => assert_eq!(jitter_27mhz, 0),
            _ => panic!("expected sample"),
        }
        let e2 = t.observe(&af2, 1880).unwrap();
        match e2 {
            PcrEvent::Sample {
                jitter_27mhz,
                bitrate_bps,
                ..
            } => {
                assert_eq!(jitter_27mhz, 0);
                assert_eq!(bitrate_bps, 1_000_000);
            }
            _ => panic!("expected sample"),
        }
        let e3 = t.observe(&af3, 1880 * 2).unwrap();
        match e3 {
            PcrEvent::Sample {
                jitter_27mhz,
                bitrate_bps,
                ..
            } => {
                assert_eq!(jitter_27mhz, 0);
                assert_eq!(bitrate_bps, 1_000_000);
            }
            _ => panic!("expected sample"),
        }
    }

    #[test]
    fn pcr_tracker_detects_signalled_discontinuity() {
        let mut t = PcrTracker::new();
        let pcr1 = Pcr::from_ticks_27mhz(0);
        let pcr2 = Pcr::from_ticks_27mhz(216 * 1880);
        let pcr3 = Pcr::from_ticks_27mhz(216 * 1880 * 2);
        // Signalled reset before the third sample, but the third
        // sample itself is *exactly* where the rate would predict —
        // the indicator wins regardless.
        t.observe(&af_with_pcr(pcr1.base_90khz(), pcr1.extension(), false), 0)
            .unwrap();
        t.observe(
            &af_with_pcr(pcr2.base_90khz(), pcr2.extension(), false),
            1880,
        )
        .unwrap();
        let e3 = t
            .observe(
                &af_with_pcr(pcr3.base_90khz(), pcr3.extension(), true),
                1880 * 2,
            )
            .unwrap();
        match e3 {
            PcrEvent::Discontinuity { reason, .. } => {
                assert_eq!(reason, DiscontinuityReason::Signalled);
            }
            _ => panic!("expected discontinuity, got {e3:?}"),
        }
        // After the discontinuity the tracker is bootstrapped from
        // the new sample as the anchor.
        assert_eq!(t.last_pcr(), Some(pcr3));
    }

    #[test]
    fn pcr_tracker_indicator_on_packet_before_new_pcr() {
        // §2.4.3.5: the indicator may be set on packets prior to the
        // one carrying the new PCR. Verify the tracker carries the
        // flag forward.
        let mut t = PcrTracker::new();
        let pcr1 = Pcr::from_ticks_27mhz(0);
        let pcr2 = Pcr::from_ticks_27mhz(1000);
        t.observe(&af_with_pcr(pcr1.base_90khz(), pcr1.extension(), false), 0)
            .unwrap();
        // Indicator-only packet, no PCR. Should *not* fire an event.
        assert!(t.observe(&af_no_pcr(true), 188).is_none());
        // Next PCR triggers the deferred discontinuity event.
        let e2 = t
            .observe(
                &af_with_pcr(pcr2.base_90khz(), pcr2.extension(), false),
                376,
            )
            .unwrap();
        match e2 {
            PcrEvent::Discontinuity { reason, .. } => {
                assert_eq!(reason, DiscontinuityReason::Signalled);
            }
            _ => panic!("expected discontinuity"),
        }
    }

    #[test]
    fn pcr_tracker_detects_unsignalled_jump() {
        // Rate is 1 Mbit/s (216 ticks/byte). The third sample lands
        // a full second too far ahead (27 000 000 ticks late). The
        // tracker should classify it as a jump even with the
        // discontinuity_indicator off.
        let mut t = PcrTracker::new();
        let pcr1 = Pcr::from_ticks_27mhz(0);
        let pcr2 = Pcr::from_ticks_27mhz(216 * 1880);
        let bad = Pcr::from_ticks_27mhz(216 * 1880 * 2 + 27_000_000);
        t.observe(&af_with_pcr(pcr1.base_90khz(), pcr1.extension(), false), 0)
            .unwrap();
        t.observe(
            &af_with_pcr(pcr2.base_90khz(), pcr2.extension(), false),
            1880,
        )
        .unwrap();
        let e3 = t
            .observe(
                &af_with_pcr(bad.base_90khz(), bad.extension(), false),
                1880 * 2,
            )
            .unwrap();
        match e3 {
            PcrEvent::Discontinuity {
                reason: DiscontinuityReason::JumpExceedsTolerance { .. },
                ..
            } => {}
            _ => panic!("expected jump-exceeds-tolerance, got {e3:?}"),
        }
    }

    #[test]
    fn continuity_tracker_classifies_typical_flow() {
        let mut t = ContinuityTracker::new();
        assert_eq!(t.observe(5, true, false), ContinuityEvent::Continuous);
        assert_eq!(t.observe(6, true, false), ContinuityEvent::Continuous);
        // Duplicate (same CC, payload-bearing).
        assert_eq!(t.observe(6, true, false), ContinuityEvent::Duplicate);
        // Skip 7, jump to 9 → one packet dropped.
        assert_eq!(
            t.observe(9, true, false),
            ContinuityEvent::Dropped { gap: 2 }
        );
    }

    #[test]
    fn continuity_tracker_wraps_at_15() {
        let mut t = ContinuityTracker::new();
        t.observe(14, true, false);
        assert_eq!(t.observe(15, true, false), ContinuityEvent::Continuous);
        assert_eq!(t.observe(0, true, false), ContinuityEvent::Continuous);
        assert_eq!(t.observe(1, true, false), ContinuityEvent::Continuous);
    }

    #[test]
    fn continuity_tracker_no_payload_does_not_advance() {
        let mut t = ContinuityTracker::new();
        t.observe(3, true, false);
        // Payload-less packet — CC stays at 3.
        assert_eq!(t.observe(3, false, false), ContinuityEvent::NoPayload);
        // Next payload packet should be 4, not 5 — the CC didn't move.
        assert_eq!(t.observe(4, true, false), ContinuityEvent::Continuous);
    }

    #[test]
    fn continuity_tracker_discontinuity_indicator_resets() {
        let mut t = ContinuityTracker::new();
        t.observe(3, true, false);
        // Big CC jump but indicator is set — should be Discontinuity,
        // not Dropped.
        assert_eq!(t.observe(10, true, true), ContinuityEvent::Discontinuity);
        // Subsequent packets pick up from 10.
        assert_eq!(t.observe(11, true, false), ContinuityEvent::Continuous);
    }

    #[test]
    fn pts_tracker_first_then_forward() {
        let mut t = PtsTracker::new();
        assert_eq!(t.observe(90_000), TimestampEvent::First);
        assert_eq!(t.extended(), Some(90_000));
        assert_eq!(t.observe(180_000), TimestampEvent::Forward);
        assert_eq!(t.extended(), Some(180_000));
        assert_eq!(t.wrap_count(), 0);
        assert_eq!(t.last_raw(), Some(180_000));
    }

    #[test]
    fn pts_tracker_unwraps_at_2pow33() {
        let mut t = PtsTracker::new();
        // Sit just below the 33-bit ceiling, then step past it.
        let near_top = TIMESTAMP_MODULUS_90KHZ - 1_000;
        assert_eq!(t.observe(near_top), TimestampEvent::First);
        // Next raw value is 2_000 ticks later → wraps to 1_000.
        assert_eq!(t.observe(1_000), TimestampEvent::Wrapped);
        assert_eq!(t.wrap_count(), 1);
        // Extended timestamp must keep increasing across the wrap.
        assert_eq!(t.extended(), Some(TIMESTAMP_MODULUS_90KHZ + 1_000));
        // A further normal step stays in the wrapped epoch.
        assert_eq!(t.observe(2_000), TimestampEvent::Forward);
        assert_eq!(t.extended(), Some(TIMESTAMP_MODULUS_90KHZ + 2_000));
    }

    #[test]
    fn pts_tracker_backward_jump_is_discontinuity_not_wrap() {
        let mut t = PtsTracker::new();
        assert_eq!(t.observe(1_000_000), TimestampEvent::First);
        // A small backward step (seek / splice) re-anchors and resets
        // the extended timeline rather than fabricating a 26 h wrap.
        assert_eq!(t.observe(500_000), TimestampEvent::Backward);
        assert_eq!(t.wrap_count(), 0);
        assert_eq!(t.extended(), Some(500_000));
    }

    #[test]
    fn pts_tracker_large_forward_step_is_backward_around_ring() {
        let mut t = PtsTracker::new();
        // Anchor low, then jump forward by more than half the ring —
        // that is a backward move around the modular ring, classified
        // as a discontinuity (the value decreased then wrapped).
        assert_eq!(t.observe(1_000), TimestampEvent::First);
        let big = TIMESTAMP_WRAP_THRESHOLD_90KHZ + 2_000;
        assert_eq!(t.observe(big), TimestampEvent::Backward);
        assert_eq!(t.extended(), Some(big));
    }

    #[test]
    fn pts_tracker_two_consecutive_wraps() {
        // A monotonic 90 kHz stream advancing in fixed steps across two
        // 2^33 boundaries. The step stays under the 2^32 wrap threshold;
        // the extended timeline must equal the true accumulated ticks.
        let m = TIMESTAMP_MODULUS_90KHZ;
        let step = 1u64 << 20; // 2^20 ticks: many samples per epoch
        let start = m - 5 * step; // a few steps below the first wrap
        let mut t = PtsTracker::new();
        assert_eq!(t.observe(start), TimestampEvent::First);

        let mut wraps_seen = 0u64;
        // start sits 5 steps below the first 2^33 boundary; the second
        // boundary is one full modulus (m/step further) on. Stop one step
        // short of the third boundary so exactly two wraps are crossed.
        let steps = 2 * (m / step);
        for i in 1..=steps {
            let true_ticks = start + i * step;
            let raw = true_ticks & (m - 1);
            let ev = t.observe(raw);
            if ev == TimestampEvent::Wrapped {
                wraps_seen += 1;
            }
            assert!(
                matches!(ev, TimestampEvent::Forward | TimestampEvent::Wrapped),
                "step {i} mis-classified as {ev:?}"
            );
            assert_eq!(t.extended(), Some(true_ticks), "extended drift at step {i}");
        }
        assert_eq!(wraps_seen, 2);
        assert_eq!(t.wrap_count(), 2);
    }

    #[test]
    fn pts_tracker_masks_input_to_33_bits() {
        let mut t = PtsTracker::new();
        // A value with bits above bit 32 set is masked down before use.
        let raw = (1u64 << 40) | 12_345;
        assert_eq!(t.observe(raw), TimestampEvent::First);
        assert_eq!(t.last_raw(), Some(12_345));
        assert_eq!(t.extended(), Some(12_345));
    }

    #[test]
    fn pts_tracker_reset_clears_state() {
        let mut t = PtsTracker::new();
        t.observe(TIMESTAMP_MODULUS_90KHZ - 1);
        t.observe(0); // wrap
        assert_eq!(t.wrap_count(), 1);
        t.reset();
        assert_eq!(t.wrap_count(), 0);
        assert_eq!(t.last_raw(), None);
        assert_eq!(t.extended(), None);
        assert_eq!(t.observe(42), TimestampEvent::First);
    }

    #[test]
    fn pts_tracker_seed_reenters_post_wrap_epoch() {
        let m = TIMESTAMP_MODULUS_90KHZ;
        let mut t = PtsTracker::new();
        // Seek landed at extended time m + 45_000 (past one wrap). The
        // first raw observation (45_500) must extend into epoch 1, not
        // re-anchor at the small raw value.
        t.seed(m + 45_000);
        assert_eq!(t.observe(45_500), TimestampEvent::First);
        assert_eq!(t.extended(), Some(m + 45_500));
        assert_eq!(t.wrap_count(), 1);
        // Subsequent observations unwrap normally from there.
        assert_eq!(t.observe(45_500 + 3_000), TimestampEvent::Forward);
        assert_eq!(t.extended(), Some(m + 48_500));
    }

    #[test]
    fn pts_tracker_seed_resolves_epoch_boundary_both_ways() {
        let m = TIMESTAMP_MODULUS_90KHZ;
        // Hint just AFTER a wrap boundary, raw just BEFORE it: the
        // nearest extended value is one epoch below the hint's.
        let mut t = PtsTracker::new();
        t.seed(2 * m + 100);
        t.observe(m - 50);
        assert_eq!(t.extended(), Some(2 * m - 50));
        // Hint just BEFORE a wrap boundary, raw just after it: the
        // nearest extended value is one epoch above the hint's.
        let mut t = PtsTracker::new();
        t.seed(m - 100);
        t.observe(50);
        assert_eq!(t.extended(), Some(m + 50));
    }

    #[test]
    fn pts_tracker_seed_epoch_zero_hint_stays_unwrapped() {
        let mut t = PtsTracker::new();
        t.seed(90_000);
        t.observe(91_000);
        assert_eq!(t.extended(), Some(91_000));
        assert_eq!(t.wrap_count(), 0);
    }

    #[test]
    fn pts_tracker_reset_discards_pending_seed() {
        let m = TIMESTAMP_MODULUS_90KHZ;
        let mut t = PtsTracker::new();
        t.seed(3 * m);
        t.reset();
        t.observe(500);
        assert_eq!(t.extended(), Some(500), "reset must discard the hint");
    }
}
