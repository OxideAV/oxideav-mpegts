#![no_main]

//! Structure-aware write-side recipes — the round-trip identity
//! contract under fuzz.
//!
//! The recipe bytes decode into a valid-by-construction multi-program
//! mux plan: 1–2 programs x 1–3 streams x 1–16 frames, DVB SDT / EIT
//! / NIT options, §2.4.3.5 / Annex-K splice signalling (plain and
//! seamless, with post-splice countdowns), §2.4.3.5 / §2.7.6
//! time-base discontinuities, §2.4.2 CBR pacing, PSI repetition
//! intervals, §2.7.5 DTS coding, and 33-bit PTS-wrap-crossing
//! timelines.
//!
//! Contract: the muxer must accept every decoded plan; its output
//! must be conformant under `validate_ts` (§2.4.3.3 continuity,
//! §2.4.3.5 field pairings + splice coherence, §2.7.2 PCR cadence,
//! §2.4.4 section CRCs) and — for single-program CBR plans — under
//! the §2.4.2 T-STD model; and demuxing each program must reproduce
//! the exact per-stream (PTS, DTS, payload length, keyframe)
//! sequence.

use libfuzzer_sys::fuzz_target;

use oxideav_mpegts_fuzz::{MuxPlan, Recipe};

fuzz_target!(|data: &[u8]| {
    let mut r = Recipe::new(data);
    let plan = MuxPlan::decode(&mut r);
    let bytes = plan.run();
    if plan.total_frames() == 0 {
        return;
    }
    plan.assert_roundtrip(&bytes);
});
