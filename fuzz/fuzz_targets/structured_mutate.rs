#![no_main]

//! Structure-aware hostile mutation — the coverage-guided upgrade of
//! the in-tree deterministic hostile sweeps.
//!
//! The first recipe bytes build a writer-shaped fixture through our
//! own muxer (multi-program PSI, DVB SI, splice runs, CBR null
//! pacing, PSI repetition — whatever the plan picks). The remaining
//! bytes drive a bounded mutation program over the fixture:
//!
//!   * sync-byte kills on the 188-byte grid (resync / §2.4.3.4
//!     double-sync validation);
//!   * TS-header and adaptation-field flips (PID remaps, flag
//!     pairings, CC gaps);
//!   * section-header flips right after a PUSI pointer_field
//!     (table_id / section_length / version arithmetic, §2.4.4);
//!   * CRC-region flips at PSI payload tails (CRC-32 rejection);
//!   * packet drops and duplicates (§2.4.3.3 continuity + duplicate
//!     cap);
//!   * truncation at arbitrary (usually unaligned) offsets;
//!   * 192/204-byte physical reframing of the mutant.
//!
//! Because the mutation starts from a structurally deep stream, the
//! fuzzer reaches parser states (fragmented PMT continuation chains,
//! splice countdown runs, CBR null spacing, SI descriptor loops)
//! that raw random bytes almost never assemble.
//!
//! Contract: no panic, no abort, no debug-build overflow, no
//! attacker-proportional allocation — whether a mutant opens or
//! errors is the stream's business. The full hostile battery runs on
//! every mutant.

use libfuzzer_sys::fuzz_target;

use oxideav_mpegts_fuzz::{exercise_hostile, mutate, MuxPlan, Recipe};

fuzz_target!(|data: &[u8]| {
    let mut r = Recipe::new(data);
    let plan = MuxPlan::decode(&mut r);
    let base = plan.run();
    if base.is_empty() {
        return;
    }
    let mut ops = Recipe::new(r.rest());
    let mutant = mutate(&base, &mut ops);
    exercise_hostile(&mutant);
});
