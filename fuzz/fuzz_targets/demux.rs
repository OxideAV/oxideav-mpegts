#![no_main]

//! Arbitrary hostile bytes through the whole demux-side surface.
//!
//! Every walk decision in a transport stream is attacker-controlled:
//! the 188-byte packet grid (and its 192/204-byte physical framings),
//! adaptation-field lengths + optional-field pairings (§2.4.3.4 /
//! §2.4.3.5), the 12-bit `section_length` of every PSI / DVB SI
//! section reassembled across packets (§2.4.4 pointer_field + PUSI),
//! the §2.6 / EN 300 468 §6 descriptor TLV loops, the Table 2-17 PES
//! optional-header ladder, the 33-bit PTS/DTS ring (§2.4.3.7), and
//! the PCR arithmetic behind duration probes and seek bisection.
//!
//! Contract under test: the validator, the packet walk (PSI assembly
//! into every table parser + descriptor walks, PES reassembly, clock
//! trackers), the §2.4.2 T-STD replay, and the typed demuxer battery
//! (open, bounded drain, RAP index, all three seek paths) ALWAYS
//! return — no panic, no abort, no debug-build integer overflow, no
//! out-of-bounds index, no allocation proportional to an attacker-
//! claimed length field.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oxideav_mpegts_fuzz::exercise_hostile(data);
});
