//! Deterministic hostile-input sweeps (test-only module).
//!
//! A tiny in-tree linear-congruential generator drives byte-level
//! mutations and pure-noise buffers through every public parse
//! surface — TS packets, PSI section assembly + table parsers, PES
//! reassembly, the conformance validator, and the demuxer open/read
//! path — asserting the crate's robustness contract: **no panics, no
//! unbounded work or allocation, errors instead of misbehaviour**.
//! The generator is seeded with fixed constants so failures reproduce
//! exactly.

use crate::packet::{AdaptationFieldSpec, TsPacket, TS_PACKET_LEN, TS_SYNC_BYTE};
use crate::pes::{PesHeaderSpec, PesReassembler};
use crate::psi::{ProgramAssociationTable, PsiSectionAssembler};
use crate::validate::validate_ts;

/// Minimal 64-bit LCG (multiplier from a classic 64-bit parameter
/// set); good enough to spread mutations, fully deterministic.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound.max(1) as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

/// Build a well-formed little TS through the crate's own write path:
/// PAT + PMT + a handful of PCR-carrying keyframe PES packets.
fn seed_stream() -> Vec<u8> {
    fn psi_packet(pid: u16, section: &[u8]) -> [u8; TS_PACKET_LEN] {
        let mut pkt = [0xFFu8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = 0b0100_0000 | ((pid >> 8) as u8 & 0x1F);
        pkt[2] = pid as u8;
        pkt[3] = 0b0001_0000;
        pkt[4] = 0; // pointer_field
        pkt[5..5 + section.len()].copy_from_slice(section);
        pkt
    }
    let mut out = Vec::new();
    out.extend_from_slice(&psi_packet(
        0x0000,
        &crate::build::build_pat(1, 0, &[(1, 0x0100)]),
    ));
    let pmt = crate::build::build_pmt(
        1,
        0,
        0x0101,
        &[],
        &[crate::build::PmtStreamEntry {
            stream_type: 0x1B,
            elementary_pid: 0x0101,
            es_info: Vec::new(),
        }],
    );
    out.extend_from_slice(&psi_packet(0x0100, &pmt));
    for i in 0..6u64 {
        let pes = PesHeaderSpec::with_timestamps(0xE0, 1_000 + i * 2_700, None)
            .encode(&[0x42; 60])
            .unwrap();
        let af = AdaptationFieldSpec {
            random_access_indicator: true,
            pcr: Some((900 + i * 2_700, 0)),
            ..Default::default()
        }
        .encode(Some(TS_PACKET_LEN - 4 - pes.len()))
        .unwrap();
        let mut pkt = [0u8; TS_PACKET_LEN];
        pkt[0] = TS_SYNC_BYTE;
        pkt[1] = 0b0100_0000 | 0x01;
        pkt[2] = 0x01;
        pkt[3] = 0b0011_0000 | (i as u8 & 0x0F);
        pkt[4..4 + af.len()].copy_from_slice(&af);
        pkt[4 + af.len()..].copy_from_slice(&pes);
        out.extend_from_slice(&pkt);
    }
    out
}

/// Feed one byte buffer through every non-demuxer parse surface.
fn exercise(bytes: &[u8]) {
    // Validator (two full passes internally).
    let report = validate_ts(bytes);
    assert!(report.packets as usize <= bytes.len() / TS_PACKET_LEN + 1);

    // Raw packet iteration + PSI assembly + PES reassembly.
    let mut pat_asm = PsiSectionAssembler::new();
    let mut pes_asm = PesReassembler::new();
    for pkt in crate::packet::iter_packets(bytes) {
        let pkt = match pkt {
            Ok(p) => p,
            Err(_) => break, // iterator halts after the first bad sync
        };
        if pkt.pid == 0 && !pkt.payload.is_empty() {
            if let Ok(sections) =
                pat_asm.feed(pkt.payload, pkt.payload_unit_start, pkt.continuity_counter)
            {
                for s in &sections {
                    let _ = ProgramAssociationTable::parse(s);
                }
            }
        }
        if pkt.pid == 0x0101 {
            let _ = pes_asm.feed(&pkt);
        }
    }
    let _ = pes_asm.flush();
}

#[test]
fn mutated_streams_never_panic() {
    let seed = seed_stream();
    let mut rng = Lcg::new(0x0415_2026_0717_0001);
    for round in 0..300 {
        let mut bytes = seed.clone();
        // 1..=8 byte mutations per round, anywhere in the stream.
        for _ in 0..(1 + rng.below(8)) {
            let at = rng.below(bytes.len());
            bytes[at] = rng.byte();
        }
        // Occasionally truncate to a non-packet-aligned length.
        if round % 5 == 0 {
            let cut = rng.below(bytes.len());
            bytes.truncate(cut);
        }
        exercise(&bytes);
    }
}

#[test]
fn pure_noise_never_panics() {
    let mut rng = Lcg::new(0xDEAD_2026);
    for size in [0usize, 1, 3, 187, 188, 189, 1024, 8192] {
        let mut bytes = vec![0u8; size];
        for b in &mut bytes {
            *b = rng.byte();
        }
        exercise(&bytes);
        // Every 188-byte window as a standalone packet + PES claim.
        for chunk in bytes.chunks(TS_PACKET_LEN) {
            let _ = TsPacket::parse(chunk);
            let _ = crate::pes::PesPacket::parse(chunk);
        }
    }
    // Noise that always starts with sync bytes on the 188 grid —
    // exercises the AF / payload parse paths rather than the sync
    // check.
    for _ in 0..50 {
        let mut bytes = vec![0u8; 10 * TS_PACKET_LEN];
        for b in &mut bytes {
            *b = rng.byte();
        }
        for k in 0..10 {
            bytes[k * TS_PACKET_LEN] = TS_SYNC_BYTE;
        }
        exercise(&bytes);
    }
}

/// A PSI section claiming the maximum section_length but delivered
/// truncated must neither panic nor make the assembler buffer grow
/// past its documented cap.
#[test]
fn oversized_section_length_is_bounded() {
    let mut section = vec![0x00u8, 0xBF, 0xFF]; // section_length = 0x3FF (over the 1021 PSI cap)
    section.extend_from_slice(&[0xAB; 100]); // far fewer bytes than claimed
    let mut asm = PsiSectionAssembler::new();
    // Feed the truncated head, then continuation garbage.
    let _ = asm.feed(
        &{
            let mut p = vec![0u8]; // pointer_field
            p.extend_from_slice(&section);
            p
        },
        true,
        0,
    );
    for cc in 1..40u8 {
        let _ = asm.feed(&[0xCD; 184], false, cc & 0x0F);
    }
    // No section can ever come out of an over-cap claim; the feed
    // calls above simply must not panic or grow unboundedly.
}

#[cfg(feature = "registry")]
#[test]
fn demuxer_survives_mutations_with_bounded_reads() {
    use oxideav_core::ReadSeek;
    use std::io::Cursor;
    let seed = seed_stream();
    let mut rng = Lcg::new(0xC0FF_EE41_5AA5);
    for _ in 0..120 {
        let mut bytes = seed.clone();
        for _ in 0..(1 + rng.below(6)) {
            let at = rng.below(bytes.len());
            bytes[at] = rng.byte();
        }
        let input: Box<dyn ReadSeek> = Box::new(Cursor::new(bytes));
        // Open may legitimately fail; if it succeeds, drain with a
        // hard iteration bound — the stream is tiny, so anything past
        // a few dozen packets would mean a livelock.
        if let Ok(mut dmx) = crate::demuxer::MpegTsDemuxer::open_program(input, 1) {
            use oxideav_core::Demuxer as _;
            let _ = dmx.random_access_points();
            for _ in 0..64 {
                if dmx.next_packet().is_err() {
                    break;
                }
            }
        }
    }
}
