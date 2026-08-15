#![no_main]

//! Hostile bytes straight into the standalone unit parsers — no TS
//! packet framing required, so the fuzzer reaches deep section /
//! descriptor / PES states without first assembling a valid packet
//! grid.
//!
//! Hostile legs (panic-free contract):
//!   * every PSI / DVB SI table parser on the raw bytes as a section
//!     (PAT / PMT / CAT / TSDT / SDT / BAT / NIT / EIT / RST / TDT /
//!     TOT / ST / DIT / SIT), with every descriptor loop walked;
//!   * the flat descriptor walk (§2.6 + EN 300 468 §6 TLVs);
//!   * `PesPacket::parse` (Table 2-17 optional-header ladder);
//!   * `TsPacket::parse` on the first 188 bytes (§2.4.3.4 adaptation
//!     field);
//!   * the section assembler fed PUSI/continuation chunks derived
//!     from the input;
//!   * `decode_utc_time` (EN 300 468 annex C MJD + BCD).
//!
//! Encode∘parse fixed-point legs (identity contract): recipe-driven
//! `PesHeaderSpec` / `AdaptationFieldSpec` encodes must parse back to
//! the same wire fields, and recipe-driven PSI section builders must
//! parse cleanly through their table parsers.

use libfuzzer_sys::fuzz_target;

use oxideav_mpegts::packet::{AdaptationFieldSpec, TsPacket, TS_PACKET_LEN, TS_SYNC_BYTE};
use oxideav_mpegts::pes::{PesHeaderSpec, PesPacket};
use oxideav_mpegts::psi::*;
use oxideav_mpegts_fuzz::Recipe;

fn parse_all_tables(data: &[u8]) {
    macro_rules! walk {
        ($d:expr) => {
            for d in $d {
                let _ = d;
            }
        };
    }
    if let Ok(pat) = ProgramAssociationTable::parse(data) {
        let _ = pat.programs.len();
    }
    if let Ok(pmt) = ProgramMapTable::parse(data) {
        walk!(pmt.iter_program_descriptors());
        for s in &pmt.streams {
            walk!(s.iter_descriptors());
        }
    }
    if let Ok(cat) = ConditionalAccessTable::parse(data) {
        walk!(cat.iter_descriptors());
    }
    if let Ok(tsdt) = TransportStreamDescriptionTable::parse(data) {
        walk!(tsdt.iter_descriptors());
    }
    if let Ok(sdt) = ServiceDescriptionTable::parse(data) {
        for s in &sdt.services {
            walk!(s.iter_descriptors());
        }
    }
    if let Ok(bat) = BouquetAssociationTable::parse(data) {
        walk!(bat.iter_descriptors());
        for ts in &bat.transport_streams {
            walk!(ts.iter_descriptors());
        }
    }
    if let Ok(nit) = NetworkInformationTable::parse(data) {
        walk!(nit.iter_descriptors());
        for ts in &nit.transport_streams {
            walk!(ts.iter_descriptors());
        }
    }
    if let Ok(eit) = EventInformationTable::parse(data) {
        for ev in &eit.events {
            let _ = ev.duration.as_seconds();
            walk!(ev.iter_descriptors());
        }
    }
    let _ = RunningStatusTable::parse(data);
    let _ = TimeDateTable::parse(data);
    if let Ok(tot) = TimeOffsetTable::parse(data) {
        walk!(tot.iter_descriptors());
    }
    let _ = StuffingTable::parse(data);
    let _ = DiscontinuityInformationTable::parse(data);
    if let Ok(sit) = SelectionInformationTable::parse(data) {
        walk!(sit.iter_descriptors());
        for s in &sit.services {
            walk!(s.iter_descriptors());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // --- Hostile legs -----------------------------------------------------
    parse_all_tables(data);
    for d in oxideav_mpegts::iter_descriptors(data) {
        let _ = d;
    }
    let _ = oxideav_mpegts::parse_descriptors(data);
    if let Ok(pes) = PesPacket::parse(data) {
        let _ = pes.trick_mode();
    }
    if data.len() >= TS_PACKET_LEN {
        let _ = TsPacket::parse(&data[..TS_PACKET_LEN]);
    }
    if data.len() >= 5 {
        let _ = decode_utc_time([data[0], data[1], data[2], data[3], data[4]]);
    }
    // Section assembler: PUSI head + continuation chunks cut from the
    // input at recipe-driven boundaries.
    {
        let mut r = Recipe::new(data);
        let mut asm = PsiSectionAssembler::new();
        let mut rest = data;
        let mut cc = 0u8;
        for _ in 0..8 {
            if rest.is_empty() {
                break;
            }
            let take = 1 + (r.u8() as usize) % rest.len().min(184);
            let (chunk, tail) = rest.split_at(take);
            let pusi = r.chance(128);
            if let Ok(sections) = asm.feed(chunk, pusi, cc) {
                for s in &sections {
                    parse_all_tables(s);
                }
            }
            cc = (cc + 1) & 0x0F;
            rest = tail;
        }
    }

    // --- Encode∘parse fixed points ---------------------------------------
    let mut r = Recipe::new(data);

    // PES header spec → encode → parse: timestamps and stream_id must
    // survive the wire (§2.4.3.7 PTS/DTS coding, §2.7.5 ordering).
    {
        let stream_id = [0xE0u8, 0xC0, 0xBD, 0xFA][(r.u8() as usize) % 4];
        let pts = r.u64() & 0x1_FFFF_FFFF;
        let dts = r
            .chance(128)
            .then(|| pts.saturating_sub(1 + u64::from(r.u16())) & 0x1_FFFF_FFFF)
            .filter(|&d| d < pts);
        let body_len = (r.u8() % 32) as usize;
        let spec = PesHeaderSpec::with_timestamps(stream_id, pts, dts);
        if let Ok(bytes) = spec.encode(&vec![0x5A; body_len]) {
            let pes = PesPacket::parse(&bytes).expect("own PES encode must parse");
            assert_eq!(pes.stream_id, stream_id);
            assert_eq!(pes.pts_90k, Some(pts));
            assert_eq!(pes.dts_90k, dts);
            assert_eq!(pes.payload.len(), body_len);
        }
    }

    // Adaptation-field spec → encode → parse via a synthetic packet:
    // §2.4.3.4 Table 2-6 field set + §2.4.3.5 pairings.
    {
        let spec = AdaptationFieldSpec {
            discontinuity_indicator: r.chance(64),
            random_access_indicator: r.chance(128),
            pcr: r
                .chance(160)
                .then(|| (r.u64() & 0x1_FFFF_FFFF, r.u16() % 300)),
            splice_countdown: r.chance(64).then(|| r.u8() as i8),
            ..Default::default()
        };
        if let Ok(af) = spec.encode(Some(1 + (r.u8() as usize) % (TS_PACKET_LEN - 5))) {
            let mut pkt = vec![0u8; TS_PACKET_LEN];
            pkt[0] = TS_SYNC_BYTE;
            pkt[1] = 0x01; // PID 0x0001, no PUSI
            pkt[2] = 0x01;
            pkt[3] = if af.len() < TS_PACKET_LEN - 4 {
                0b0011_0000 // adaptation + payload
            } else {
                0b0010_0000 // adaptation only
            };
            pkt[4..4 + af.len()].copy_from_slice(&af);
            let parsed = TsPacket::parse(&pkt).expect("own AF encode must parse");
            let paf = parsed.adaptation_field.expect("AF present");
            assert_eq!(paf.discontinuity_indicator, spec.discontinuity_indicator);
            assert_eq!(paf.random_access_indicator, spec.random_access_indicator);
            assert_eq!(paf.pcr_base, spec.pcr.map(|(b, _)| b));
            assert_eq!(paf.pcr_extension, spec.pcr.map(|(_, e)| e));
            assert_eq!(paf.splice_countdown, spec.splice_countdown);
        }
    }

    // PSI builders → parse: PAT and PMT with recipe-driven loops must
    // come back through their parsers (CRC-32 + section framing).
    {
        let n = (r.u8() % 8) as usize;
        let entries: Vec<(u16, u16)> = (0..n)
            .map(|_| (r.u16(), 0x0020 + r.u16() % 0x1FC0))
            .collect();
        let tsid = r.u16();
        let version = r.u8() % 32;
        let section = oxideav_mpegts::build_pat(tsid, version, &entries);
        let pat = ProgramAssociationTable::parse(&section).expect("own PAT must parse");
        assert_eq!(pat.programs.len(), n);

        let n_streams = (r.u8() % 6) as usize;
        let streams: Vec<oxideav_mpegts::PmtStreamEntry> = (0..n_streams)
            .map(|k| oxideav_mpegts::PmtStreamEntry {
                stream_type: r.u8(),
                elementary_pid: 0x0100 + k as u16,
                es_info: vec![0x52, 1, r.u8()], // stream_identifier
            })
            .collect();
        let pcr_pid = 0x0100;
        let section =
            oxideav_mpegts::build_pmt(1 + r.u16() % 0xFFFE, version, pcr_pid, &[], &streams);
        let pmt = ProgramMapTable::parse(&section).expect("own PMT must parse");
        assert_eq!(pmt.streams.len(), n_streams);
    }
});
