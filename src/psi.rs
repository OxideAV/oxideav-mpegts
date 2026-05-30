//! Program-Specific Information tables — PAT + PMT.
//!
//! Wire layout (ISO/IEC 13818-1 §2.4.4):
//!
//! When carried in a TS packet whose `payload_unit_start_indicator`
//! is set, the payload begins with a one-byte `pointer_field` that
//! gives the offset (from the byte that follows it) to the start of
//! the first section. Subsequent TS packets with the same PID and
//! `payload_unit_start_indicator == 0` carry continuation bytes for
//! the same section.
//!
//! A PSI section's common header (§2.4.4.10):
//!
//! ```text
//! table_id (8)
//! section_syntax_indicator (1) | '0' (1) | reserved (2) | section_length (12)
//! table_id_extension (16)
//! reserved (2) | version_number (5) | current_next_indicator (1)
//! section_number (8)
//! last_section_number (8)
//! ... body ...
//! CRC_32 (32, MPEG-2 left-shifting, init 0xFFFFFFFF, no reflect, no final XOR)
//! ```
//!
//! `section_length` counts the bytes AFTER the section_length field
//! itself, INCLUDING the CRC trailer.

use crate::TsError;

/// PAT table_id per §2.4.4.3.
pub const PAT_TABLE_ID: u8 = 0x00;
/// PMT table_id per §2.4.4.8.
pub const PMT_TABLE_ID: u8 = 0x02;

/// Header bytes common to every long-form PSI section (table_id +
/// section_length field through last_section_number).
const SECTION_HEADER_LEN: usize = 8;
/// Length of the CRC-32 trailer.
const SECTION_CRC_LEN: usize = 4;

/// Parsed Program Association Table.
#[derive(Debug, Default, Clone)]
pub struct ProgramAssociationTable {
    /// `transport_stream_id` carried in `table_id_extension`.
    pub transport_stream_id: u16,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// `section_number`.
    pub section_number: u8,
    /// `last_section_number`.
    pub last_section_number: u8,
    /// `(program_number, pmt_pid)` pairs.
    ///
    /// `program_number == 0` denotes the network PID; otherwise the
    /// PID is the PMT for that program.
    pub programs: Vec<(u16, u16)>,
}

impl ProgramAssociationTable {
    /// Parse a single PAT section. The slice must run from
    /// `table_id` through the CRC trailer (i.e. the pointer_field has
    /// already been skipped and the section has been extracted from
    /// the TS payload).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_section_header(section, PAT_TABLE_ID)?;
        let mut programs = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let program_number = u16::from_be_bytes([body[i], body[i + 1]]);
            let pid = ((((body[i + 2] & 0b0001_1111) as u16) << 8) | (body[i + 3] as u16)) & 0x1FFF;
            programs.push((program_number, pid));
            i += 4;
        }
        Ok(Self {
            transport_stream_id: hdr.table_id_extension,
            version_number: hdr.version_number,
            current_next_indicator: hdr.current_next_indicator,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            programs,
        })
    }
}

/// One elementary-stream descriptor inside a PMT.
#[derive(Debug, Clone)]
pub struct PmtStream {
    /// Per ISO/IEC 13818-1 Table 2-29 (`stream_type`).
    pub stream_type: u8,
    /// 13-bit elementary-stream PID.
    pub elementary_pid: u16,
    /// Raw descriptor bytes — the contents of the
    /// `ES_info_length`-bytes block, copied verbatim.
    pub descriptors: Vec<u8>,
}

/// Parsed Program Map Table for one program.
#[derive(Debug, Default, Clone)]
pub struct ProgramMapTable {
    /// Program number this PMT serves (from `table_id_extension`).
    pub program_number: u16,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// PID carrying the program's PCR (13 bits).
    pub pcr_pid: u16,
    /// Raw `program_info` descriptor bytes (length given by
    /// `program_info_length`).
    pub program_info: Vec<u8>,
    /// Per-stream descriptors keyed by `elementary_pid`.
    pub streams: Vec<PmtStream>,
}

impl ProgramMapTable {
    /// Parse a single PMT section. The slice must run from
    /// `table_id` through the CRC trailer.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_section_header(section, PMT_TABLE_ID)?;
        if body.len() < 4 {
            return Err(TsError::Truncated {
                what: "PMT body",
                have: body.len(),
                need: 4,
            });
        }
        let pcr_pid = u16::from_be_bytes([body[0] & 0b0001_1111, body[1]]);
        let program_info_length = (u16::from_be_bytes([body[2] & 0b0000_1111, body[3]])) as usize;
        let after_pcr: usize = 4;
        let pi_end =
            after_pcr
                .checked_add(program_info_length)
                .ok_or(TsError::SectionLengthOverrun {
                    claimed: program_info_length,
                    have: body.len() - after_pcr,
                })?;
        if pi_end > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: program_info_length,
                have: body.len() - after_pcr,
            });
        }
        let program_info = body[after_pcr..pi_end].to_vec();

        let mut streams = Vec::new();
        let mut i = pi_end;
        while i + 5 <= body.len() {
            let stream_type = body[i];
            let elementary_pid = u16::from_be_bytes([body[i + 1] & 0b0001_1111, body[i + 2]]);
            let es_info_length =
                (u16::from_be_bytes([body[i + 3] & 0b0000_1111, body[i + 4]])) as usize;
            let descr_start = i + 5;
            let descr_end =
                descr_start
                    .checked_add(es_info_length)
                    .ok_or(TsError::SectionLengthOverrun {
                        claimed: es_info_length,
                        have: body.len() - descr_start,
                    })?;
            if descr_end > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: es_info_length,
                    have: body.len() - descr_start,
                });
            }
            let descriptors = body[descr_start..descr_end].to_vec();
            streams.push(PmtStream {
                stream_type,
                elementary_pid,
                descriptors,
            });
            i = descr_end;
        }
        Ok(Self {
            program_number: hdr.table_id_extension,
            version_number: hdr.version_number,
            current_next_indicator: hdr.current_next_indicator,
            pcr_pid,
            program_info,
            streams,
        })
    }
}

/// Shared header parse — verifies sync, length, CRC.
struct SectionHeader {
    table_id_extension: u16,
    version_number: u8,
    current_next_indicator: bool,
    section_number: u8,
    last_section_number: u8,
}

fn parse_section_header(
    section: &[u8],
    expected_table_id: u8,
) -> Result<(SectionHeader, &[u8]), TsError> {
    if section.len() < SECTION_HEADER_LEN + SECTION_CRC_LEN {
        return Err(TsError::Truncated {
            what: "PSI section header",
            have: section.len(),
            need: SECTION_HEADER_LEN + SECTION_CRC_LEN,
        });
    }
    let table_id = section[0];
    if table_id != expected_table_id {
        return Err(TsError::Unsupported(
            "PSI table_id does not match expected value",
        ));
    }
    let b1 = section[1];
    let b2 = section[2];
    // section_length is 12 bits across the bottom 4 of b1 + b2.
    let section_length = ((((b1 & 0b0000_1111) as usize) << 8) | (b2 as usize)) & 0x0FFF;

    // section_length counts bytes after itself — i.e. from `section[3]`
    // through the CRC. So total section size = 3 + section_length.
    let total = 3 + section_length;
    if total > section.len() {
        return Err(TsError::SectionLengthOverrun {
            claimed: section_length,
            have: section.len() - 3,
        });
    }
    let section = &section[..total];

    // Verify the MPEG-2 CRC over [section_start .. section_end - 4].
    let crc_pos = total - SECTION_CRC_LEN;
    let computed = mpeg2_crc32(&section[..crc_pos]);
    let header_crc = u32::from_be_bytes([
        section[crc_pos],
        section[crc_pos + 1],
        section[crc_pos + 2],
        section[crc_pos + 3],
    ]);
    if computed != header_crc {
        return Err(TsError::PsiCrcMismatch {
            header: header_crc,
            computed,
        });
    }

    let table_id_extension = u16::from_be_bytes([section[3], section[4]]);
    let b5 = section[5];
    let version_number = (b5 >> 1) & 0b0001_1111;
    let current_next_indicator = (b5 & 0b0000_0001) != 0;
    let section_number = section[6];
    let last_section_number = section[7];

    let body = &section[SECTION_HEADER_LEN..crc_pos];
    Ok((
        SectionHeader {
            table_id_extension,
            version_number,
            current_next_indicator,
            section_number,
            last_section_number,
        },
        body,
    ))
}

/// MPEG-2 CRC-32 (poly 0x04C11DB7, init 0xFFFFFFFF, MSB-first, no
/// reflect, no final XOR).
pub fn mpeg2_crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if (crc & 0x8000_0000) != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Iterate the long-form PSI sections carried in one TS-packet payload.
///
/// `ts_payload` is the TS payload bytes (after AF stripping) of a TS
/// packet whose `payload_unit_start_indicator` was set. The first
/// byte is treated as the `pointer_field`. Each successive section is
/// located by reading its `section_length`. Stuffing bytes (`0xFF`
/// table_id) terminate iteration.
///
/// Each yielded slice runs from `table_id` through the CRC trailer.
pub fn iter_sections(ts_payload: &[u8]) -> SectionIter<'_> {
    if ts_payload.is_empty() {
        return SectionIter { rest: &[][..] };
    }
    let ptr = ts_payload[0] as usize;
    let start = 1 + ptr;
    if start > ts_payload.len() {
        return SectionIter { rest: &[][..] };
    }
    SectionIter {
        rest: &ts_payload[start..],
    }
}

/// Iterator returned by [`iter_sections`].
#[derive(Debug)]
pub struct SectionIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SectionIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Need at least the 3-byte length-bearing header.
        if self.rest.len() < 3 {
            return None;
        }
        // `0xFF` is the stuffing byte that fills out a section-bearing
        // TS payload.
        if self.rest[0] == 0xFF {
            return None;
        }
        let section_length =
            ((((self.rest[1] & 0b0000_1111) as usize) << 8) | (self.rest[2] as usize)) & 0x0FFF;
        let total = 3 + section_length;
        if total > self.rest.len() {
            return None;
        }
        let (head, tail) = self.rest.split_at(total);
        self.rest = tail;
        Some(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PAT section for a single (program_number, pmt_pid)
    /// pair. Section bytes run from table_id through CRC.
    fn build_pat_section(tsid: u16, version: u8, programs: &[(u16, u16)]) -> Vec<u8> {
        // Body = 4 bytes per program.
        // Section total after section_length = 5 (rest of header) + body + 4 (CRC).
        let body_len = programs.len() * 4;
        let section_length = 5 + body_len + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(PAT_TABLE_ID);
        // section_syntax_indicator=1, '0', reserved=0b11, then 12-bit
        // length.
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&tsid.to_be_bytes());
        // reserved=0b11, version (5), current_next=1.
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(0); // section_number
        s.push(0); // last_section_number
        for (prog, pid) in programs {
            s.extend_from_slice(&prog.to_be_bytes());
            // reserved=0b111, then 13-bit PID.
            s.push(0b1110_0000 | ((pid >> 8) & 0x1F) as u8);
            s.push((pid & 0xFF) as u8);
        }
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    fn build_pmt_section(
        program_number: u16,
        version: u8,
        pcr_pid: u16,
        program_info: &[u8],
        streams: &[(u8, u16, &[u8])],
    ) -> Vec<u8> {
        // Body = 4 bytes (pcr/program_info_length) + program_info + Σ(5+es_info).
        let body_len: usize =
            4 + program_info.len() + streams.iter().map(|(_, _, d)| 5 + d.len()).sum::<usize>();
        let section_length = 5 + body_len + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(PMT_TABLE_ID);
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&program_number.to_be_bytes());
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(0);
        s.push(0);
        // PCR_PID
        s.push(0b1110_0000 | ((pcr_pid >> 8) & 0x1F) as u8);
        s.push((pcr_pid & 0xFF) as u8);
        // program_info_length
        let pil = program_info.len() as u16;
        s.push(0b1111_0000 | ((pil >> 8) & 0x0F) as u8);
        s.push((pil & 0xFF) as u8);
        s.extend_from_slice(program_info);
        for (stype, epid, descr) in streams {
            s.push(*stype);
            s.push(0b1110_0000 | ((*epid >> 8) & 0x1F) as u8);
            s.push((*epid & 0xFF) as u8);
            let el = descr.len() as u16;
            s.push(0b1111_0000 | ((el >> 8) & 0x0F) as u8);
            s.push((el & 0xFF) as u8);
            s.extend_from_slice(descr);
        }
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    #[test]
    fn mpeg2_crc32_known_vector() {
        // CRC of the byte "1": MPEG-2 CRC of the ASCII string "1"
        // is 0xA6B15CD4 — easy to confirm with any spec-matching
        // implementation. We assert internal consistency via the
        // round-trip below; this anchors the polynomial wiring.
        let crc = mpeg2_crc32(b"123456789");
        // The classic check value for CRC-32/MPEG-2 over "123456789"
        // is 0x0376E6E7 (see CRC-Catalogue / Greg Cook).
        assert_eq!(crc, 0x0376_E6E7);
    }

    #[test]
    fn pat_one_program_round_trip() {
        let section = build_pat_section(1, 3, &[(1, 0x100)]);
        let pat = ProgramAssociationTable::parse(&section).unwrap();
        assert_eq!(pat.transport_stream_id, 1);
        assert_eq!(pat.version_number, 3);
        assert!(pat.current_next_indicator);
        assert_eq!(pat.programs, vec![(1, 0x100)]);
    }

    #[test]
    fn pmt_avc_ac3_pgs_round_trip() {
        // Stream descriptors: one AVC (0x1B), one AC-3 (0x81), one
        // PGS (0x90), each with a tiny descriptor blob to prove the
        // length/bytes survive.
        let avc_descr: &[u8] = &[0x52, 0x01, 0x00]; // dummy stream_identifier
        let ac3_descr: &[u8] = &[0x6A, 0x01, 0x80];
        let pgs_descr: &[u8] = &[];
        let section = build_pmt_section(
            1,
            5,
            0x100,
            &[],
            &[
                (0x1B, 0x1011, avc_descr),
                (0x81, 0x1100, ac3_descr),
                (0x90, 0x1200, pgs_descr),
            ],
        );
        let pmt = ProgramMapTable::parse(&section).unwrap();
        assert_eq!(pmt.program_number, 1);
        assert_eq!(pmt.version_number, 5);
        assert!(pmt.current_next_indicator);
        assert_eq!(pmt.pcr_pid, 0x100);
        assert!(pmt.program_info.is_empty());
        assert_eq!(pmt.streams.len(), 3);
        assert_eq!(pmt.streams[0].stream_type, 0x1B);
        assert_eq!(pmt.streams[0].elementary_pid, 0x1011);
        assert_eq!(pmt.streams[0].descriptors, avc_descr);
        assert_eq!(pmt.streams[1].stream_type, 0x81);
        assert_eq!(pmt.streams[1].elementary_pid, 0x1100);
        assert_eq!(pmt.streams[1].descriptors, ac3_descr);
        assert_eq!(pmt.streams[2].stream_type, 0x90);
        assert_eq!(pmt.streams[2].elementary_pid, 0x1200);
        assert!(pmt.streams[2].descriptors.is_empty());
    }

    #[test]
    fn psi_crc_corruption_is_rejected() {
        let mut section = build_pat_section(7, 0, &[(1, 0x100)]);
        // Flip a payload bit.
        section[3] ^= 0x01;
        let err = ProgramAssociationTable::parse(&section).unwrap_err();
        match err {
            TsError::PsiCrcMismatch { .. } => {}
            other => panic!("expected PsiCrcMismatch, got {other:?}"),
        }
    }

    #[test]
    fn iter_sections_skips_pointer_field_and_stuffing() {
        let section = build_pat_section(1, 0, &[(1, 0x100)]);
        // Simulate a TS payload: pointer_field=0, then the section,
        // then stuffing.
        let mut payload = Vec::new();
        payload.push(0u8); // pointer_field
        payload.extend_from_slice(&section);
        payload.extend(std::iter::repeat(0xFF).take(10));
        let mut it = iter_sections(&payload);
        let s = it.next().expect("section");
        assert_eq!(s, section);
        assert!(it.next().is_none());
    }

    #[test]
    fn iter_sections_with_nonzero_pointer_field() {
        let section = build_pat_section(1, 0, &[(1, 0x100)]);
        let mut payload = Vec::new();
        payload.push(3u8); // pointer_field = 3
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 stuffing-ish bytes
        payload.extend_from_slice(&section);
        let s = iter_sections(&payload).next().expect("section");
        assert_eq!(s, section);
    }

    #[test]
    fn pat_network_pid_program_zero() {
        let section = build_pat_section(2, 0, &[(0, 0x10), (1, 0x100)]);
        let pat = ProgramAssociationTable::parse(&section).unwrap();
        assert_eq!(pat.programs[0], (0, 0x10));
        assert_eq!(pat.programs[1], (1, 0x100));
    }
}
