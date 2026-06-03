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

use crate::descriptor::{iter_descriptors, DescriptorIter};
use crate::TsError;

/// PAT table_id per §2.4.4.3.
pub const PAT_TABLE_ID: u8 = 0x00;
/// CAT table_id per §2.4.4.6 (Table 2-26).
pub const CAT_TABLE_ID: u8 = 0x01;
/// PMT table_id per §2.4.4.8.
pub const PMT_TABLE_ID: u8 = 0x02;

/// PID reserved for the Program Association Table per §2.4.4.3 / Table 2-3.
pub const PAT_PID: u16 = 0x0000;
/// PID reserved for the Conditional Access Table per §2.4.4.6 / Table 2-3.
pub const CAT_PID: u16 = 0x0001;

/// Header bytes common to every long-form PSI section (table_id +
/// section_length field through last_section_number).
const SECTION_HEADER_LEN: usize = 8;
/// Length of the CRC-32 trailer.
const SECTION_CRC_LEN: usize = 4;
/// Upper bound on a single PSI section per §2.4.4: 3 header bytes
/// (table_id + section_length wrappers) plus `section_length` ≤ 0x3FD
/// (1021). For private sections this rises to 4096 — kept conservative
/// here since the assembler is sized for ITU-T-defined PSI tables.
pub const MAX_PSI_SECTION_LEN: usize = 3 + 0x3FD;

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

impl PmtStream {
    /// Iterate per-elementary-stream descriptors as typed TLV records.
    /// See [`crate::descriptor::iter_descriptors`].
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
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
    /// Iterate the program-wide descriptors carried in `program_info`
    /// as typed TLV records. See
    /// [`crate::descriptor::iter_descriptors`].
    pub fn iter_program_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.program_info)
    }

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

/// Parsed Conditional Access Table per §2.4.4.6 / Table 2-27.
///
/// The CAT carries the program-wide CA descriptor block — one or more
/// CA_descriptors (§2.6.16) keyed by `CA_system_ID` that point at the
/// EMM PIDs. The CAT is signalled on the fixed PID `CAT_PID` and uses
/// `table_id == CAT_TABLE_ID`. Like PAT and PMT it may be segmented
/// across multiple sections, all of which share `table_id_extension`
/// (reserved; not used to identify a CAT).
#[derive(Debug, Default, Clone)]
pub struct ConditionalAccessTable {
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// `section_number`.
    pub section_number: u8,
    /// `last_section_number`.
    pub last_section_number: u8,
    /// Raw bytes of the descriptor() loop carried in the CAT body —
    /// walk with [`Self::iter_descriptors`] to get typed CA entries.
    pub descriptors: Vec<u8>,
}

impl ConditionalAccessTable {
    /// Parse a single CAT section. The slice must run from `table_id`
    /// through the CRC trailer (i.e. the pointer_field has already
    /// been skipped).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_section_header(section, CAT_TABLE_ID)?;
        Ok(Self {
            version_number: hdr.version_number,
            current_next_indicator: hdr.current_next_indicator,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            descriptors: body.to_vec(),
        })
    }

    /// Walk the carried descriptor() loop as typed TLV records.
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
}

/// Per-PID PSI section reassembler — joins TS payloads carrying the
/// same `table_id` across multiple 188-byte TS packets per §2.4.4.
///
/// Real PMTs that carry many ES_descriptors (e.g. an HEVC + multi-
/// language audio + multi-language PGS Blu-ray title) routinely run
/// past one TS packet's ~184-byte payload budget. The spec carries
/// the overflow into the next same-PID packet whose
/// `payload_unit_start_indicator == 0`; the assembler concatenates
/// those continuation payloads onto the in-flight section until
/// `3 + section_length` bytes have been collected, then yields the
/// completed section as a borrow over the internal buffer.
///
/// Wire rules enforced (§2.4.4 / §2.4.4.1):
///
/// * A PUSI=1 TS payload starts with a `pointer_field`. The bytes
///   from the byte immediately following `pointer_field` for
///   `pointer_field` bytes complete the previous in-flight section,
///   then the next section begins. A `pointer_field == 0` means the
///   first section starts immediately after the pointer.
/// * A PUSI=0 TS payload contains continuation bytes for the section
///   in flight at the end of the previous same-PID packet.
/// * `0xFF` table_id terminates section iteration inside a single TS
///   payload (stuffing bytes after a section).
/// * The 4-bit `continuity_counter` advances by +1 (mod 16) between
///   payload-carrying same-PID packets. A skipped count (per
///   §2.4.3.3) discards the in-flight buffer rather than blindly
///   concatenating misordered bytes — the next PUSI=1 packet rebuilds
///   from scratch.
///
/// The assembler is `table_id`-agnostic — it yields raw section bytes
/// and leaves CRC verification + table parsing to the caller (the
/// `Parse::parse` methods on [`ProgramAssociationTable`],
/// [`ProgramMapTable`], and [`ConditionalAccessTable`] each verify
/// CRC-32/MPEG-2 themselves). Sections that exceed
/// [`MAX_PSI_SECTION_LEN`] are dropped with [`TsError::SectionLengthOverrun`].
#[derive(Debug, Default)]
pub struct PsiSectionAssembler {
    /// Bytes of the section being assembled, including the 3-byte
    /// length-bearing header (table_id + 12-bit section_length).
    in_flight: Vec<u8>,
    /// Total length of `in_flight` once complete (= 3 + section_length).
    /// `None` until the first 3 bytes have been collected.
    target_len: Option<usize>,
    /// Last `continuity_counter` observed for the assembler's PID.
    /// `None` until the first TS packet has been fed. Used to detect a
    /// CC skip that invalidates the in-flight buffer.
    last_cc: Option<u8>,
}

impl PsiSectionAssembler {
    /// Create an empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop any in-flight section bytes — used when the caller knows
    /// the underlying PID just signalled a `discontinuity_indicator`
    /// (§2.4.3.5) or the input stream restarted.
    pub fn reset(&mut self) {
        self.in_flight.clear();
        self.target_len = None;
        self.last_cc = None;
    }

    /// Feed one TS-packet payload to the assembler.
    ///
    /// * `payload` is the TS packet's payload bytes (after the
    ///   adaptation field has been stripped) — the same byte slice
    ///   `iter_sections` would consume on a single-payload section.
    /// * `pusi` is the value of the TS packet's
    ///   `payload_unit_start_indicator`.
    /// * `continuity_counter` is the 4-bit field from the TS packet's
    ///   byte-3 low nibble — used to detect a dropped same-PID packet
    ///   that would corrupt the in-flight section if blindly
    ///   concatenated.
    ///
    /// Returns every complete section gathered by this call (a single
    /// payload can carry many short sections, or finish off one
    /// section and start another). Each yielded `Vec<u8>` runs from
    /// `table_id` through the CRC trailer — exactly what
    /// [`ProgramAssociationTable::parse`] /
    /// [`ProgramMapTable::parse`] / [`ConditionalAccessTable::parse`]
    /// expect.
    pub fn feed(
        &mut self,
        payload: &[u8],
        pusi: bool,
        continuity_counter: u8,
    ) -> Result<Vec<Vec<u8>>, TsError> {
        // CC continuity check — the 4-bit field wraps mod 16. A skip
        // means we missed a same-PID payload; the in-flight section
        // is no longer trustable, so drop it and resume on the next
        // PUSI=1 packet.
        let cc = continuity_counter & 0x0F;
        if let Some(prev) = self.last_cc {
            let expected = (prev + 1) & 0x0F;
            if cc != expected {
                // CC skip — discard buffer.
                self.in_flight.clear();
                self.target_len = None;
            }
        }
        self.last_cc = Some(cc);

        let mut out = Vec::new();
        let mut rest: &[u8] = payload;

        if pusi {
            // pointer_field = first byte of the payload (§2.4.4.1).
            if rest.is_empty() {
                return Ok(out);
            }
            let ptr = rest[0] as usize;
            rest = &rest[1..];
            if ptr > rest.len() {
                // Pointer overruns the payload — corrupt header, drop
                // whatever was in flight and stop.
                self.in_flight.clear();
                self.target_len = None;
                return Ok(out);
            }
            let (tail_of_prev, after_ptr) = rest.split_at(ptr);
            // `tail_of_prev` finishes the previous in-flight section
            // (when there was one). It may be padded with 0xFF
            // stuffing if no continuation was due — both cases share
            // the same "extend then check completion" path.
            if !self.in_flight.is_empty() || self.target_len.is_some() {
                if let Some(section) = self.extend_in_flight(tail_of_prev)? {
                    out.push(section);
                }
                // If the in-flight section isn't done after consuming
                // `tail_of_prev`, drop it: a PUSI=1 packet promises a
                // fresh section is about to begin, so the previous
                // section can't be straddled further into this
                // packet.
                self.in_flight.clear();
                self.target_len = None;
            }
            rest = after_ptr;
        } else if self.target_len.is_none() {
            // PUSI=0 with nothing in flight — payload bytes belong to
            // a section that started before we attached. Skip.
            return Ok(out);
        } else {
            // PUSI=0 continuation — every payload byte feeds the
            // in-flight section.
            if let Some(section) = self.extend_in_flight(rest)? {
                out.push(section);
            }
            return Ok(out);
        }

        // After pointer_field handling, `rest` points at one-or-more
        // freshly-starting sections. Each begins with a 3-byte
        // length-bearing header; 0xFF is a stuffing terminator.
        while !rest.is_empty() {
            if rest[0] == 0xFF {
                // Stuffing — rest of payload is filler.
                break;
            }
            if rest.len() < 3 {
                // Header straddles into the next TS packet — buffer
                // what we have and wait for the continuation.
                self.in_flight.extend_from_slice(rest);
                self.target_len = None;
                break;
            }
            let section_length =
                ((((rest[1] & 0b0000_1111) as usize) << 8) | (rest[2] as usize)) & 0x0FFF;
            let total = 3 + section_length;
            if total > MAX_PSI_SECTION_LEN {
                self.in_flight.clear();
                self.target_len = None;
                return Err(TsError::SectionLengthOverrun {
                    claimed: section_length,
                    have: rest.len() - 3,
                });
            }
            if rest.len() >= total {
                // Section fits entirely within this payload — emit
                // and advance.
                out.push(rest[..total].to_vec());
                rest = &rest[total..];
            } else {
                // Section straddles into next TS packet — buffer.
                self.in_flight.clear();
                self.in_flight.extend_from_slice(rest);
                self.target_len = Some(total);
                break;
            }
        }

        Ok(out)
    }

    /// Extend the in-flight section with `bytes`. If the section
    /// completes, return it (and clear the buffer). Returns `Ok(None)`
    /// when more bytes are still needed.
    fn extend_in_flight(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, TsError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        // If we don't yet have a target_len, we're still gathering the
        // 3-byte length-bearing header.
        if self.target_len.is_none() {
            let want = 3usize.saturating_sub(self.in_flight.len());
            let take = want.min(bytes.len());
            self.in_flight.extend_from_slice(&bytes[..take]);
            if self.in_flight.len() < 3 {
                return Ok(None);
            }
            let section_length = ((((self.in_flight[1] & 0b0000_1111) as usize) << 8)
                | (self.in_flight[2] as usize))
                & 0x0FFF;
            let total = 3 + section_length;
            if total > MAX_PSI_SECTION_LEN {
                self.in_flight.clear();
                self.target_len = None;
                return Err(TsError::SectionLengthOverrun {
                    claimed: section_length,
                    have: bytes.len() - take,
                });
            }
            self.target_len = Some(total);
            // Recurse on the remainder past the header bytes.
            return self.extend_in_flight(&bytes[take..]);
        }
        let target = self.target_len.expect("checked above");
        let want = target.saturating_sub(self.in_flight.len());
        let take = want.min(bytes.len());
        self.in_flight.extend_from_slice(&bytes[..take]);
        if self.in_flight.len() < target {
            return Ok(None);
        }
        // Section complete.
        let done = std::mem::take(&mut self.in_flight);
        self.target_len = None;
        Ok(Some(done))
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
    fn pmt_per_stream_descriptors_decode_iso639() {
        // ES descriptor block: an ISO-639 language descriptor with two
        // entries — eng/0, jpn/2.
        let es_descr: &[u8] = &[0x0A, 0x08, b'e', b'n', b'g', 0x00, b'j', b'p', b'n', 0x02];
        let section = build_pmt_section(1, 0, 0x100, &[], &[(0x81, 0x1100, es_descr)]);
        let pmt = ProgramMapTable::parse(&section).unwrap();
        assert_eq!(pmt.streams.len(), 1);
        let descriptors: Vec<_> = pmt.streams[0]
            .iter_descriptors()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].tag, 0x0A);
        match &descriptors[0].body {
            crate::descriptor::DescriptorBody::Iso639Language(langs) => {
                assert_eq!(langs.len(), 2);
                assert_eq!(&langs[0].language, b"eng");
                assert_eq!(&langs[1].language, b"jpn");
                assert_eq!(langs[1].audio_type, 2);
            }
            other => panic!("expected Iso639Language, got {other:?}"),
        }
    }

    #[test]
    fn pmt_program_info_descriptors_decode_registration() {
        // program_info: registration descriptor with format_identifier=HDMV.
        let program_info: &[u8] = &[0x05, 0x04, b'H', b'D', b'M', b'V'];
        let section = build_pmt_section(1, 0, 0x100, program_info, &[(0x1B, 0x1011, &[])]);
        let pmt = ProgramMapTable::parse(&section).unwrap();
        let descriptors: Vec<_> = pmt
            .iter_program_descriptors()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(descriptors.len(), 1);
        match &descriptors[0].body {
            crate::descriptor::DescriptorBody::Registration {
                format_identifier, ..
            } => {
                assert_eq!(format_identifier, b"HDMV");
            }
            other => panic!("expected Registration, got {other:?}"),
        }
    }

    #[test]
    fn pat_network_pid_program_zero() {
        let section = build_pat_section(2, 0, &[(0, 0x10), (1, 0x100)]);
        let pat = ProgramAssociationTable::parse(&section).unwrap();
        assert_eq!(pat.programs[0], (0, 0x10));
        assert_eq!(pat.programs[1], (1, 0x100));
    }

    /// Build a CAT section carrying `descriptors` as its body.
    /// Section bytes run from table_id through CRC.
    fn build_cat_section(version: u8, descriptors: &[u8]) -> Vec<u8> {
        let section_length = 5 + descriptors.len() + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(CAT_TABLE_ID);
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        // reserved (18 bits high padding) -> for CAT, table_id_extension
        // is the 16 reserved bits of bytes 3..5 — encode as 0xFFFF.
        s.push(0xFF);
        s.push(0xFF);
        // reserved | version | current_next.
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(0);
        s.push(0);
        s.extend_from_slice(descriptors);
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    #[test]
    fn cat_round_trip_single_ca_descriptor() {
        // CA_descriptor (tag 0x09): CA_system_ID=0x0500, CA_PID=0x0123,
        // private_data=0xCA 0xFE.
        let ca_descr: &[u8] = &[0x09, 0x06, 0x05, 0x00, 0xE1, 0x23, 0xCA, 0xFE];
        let section = build_cat_section(3, ca_descr);
        let cat = ConditionalAccessTable::parse(&section).unwrap();
        assert_eq!(cat.version_number, 3);
        assert!(cat.current_next_indicator);
        let descrs: Vec<_> = cat.iter_descriptors().collect::<Result<_, _>>().unwrap();
        assert_eq!(descrs.len(), 1);
        match &descrs[0].body {
            crate::descriptor::DescriptorBody::Ca(ca) => {
                assert_eq!(ca.ca_system_id, 0x0500);
                assert_eq!(ca.ca_pid, 0x0123);
                assert_eq!(ca.private_data, &[0xCA, 0xFE]);
            }
            other => panic!("expected CA, got {other:?}"),
        }
    }

    #[test]
    fn cat_rejects_wrong_table_id() {
        // Build a PAT-shaped section and parse it as CAT — table_id
        // mismatch must surface as an error.
        let section = build_pat_section(1, 0, &[(1, 0x100)]);
        let err = ConditionalAccessTable::parse(&section).unwrap_err();
        match err {
            TsError::Unsupported(_) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// Build a synthetic TS packet carrying `payload` with the given
    /// PUSI bit and continuity counter. Used to drive
    /// `PsiSectionAssembler` without going through the full
    /// `TsPacket::parse` path.
    fn fake_ts_payload(payload: &[u8], _pusi: bool, _cc: u8) -> Vec<u8> {
        // The assembler receives the already-extracted TS payload,
        // not the wire bytes — so this helper just hands back the
        // payload as-is. Kept for symmetry with the test layout.
        payload.to_vec()
    }

    #[test]
    fn assembler_single_packet_section() {
        // A short PAT fits in one TS payload — the assembler must
        // emit it on a single feed() call.
        let section = build_pat_section(7, 0, &[(1, 0x100)]);
        let mut payload = vec![0u8]; // pointer_field = 0
        payload.extend_from_slice(&section);
        // Pad with stuffing so the payload looks like a real 184-byte
        // TS data area.
        payload.resize(184, 0xFF);
        let mut asm = PsiSectionAssembler::new();
        let out = asm
            .feed(&fake_ts_payload(&payload, true, 0), true, 0)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], section);
        let pat = ProgramAssociationTable::parse(&out[0]).unwrap();
        assert_eq!(pat.programs, vec![(1, 0x100)]);
    }

    #[test]
    fn assembler_section_spans_two_ts_packets() {
        // Build a PMT large enough to overflow one TS payload — use
        // many ES_descriptors per stream entry to inflate ES_info.
        let stuff_descr = vec![0u8; 100]; // raw 100-byte descriptor blob
        let mut descr_block = vec![];
        descr_block.push(0xC0); // user-private tag → DescriptorBody::Raw
        descr_block.push(stuff_descr.len() as u8);
        descr_block.extend_from_slice(&stuff_descr);
        let section = build_pmt_section(
            1,
            0,
            0x100,
            &[],
            &[(0x1B, 0x1011, &descr_block), (0x81, 0x1100, &descr_block)],
        );
        assert!(
            section.len() > 184,
            "section ({} bytes) must exceed a single TS payload to exercise the assembler",
            section.len()
        );

        // First TS payload: pointer_field=0, then first 183 bytes of
        // section. The TS packet has a 184-byte payload (no
        // adaptation_field), pointer_field eats one byte, leaving 183
        // bytes of section.
        let mut p0 = vec![0u8]; // pointer_field
        p0.extend_from_slice(&section[..183]);
        // Second TS payload: continuation = rest of section, plus
        // stuffing to fill 184 bytes.
        let mut p1 = Vec::new();
        p1.extend_from_slice(&section[183..]);
        p1.resize(184, 0xFF);

        let mut asm = PsiSectionAssembler::new();
        let out0 = asm.feed(&p0, true, 5).unwrap();
        assert!(
            out0.is_empty(),
            "section straddles two TS packets — first feed must not yield"
        );
        let out1 = asm.feed(&p1, false, 6).unwrap();
        assert_eq!(out1.len(), 1, "second feed must complete the section");
        assert_eq!(out1[0], section);
        let pmt = ProgramMapTable::parse(&out1[0]).unwrap();
        assert_eq!(pmt.streams.len(), 2);
    }

    #[test]
    fn assembler_section_spans_three_ts_packets() {
        // Stuff a single PMT so it needs three TS payloads. Pad the
        // program_info area with two ~250-byte raw descriptor blobs;
        // each TLV uses an 8-bit length so the upper bound per blob
        // is 255 + 2 header bytes.
        let payload_chunk = vec![0xABu8; 250];
        let mut descr_block: Vec<u8> = Vec::new();
        for tag in [0xC0u8, 0xC1] {
            descr_block.push(tag);
            descr_block.push(payload_chunk.len() as u8);
            descr_block.extend_from_slice(&payload_chunk);
        }
        let section = build_pmt_section(1, 0, 0x100, &descr_block, &[(0x1B, 0x1011, &[])]);
        assert!(
            section.len() > 2 * 184,
            "need >2 TS payloads worth, got {} bytes",
            section.len()
        );

        // Slice into three chunks. First payload carries 183 section
        // bytes (after pointer_field=0); the next two carry up to 184
        // continuation bytes each.
        let mut p0 = vec![0u8];
        p0.extend_from_slice(&section[..183]);
        let p1 = section[183..183 + 184].to_vec();
        let mut p2 = section[183 + 184..].to_vec();
        p2.resize(184, 0xFF);

        let mut asm = PsiSectionAssembler::new();
        assert!(asm.feed(&p0, true, 0).unwrap().is_empty());
        assert!(asm.feed(&p1, false, 1).unwrap().is_empty());
        let out = asm.feed(&p2, false, 2).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], section);
    }

    #[test]
    fn assembler_cc_skip_discards_in_flight_section() {
        // Begin a section in packet A (CC=4), then jump to CC=8 in
        // packet B. The assembler must discard the in-flight bytes
        // rather than concatenate them blindly.
        let section = build_pat_section(1, 0, &[(1, 0x100), (2, 0x200), (3, 0x300)]);
        // Make sure the section doesn't fit in one payload, so the
        // CC skip actually matters.
        let mut padded = Vec::new();
        for _ in 0..200 {
            padded.extend_from_slice(&section);
        }
        let big_section = build_pmt_section(
            1,
            0,
            0x100,
            &[0u8; 200],
            &[(0x1B, 0x1011, &[]), (0x81, 0x1100, &[])],
        );
        let mut p0 = vec![0u8];
        p0.extend_from_slice(&big_section[..183]);

        let mut asm = PsiSectionAssembler::new();
        assert!(asm.feed(&p0, true, 0).unwrap().is_empty());
        // Skip CC from 0 → 2 (expected was 1). Assembler drops the
        // in-flight buffer.
        let p1 = vec![0xFFu8; 184];
        let out = asm.feed(&p1, false, 2).unwrap();
        assert!(out.is_empty());
        // Confirm the buffer was actually dropped: feeding the rest
        // of `big_section` as a continuation now produces no section.
        let mut p2 = big_section[183..].to_vec();
        p2.resize(184, 0xFF);
        let out2 = asm.feed(&p2, false, 3).unwrap();
        assert!(out2.is_empty(), "CC-skip must have dropped in-flight bytes");

        let _ = padded;
    }

    #[test]
    fn assembler_stuffing_terminates_payload() {
        // A single short section followed by stuffing — assembler
        // must yield the section and stop at the first 0xFF.
        let section = build_pat_section(9, 0, &[(1, 0x100)]);
        let mut payload = vec![0u8]; // pointer_field
        payload.extend_from_slice(&section);
        payload.extend_from_slice(&[0xFFu8; 64]);
        let mut asm = PsiSectionAssembler::new();
        let out = asm.feed(&payload, true, 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], section);
    }

    #[test]
    fn assembler_two_sections_same_payload() {
        // Two short PAT sections packed back-to-back in one PUSI
        // payload — pointer_field=0 puts the first section
        // immediately after the pointer.
        let s0 = build_pat_section(1, 0, &[(1, 0x100)]);
        let s1 = build_pat_section(2, 0, &[(2, 0x200)]);
        let mut payload = vec![0u8];
        payload.extend_from_slice(&s0);
        payload.extend_from_slice(&s1);
        payload.resize(184, 0xFF);
        let mut asm = PsiSectionAssembler::new();
        let out = asm.feed(&payload, true, 0).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], s0);
        assert_eq!(out[1], s1);
    }

    #[test]
    fn assembler_pointer_field_finishes_prev_section() {
        // First TS payload starts a section that runs past the
        // 184-byte data area. Second TS payload has PUSI=1 with
        // pointer_field = N where N is the remaining bytes of the
        // previous section; after those N bytes, a new section
        // begins.
        //
        // s0 must overflow one TS payload — build it with a stuffed
        // PMT body. s1 is the trailing short section.
        let big_descr = vec![0u8; 200];
        let s0 = build_pmt_section(1, 0, 0x100, &big_descr, &[(0x1B, 0x1011, &[])]);
        let s1 = build_pat_section(7, 0, &[(3, 0x300)]);
        assert!(s0.len() > 184, "s0 must straddle a TS packet boundary");
        let mut p0 = vec![0u8]; // pointer_field = 0
        p0.extend_from_slice(&s0[..183]);
        // p1: pointer_field = remaining s0 bytes, then s1.
        let remaining = s0.len() - 183;
        let mut p1 = vec![remaining as u8];
        p1.extend_from_slice(&s0[183..]);
        p1.extend_from_slice(&s1);
        p1.resize(184, 0xFF);

        let mut asm = PsiSectionAssembler::new();
        let out0 = asm.feed(&p0, true, 0).unwrap();
        assert!(out0.is_empty());
        let out1 = asm.feed(&p1, true, 1).unwrap();
        assert_eq!(out1.len(), 2);
        assert_eq!(out1[0], s0);
        assert_eq!(out1[1], s1);
    }

    #[test]
    fn assembler_reset_drops_buffer() {
        let section = build_pmt_section(1, 0, 0x100, &[0u8; 200], &[(0x1B, 0x1011, &[])]);
        let mut p0 = vec![0u8];
        p0.extend_from_slice(&section[..183]);
        let mut asm = PsiSectionAssembler::new();
        assert!(asm.feed(&p0, true, 0).unwrap().is_empty());
        asm.reset();
        // Feeding the continuation now does nothing — the buffer
        // was wiped.
        let mut p1 = section[183..].to_vec();
        p1.resize(184, 0xFF);
        let out = asm.feed(&p1, false, 1).unwrap();
        assert!(out.is_empty());
    }
}
