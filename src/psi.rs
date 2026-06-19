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
/// TSDT (Transport Stream Description Table) table_id per §2.4.4.12 /
/// Table 2-26.
pub const TSDT_TABLE_ID: u8 = 0x03;
/// SDT (Service Description Table) `table_id` for sections describing the
/// **actual** Transport Stream — the one that carries the SDT (ETSI
/// EN 300 468 §5.2.3 / Table 2, `service_description_section`).
pub const SDT_ACTUAL_TABLE_ID: u8 = 0x42;
/// SDT `table_id` for sections describing **other** Transport Streams
/// (ETSI EN 300 468 §5.2.3 / Table 2).
pub const SDT_OTHER_TABLE_ID: u8 = 0x46;
/// EIT `table_id` for present/following events on the **actual** TS
/// (ETSI EN 300 468 §5.2.4 / Table 2 — `0x4E`).
pub const EIT_ACTUAL_PF_TABLE_ID: u8 = 0x4E;
/// EIT `table_id` for present/following events on **other** TSs
/// (ETSI EN 300 468 §5.2.4 / Table 2 — `0x4F`).
pub const EIT_OTHER_PF_TABLE_ID: u8 = 0x4F;
/// First `table_id` of the EIT **actual**-TS schedule range
/// (ETSI EN 300 468 §5.2.4 / Table 2 — `0x50`–`0x5F` inclusive).
pub const EIT_ACTUAL_SCHEDULE_FIRST: u8 = 0x50;
/// Last `table_id` of the EIT actual-TS schedule range (`0x5F`).
pub const EIT_ACTUAL_SCHEDULE_LAST: u8 = 0x5F;
/// First `table_id` of the EIT **other**-TS schedule range
/// (ETSI EN 300 468 §5.2.4 / Table 2 — `0x60`–`0x6F` inclusive).
pub const EIT_OTHER_SCHEDULE_FIRST: u8 = 0x60;
/// Last `table_id` of the EIT other-TS schedule range (`0x6F`).
pub const EIT_OTHER_SCHEDULE_LAST: u8 = 0x6F;
/// NIT (Network Information Table) `table_id` for sections describing the
/// **actual** network — the network the TS carrying the NIT belongs to
/// (ETSI EN 300 468 §5.2.1 / Table 2 — `0x40`).
pub const NIT_ACTUAL_TABLE_ID: u8 = 0x40;
/// NIT `table_id` for sections describing **other** networks (ETSI
/// EN 300 468 §5.2.1 / Table 2 — `0x41`).
pub const NIT_OTHER_TABLE_ID: u8 = 0x41;
/// TDT (Time and Date Table) `table_id` (ETSI EN 300 468 §5.2.5 /
/// Table 8 — `0x70`).
pub const TDT_TABLE_ID: u8 = 0x70;
/// TOT (Time Offset Table) `table_id` (ETSI EN 300 468 §5.2.6 /
/// Table 9 — `0x73`).
pub const TOT_TABLE_ID: u8 = 0x73;

/// PID reserved for the Program Association Table per §2.4.4.3 / Table 2-3.
pub const PAT_PID: u16 = 0x0000;
/// PID reserved for the Conditional Access Table per §2.4.4.6 / Table 2-3.
pub const CAT_PID: u16 = 0x0001;
/// PID reserved for the Transport Stream Description Table per §2.4.4.12
/// / Table 2-3.
pub const TSDT_PID: u16 = 0x0002;
/// Fixed PID carrying the DVB SDT / BAT / ST sections (ETSI EN 300 468
/// §5.1.3 Table 1 — `0x0011`).
pub const SDT_PID: u16 = 0x0011;
/// Fixed PID carrying the DVB EIT sections (ETSI EN 300 468 §5.1.3
/// Table 1 / §5.2.4 — `0x0012`).
pub const EIT_PID: u16 = 0x0012;
/// Fixed PID carrying the DVB NIT sections (ETSI EN 300 468 §5.1.3
/// Table 1 / §5.2.1 — `0x0010`).
pub const NIT_PID: u16 = 0x0010;
/// Fixed PID carrying the DVB TDT and TOT sections (ETSI EN 300 468
/// §5.1.3 Table 1 / §5.2.5 / §5.2.6 — `0x0014`).
pub const TDT_TOT_PID: u16 = 0x0014;

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

/// Parsed Transport Stream Description Table per §2.4.4.12 /
/// Table 2-30-1.
///
/// The TSDT is optional. When present it is carried on the fixed PID
/// [`TSDT_PID`] (`0x0002`) with `table_id == TSDT_TABLE_ID` (`0x03`)
/// and carries a single `descriptor()` loop (§2.6) that applies to the
/// **entire** Transport Stream rather than to one program or stream.
/// Structurally it mirrors the CAT: the long-form section header
/// (`table_id` … `last_section_number`), then a run of descriptors,
/// then the CRC. The 16 bits at byte offsets 3–4 are reserved per the
/// `reserved (18 bits)` field of Table 2-30-1 and carry no
/// `table_id_extension` meaning; like the CAT they are ignored on
/// parse. Sections may be segmented across the [`TSDT_PID`] stream and
/// reassembled with [`PsiSectionAssembler`] before parsing.
#[derive(Debug, Default, Clone)]
pub struct TransportStreamDescriptionTable {
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// `section_number`.
    pub section_number: u8,
    /// `last_section_number`.
    pub last_section_number: u8,
    /// Raw bytes of the descriptor() loop carried in the TSDT body —
    /// walk with [`Self::iter_descriptors`] to get typed records.
    pub descriptors: Vec<u8>,
}

impl TransportStreamDescriptionTable {
    /// Parse a single TSDT section. The slice must run from `table_id`
    /// through the CRC trailer (i.e. the pointer_field has already been
    /// skipped).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_section_header(section, TSDT_TABLE_ID)?;
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

/// One transport-stream entry from a NIT's `transport_stream_loop`
/// (ETSI EN 300 468 §5.2.1 Table 3).
///
/// Each entry pairs a `(transport_stream_id, original_network_id)` —
/// which the spec notes uniquely identifies a TS throughout the
/// application area — with a per-TS descriptor loop. That loop most
/// commonly carries delivery-system descriptors (cable / satellite /
/// terrestrial) plus the `service_list_descriptor`; this crate exposes
/// the raw descriptor block so callers walk it with
/// [`Self::iter_descriptors`].
#[derive(Debug, Default, Clone)]
pub struct NitTransportStream {
    /// 16-bit `transport_stream_id` — labels this TS within the
    /// delivery system.
    pub transport_stream_id: u16,
    /// 16-bit `original_network_id` — labels the network_id of the
    /// originating delivery system.
    pub original_network_id: u16,
    /// Raw bytes of this TS entry's descriptor() loop — walk with
    /// [`Self::iter_descriptors`] to get typed TLV records.
    pub descriptors: Vec<u8>,
}

impl NitTransportStream {
    /// Walk this TS entry's descriptor() loop as typed TLV records.
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
}

/// Parsed Network Information Table per ETSI EN 300 468 §5.2.1 (Table 3).
///
/// The NIT conveys the physical organization of the multiplexes / TSs
/// carried by a network and the characteristics of the network itself.
/// It is carried on the fixed PID [`NIT_PID`] (`0x0010`); sections that
/// describe the **actual** network carry `table_id` `0x40`
/// ([`NIT_ACTUAL_TABLE_ID`]) and sections that describe **other**
/// networks carry `0x41` ([`NIT_OTHER_TABLE_ID`]). The `network_id`
/// label rides in the `table_id_extension` slot.
///
/// Structurally the section carries a two-level descriptor layout — a
/// network-level descriptor loop (most commonly the
/// `network_name_descriptor`, tag `0x40`, naming the delivery system)
/// followed by a `transport_stream_loop` whose entries each carry their
/// own descriptor loop. This mirrors the PMT's program-info / ES-info
/// split. Like the other long-form tables a NIT may be segmented across
/// the [`NIT_PID`] stream and reassembled with [`PsiSectionAssembler`]
/// before parsing.
#[derive(Debug, Default, Clone)]
pub struct NetworkInformationTable {
    /// `network_id` (from `table_id_extension`).
    pub network_id: u16,
    /// `true` when the section's `table_id` was `0x41` (describes another
    /// network); `false` for `0x40` (the actual network carrying the NIT).
    pub other_network: bool,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// `section_number`.
    pub section_number: u8,
    /// `last_section_number`.
    pub last_section_number: u8,
    /// Raw bytes of the network-level descriptor() loop — walk with
    /// [`Self::iter_descriptors`] to get typed records (e.g. the
    /// `network_name_descriptor`).
    pub descriptors: Vec<u8>,
    /// Transport-stream entries carried in this section.
    pub transport_streams: Vec<NitTransportStream>,
}

impl NetworkInformationTable {
    /// `true` when `table_id` is either NIT classification (`0x40`/`0x41`).
    pub fn is_nit_table_id(table_id: u8) -> bool {
        matches!(table_id, NIT_ACTUAL_TABLE_ID | NIT_OTHER_TABLE_ID)
    }

    /// Parse a single NIT section. The slice must run from `table_id`
    /// through the CRC trailer (i.e. the pointer_field has already been
    /// skipped). Accepts both the actual-network (`0x40`) and
    /// other-network (`0x41`) table_ids.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let table_id = section.first().copied().unwrap_or(0);
        let other_network = match table_id {
            NIT_ACTUAL_TABLE_ID => false,
            NIT_OTHER_TABLE_ID => true,
            _ => {
                return Err(TsError::Unsupported(
                    "PSI table_id does not match expected value",
                ))
            }
        };
        let (hdr, body) = parse_section_header(section, table_id)?;
        // Body layout (Table 3): reserved_future_use (4) +
        // network_descriptors_length (12) + network descriptors +
        // reserved_future_use (4) + transport_stream_loop_length (12) +
        // TS loop.
        if body.len() < 2 {
            return Err(TsError::Truncated {
                what: "NIT body",
                have: body.len(),
                need: 2,
            });
        }
        let network_descriptors_length =
            (u16::from_be_bytes([body[0] & 0b0000_1111, body[1]])) as usize;
        let nd_start = 2usize;
        let nd_end = nd_start.checked_add(network_descriptors_length).ok_or(
            TsError::SectionLengthOverrun {
                claimed: network_descriptors_length,
                have: body.len() - nd_start,
            },
        )?;
        if nd_end > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: network_descriptors_length,
                have: body.len() - nd_start,
            });
        }
        let descriptors = body[nd_start..nd_end].to_vec();

        // transport_stream_loop_length (12 bits) gates the TS loop.
        if nd_end + 2 > body.len() {
            return Err(TsError::Truncated {
                what: "NIT transport_stream_loop_length",
                have: body.len() - nd_end,
                need: 2,
            });
        }
        let ts_loop_length =
            (u16::from_be_bytes([body[nd_end] & 0b0000_1111, body[nd_end + 1]])) as usize;
        let loop_start = nd_end + 2;
        let loop_end =
            loop_start
                .checked_add(ts_loop_length)
                .ok_or(TsError::SectionLengthOverrun {
                    claimed: ts_loop_length,
                    have: body.len() - loop_start,
                })?;
        if loop_end > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: ts_loop_length,
                have: body.len() - loop_start,
            });
        }
        let ts_loop = &body[loop_start..loop_end];

        let mut transport_streams = Vec::new();
        let mut i = 0;
        // Each TS entry: transport_stream_id (16) + original_network_id
        // (16) + reserved_future_use (4) + transport_descriptors_length
        // (12) + descriptor loop. Fixed head = 6 bytes before descriptors.
        while i + 6 <= ts_loop.len() {
            let transport_stream_id = u16::from_be_bytes([ts_loop[i], ts_loop[i + 1]]);
            let original_network_id = u16::from_be_bytes([ts_loop[i + 2], ts_loop[i + 3]]);
            let transport_descriptors_length =
                (u16::from_be_bytes([ts_loop[i + 4] & 0b0000_1111, ts_loop[i + 5]])) as usize;
            let descr_start = i + 6;
            let descr_end = descr_start
                .checked_add(transport_descriptors_length)
                .ok_or(TsError::SectionLengthOverrun {
                    claimed: transport_descriptors_length,
                    have: ts_loop.len() - descr_start,
                })?;
            if descr_end > ts_loop.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: transport_descriptors_length,
                    have: ts_loop.len() - descr_start,
                });
            }
            transport_streams.push(NitTransportStream {
                transport_stream_id,
                original_network_id,
                descriptors: ts_loop[descr_start..descr_end].to_vec(),
            });
            i = descr_end;
        }

        Ok(Self {
            network_id: hdr.table_id_extension,
            other_network,
            version_number: hdr.version_number,
            current_next_indicator: hdr.current_next_indicator,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            descriptors,
            transport_streams,
        })
    }

    /// Walk the network-level descriptor() loop as typed TLV records.
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
}

/// Running status of a service (ETSI EN 300 468 §5.2.3 Table 6).
///
/// A 3-bit field; values 6 and 7 are reserved and surface as
/// [`RunningStatus::Reserved`] preserving the raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunningStatus {
    /// `0` — undefined.
    Undefined,
    /// `1` — not running.
    NotRunning,
    /// `2` — starts in a few seconds (e.g. for video recording).
    StartsSoon,
    /// `3` — pausing.
    Pausing,
    /// `4` — running.
    Running,
    /// `5` — service off-air.
    OffAir,
    /// `6`–`7` — reserved for future use; raw value preserved.
    Reserved(u8),
}

impl RunningStatus {
    /// Map the 3-bit wire value to a typed status.
    pub fn from_bits(value: u8) -> Self {
        match value & 0b0000_0111 {
            0 => RunningStatus::Undefined,
            1 => RunningStatus::NotRunning,
            2 => RunningStatus::StartsSoon,
            3 => RunningStatus::Pausing,
            4 => RunningStatus::Running,
            5 => RunningStatus::OffAir,
            other => RunningStatus::Reserved(other),
        }
    }
}

/// One service entry from the SDT service loop (ETSI EN 300 468
/// §5.2.3 Table 5).
#[derive(Debug, Clone)]
pub struct SdtService {
    /// 16-bit `service_id` — equals the corresponding PMT
    /// `program_number` for normal services.
    pub service_id: u16,
    /// `EIT_schedule_flag` — EIT schedule info present in this TS.
    pub eit_schedule_flag: bool,
    /// `EIT_present_following_flag` — EIT present/following info present.
    pub eit_present_following_flag: bool,
    /// 3-bit `running_status` (Table 6).
    pub running_status: RunningStatus,
    /// `free_CA_mode` — when `false` every component stream is
    /// unscrambled; when `true` one or more streams may be CA-controlled.
    pub free_ca_mode: bool,
    /// Raw bytes of this service's `descriptor()` loop — walk with
    /// [`Self::iter_descriptors`]. The DVB `service_descriptor`
    /// (tag `0x48`) carried here decodes the service / provider names.
    pub descriptors: Vec<u8>,
}

impl SdtService {
    /// Walk this service's descriptor loop as typed TLV records.
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
}

/// Parsed DVB Service Description Table (ETSI EN 300 468 §5.2.3
/// Table 5).
///
/// The SDT is a DVB Service Information table carried on the fixed PID
/// [`SDT_PID`] (`0x0011`). Sections describing the **actual** TS use
/// `table_id == SDT_ACTUAL_TABLE_ID` (`0x42`); sections describing
/// **other** TSs use `SDT_OTHER_TABLE_ID` (`0x46`). It shares the
/// 8-byte long-form PSI section header (parsed and CRC-verified the
/// same way as PAT/PMT), then carries `original_network_id` (16 bits)
/// plus one reserved byte, then a loop of [`SdtService`] entries, then
/// the CRC.
///
/// `transport_stream_id` is taken from the `table_id_extension` slot
/// per §5.2.3. The service loop's per-service descriptor blocks most
/// commonly carry the DVB `service_descriptor` (tag `0x48`), which the
/// crate's descriptor decoder lifts into
/// [`crate::descriptor::ServiceDescriptor`] — the source of a service's
/// human-readable name and provider.
#[derive(Debug, Default, Clone)]
pub struct ServiceDescriptionTable {
    /// `transport_stream_id` (from `table_id_extension`).
    pub transport_stream_id: u16,
    /// `true` when the section's `table_id` was `0x46` (describes another
    /// TS); `false` for `0x42` (the actual TS carrying the SDT).
    pub other_transport_stream: bool,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// `section_number`.
    pub section_number: u8,
    /// `last_section_number`.
    pub last_section_number: u8,
    /// `original_network_id`.
    pub original_network_id: u16,
    /// Service entries carried in this section.
    pub services: Vec<SdtService>,
}

impl ServiceDescriptionTable {
    /// Parse a single SDT section. The slice must run from `table_id`
    /// through the CRC trailer (i.e. the pointer_field has already been
    /// skipped). Accepts both the actual-TS (`0x42`) and other-TS
    /// (`0x46`) table_ids.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let table_id = section.first().copied().unwrap_or(0);
        let other_transport_stream = match table_id {
            SDT_ACTUAL_TABLE_ID => false,
            SDT_OTHER_TABLE_ID => true,
            _ => {
                return Err(TsError::Unsupported(
                    "PSI table_id does not match expected value",
                ))
            }
        };
        let (hdr, body) = parse_section_header(section, table_id)?;
        // Body layout (Table 5): original_network_id (16) +
        // reserved_future_use (8) + service loop.
        if body.len() < 3 {
            return Err(TsError::Truncated {
                what: "SDT body",
                have: body.len(),
                need: 3,
            });
        }
        let original_network_id = u16::from_be_bytes([body[0], body[1]]);
        // body[2] is reserved_future_use.
        let mut services = Vec::new();
        let mut i = 3;
        // Each service entry: service_id (16) + flags/running_status/
        // free_CA_mode (8) + descriptors_length (12, top 4 of next byte)
        // + descriptor loop. Fixed head = 5 bytes before descriptors.
        while i + 5 <= body.len() {
            let service_id = u16::from_be_bytes([body[i], body[i + 1]]);
            let b = body[i + 2];
            let eit_schedule_flag = (b & 0b0000_0010) != 0;
            let eit_present_following_flag = (b & 0b0000_0001) != 0;
            let b3 = body[i + 3];
            let running_status = RunningStatus::from_bits(b3 >> 5);
            let free_ca_mode = (b3 & 0b0001_0000) != 0;
            let descriptors_length = (u16::from_be_bytes([b3 & 0b0000_1111, body[i + 4]])) as usize;
            let descr_start = i + 5;
            let descr_end = descr_start.checked_add(descriptors_length).ok_or(
                TsError::SectionLengthOverrun {
                    claimed: descriptors_length,
                    have: body.len() - descr_start,
                },
            )?;
            if descr_end > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: descriptors_length,
                    have: body.len() - descr_start,
                });
            }
            services.push(SdtService {
                service_id,
                eit_schedule_flag,
                eit_present_following_flag,
                running_status,
                free_ca_mode,
                descriptors: body[descr_start..descr_end].to_vec(),
            });
            i = descr_end;
        }
        Ok(Self {
            transport_stream_id: hdr.table_id_extension,
            other_transport_stream,
            version_number: hdr.version_number,
            current_next_indicator: hdr.current_next_indicator,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            original_network_id,
            services,
        })
    }
}

/// A calendar date + wall-clock time decoded from an EIT 40-bit
/// `start_time` field (ETSI EN 300 468 §5.2.4 / annex C).
///
/// On the wire the field is 16 bits of Modified Julian Date (the 16
/// least-significant bits of the MJD) followed by 24 bits of 6-digit
/// 4-bit BCD encoding the UTC hours/minutes/seconds. The date portion
/// is converted to the proleptic Gregorian `(year, month, day)` using
/// the integer formula in annex C; the time portion is the decoded BCD.
///
/// When every bit of the 40-bit field is set (`0xFF_FFFF_FFFF`) the
/// start time is *undefined* (e.g. for an NVOD reference event) and the
/// parser yields `None` rather than a bogus date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EitDateTime {
    /// Full Gregorian year (e.g. `2003`), reconstructed from the 16-bit
    /// MJD plus the annex-C `Y = year − 1900` intermediate.
    pub year: u16,
    /// Month, 1 (January) through 12 (December).
    pub month: u8,
    /// Day of month, 1 through 31.
    pub day: u8,
    /// UTC hour, 0 through 23 (decoded from BCD; not range-clamped).
    pub hour: u8,
    /// UTC minute, 0 through 59 (decoded from BCD; not range-clamped).
    pub minute: u8,
    /// UTC second, 0 through 59 (decoded from BCD; not range-clamped).
    pub second: u8,
    /// The raw 16-bit MJD value, preserved for callers that prefer to do
    /// their own date arithmetic.
    pub mjd: u16,
}

/// An event duration decoded from an EIT 24-bit `duration` field
/// (ETSI EN 300 468 §5.2.4) — 6 digits of 4-bit BCD giving hours,
/// minutes, and seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EitDuration {
    /// Hours component (BCD-decoded; may exceed 24 for long events).
    pub hours: u8,
    /// Minutes component (BCD-decoded, 0–59).
    pub minutes: u8,
    /// Seconds component (BCD-decoded, 0–59).
    pub seconds: u8,
}

impl EitDuration {
    /// Total duration expressed in whole seconds.
    pub fn as_seconds(&self) -> u32 {
        (self.hours as u32) * 3600 + (self.minutes as u32) * 60 + (self.seconds as u32)
    }
}

/// Decode one 4-bit-BCD byte into its 0–99 integer value.
fn bcd_byte(b: u8) -> u8 {
    (b >> 4) * 10 + (b & 0x0F)
}

/// Decode a 40-bit DVB UTC_time field (16-bit MJD + 24-bit BCD time).
///
/// This is the common time encoding shared by the EIT `start_time`
/// (§5.2.4), the TDT / TOT `UTC_time` (§5.2.5 / §5.2.6), and the
/// `local_time_offset_descriptor` `time_of_change` (§6.2.20): 16 bits
/// giving the 16 lsb of the Modified Julian Date followed by 24 bits of
/// 6-digit 4-bit BCD encoding the UTC hours/minutes/seconds.
///
/// Returns `None` when the field is the all-ones "undefined" sentinel.
/// The MJD→(Y,M,D) conversion follows the integer formula in
/// ETSI EN 300 468 annex C:
///
/// ```text
/// Y' = int((MJD − 15078,2) / 365,25)
/// M' = int((MJD − 14956,1 − int(Y' × 365,25)) / 30,6001)
/// D  = MJD − 14956 − int(Y' × 365,25) − int(M' × 30,6001)
/// K  = 1 if M' == 14 or M' == 15 else 0
/// Y  = Y' + K                 (years since 1900)
/// M  = M' − 1 − K × 12
/// ```
pub fn decode_utc_time(bytes: [u8; 5]) -> Option<EitDateTime> {
    if bytes == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
        return None;
    }
    let mjd = u16::from_be_bytes([bytes[0], bytes[1]]);
    // Annex C integer arithmetic. The constants 365,25 and 30,6001 are
    // applied via scaled integer multiplication to avoid floating point:
    // int(Y' × 365,25) == (Y' × 36525) / 100, etc.
    let mjd_i = mjd as i64;
    let yp = ((mjd_i - 15078) * 100 - 20) / 36525; // int((MJD − 15078,2)/365,25)
    let yp_days = (yp * 36525) / 100; // int(Y' × 365,25)
                                      // int((MJD − 14956,1 − yp_days)/30,6001)
    let mp = ((mjd_i - 14956 - yp_days) * 10000 - 1) / 306001;
    let mp_days = (mp * 306001) / 10000; // int(M' × 30,6001)
    let d = mjd_i - 14956 - yp_days - mp_days;
    let k: i64 = if mp == 14 || mp == 15 { 1 } else { 0 };
    let y = yp + k;
    let m = mp - 1 - k * 12;
    let year = (1900 + y) as u16;
    let month = m as u8;
    let day = d as u8;
    let hour = bcd_byte(bytes[2]);
    let minute = bcd_byte(bytes[3]);
    let second = bcd_byte(bytes[4]);
    Some(EitDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        mjd,
    })
}

/// One event entry from the EIT event loop (ETSI EN 300 468 §5.2.4
/// Table 7).
#[derive(Debug, Clone)]
pub struct EitEvent {
    /// 16-bit `event_id`, unique within a service.
    pub event_id: u16,
    /// Decoded `start_time` — `None` when the field was the all-ones
    /// "undefined" sentinel (e.g. for an NVOD reference event).
    pub start_time: Option<EitDateTime>,
    /// Decoded `duration` (BCD hours/minutes/seconds).
    pub duration: EitDuration,
    /// 3-bit `running_status` (Table 6).
    pub running_status: RunningStatus,
    /// `free_CA_mode` — `false` when every component stream of the event
    /// is unscrambled; `true` when one or more may be CA-controlled.
    pub free_ca_mode: bool,
    /// Raw bytes of this event's `descriptor()` loop — walk with
    /// [`Self::iter_descriptors`]. The DVB `short_event_descriptor`
    /// (tag `0x4D`) carried here decodes the event name + short text.
    pub descriptors: Vec<u8>,
}

impl EitEvent {
    /// Walk this event's descriptor loop as typed TLV records.
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
}

/// Parsed DVB Event Information Table (ETSI EN 300 468 §5.2.4 Table 7).
///
/// The EIT carries chronological per-event metadata (start time,
/// duration, running status, descriptors) for the services in a
/// multiplex. It is carried on the fixed PID [`EIT_PID`] (`0x0012`) and
/// distinguished from other tables by `table_id`:
///
/// * `0x4E` — present/following events on the **actual** TS.
/// * `0x4F` — present/following events on **other** TSs.
/// * `0x50`–`0x5F` — event schedule on the actual TS.
/// * `0x60`–`0x6F` — event schedule on other TSs.
///
/// The section shares the 8-byte long-form PSI header (CRC-verified the
/// same way as PAT/PMT/SDT) where `service_id` lives in the
/// `table_id_extension` slot. After the header the body carries
/// `transport_stream_id` (16) + `original_network_id` (16) +
/// `segment_last_section_number` (8) + `last_table_id` (8), then a loop
/// of [`EitEvent`] entries, then the CRC.
///
/// The `service_id` equals the corresponding PMT `program_number` for
/// normal services, so an EIT lets the `oxideav remux bluray://` path
/// attach human-readable event names (via the per-event
/// `short_event_descriptor`) and time ranges to each program.
#[derive(Debug, Default, Clone)]
pub struct EventInformationTable {
    /// `service_id` (from `table_id_extension`).
    pub service_id: u16,
    /// `true` when the section describes other TSs (`table_id` `0x4F`
    /// or `0x60`–`0x6F`); `false` for the actual TS (`0x4E` /
    /// `0x50`–`0x5F`).
    pub other_transport_stream: bool,
    /// `true` when the section is event-schedule information
    /// (`0x50`–`0x6F`); `false` for present/following (`0x4E` / `0x4F`).
    pub schedule: bool,
    /// Raw `table_id` of the parsed section.
    pub table_id: u8,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `current_next_indicator`.
    pub current_next_indicator: bool,
    /// `section_number`.
    pub section_number: u8,
    /// `last_section_number`.
    pub last_section_number: u8,
    /// `transport_stream_id`.
    pub transport_stream_id: u16,
    /// `original_network_id`.
    pub original_network_id: u16,
    /// `segment_last_section_number` — last section of this segment of
    /// the sub_table (equals `last_section_number` for unsegmented
    /// sub_tables).
    pub segment_last_section_number: u8,
    /// `last_table_id` — the largest `table_id` used by this service's
    /// sub_table (per §5.2.4 may differ per service).
    pub last_table_id: u8,
    /// Event entries carried in this section, in chronological order.
    pub events: Vec<EitEvent>,
}

impl EventInformationTable {
    /// `true` when `table_id` is any of the four EIT classifications
    /// (`0x4E`, `0x4F`, `0x50`–`0x5F`, `0x60`–`0x6F`).
    pub fn is_eit_table_id(table_id: u8) -> bool {
        matches!(table_id, EIT_ACTUAL_PF_TABLE_ID | EIT_OTHER_PF_TABLE_ID)
            || (EIT_ACTUAL_SCHEDULE_FIRST..=EIT_ACTUAL_SCHEDULE_LAST).contains(&table_id)
            || (EIT_OTHER_SCHEDULE_FIRST..=EIT_OTHER_SCHEDULE_LAST).contains(&table_id)
    }

    /// Parse a single EIT section. The slice must run from `table_id`
    /// through the CRC trailer (i.e. the pointer_field has already been
    /// skipped). Accepts any of the four EIT `table_id` classifications.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let table_id = section.first().copied().unwrap_or(0);
        if !Self::is_eit_table_id(table_id) {
            return Err(TsError::Unsupported(
                "PSI table_id does not match expected value",
            ));
        }
        let other_transport_stream = table_id == EIT_OTHER_PF_TABLE_ID
            || (EIT_OTHER_SCHEDULE_FIRST..=EIT_OTHER_SCHEDULE_LAST).contains(&table_id);
        let schedule = (EIT_ACTUAL_SCHEDULE_FIRST..=EIT_OTHER_SCHEDULE_LAST).contains(&table_id);
        let (hdr, body) = parse_section_header(section, table_id)?;
        // Body layout (Table 7): transport_stream_id (16) +
        // original_network_id (16) + segment_last_section_number (8) +
        // last_table_id (8), then the event loop.
        if body.len() < 6 {
            return Err(TsError::Truncated {
                what: "EIT body",
                have: body.len(),
                need: 6,
            });
        }
        let transport_stream_id = u16::from_be_bytes([body[0], body[1]]);
        let original_network_id = u16::from_be_bytes([body[2], body[3]]);
        let segment_last_section_number = body[4];
        let last_table_id = body[5];
        let mut events = Vec::new();
        let mut i = 6;
        // Each event entry: event_id (16) + start_time (40) +
        // duration (24) + running_status (3) / free_CA_mode (1) /
        // descriptors_length (12). Fixed head = 12 bytes before the
        // descriptor loop.
        while i + 12 <= body.len() {
            let event_id = u16::from_be_bytes([body[i], body[i + 1]]);
            let start_time = decode_utc_time([
                body[i + 2],
                body[i + 3],
                body[i + 4],
                body[i + 5],
                body[i + 6],
            ]);
            let duration = EitDuration {
                hours: bcd_byte(body[i + 7]),
                minutes: bcd_byte(body[i + 8]),
                seconds: bcd_byte(body[i + 9]),
            };
            let b10 = body[i + 10];
            let running_status = RunningStatus::from_bits(b10 >> 5);
            let free_ca_mode = (b10 & 0b0001_0000) != 0;
            let descriptors_length =
                (u16::from_be_bytes([b10 & 0b0000_1111, body[i + 11]])) as usize;
            let descr_start = i + 12;
            let descr_end = descr_start.checked_add(descriptors_length).ok_or(
                TsError::SectionLengthOverrun {
                    claimed: descriptors_length,
                    have: body.len() - descr_start,
                },
            )?;
            if descr_end > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: descriptors_length,
                    have: body.len() - descr_start,
                });
            }
            events.push(EitEvent {
                event_id,
                start_time,
                duration,
                running_status,
                free_ca_mode,
                descriptors: body[descr_start..descr_end].to_vec(),
            });
            i = descr_end;
        }
        Ok(Self {
            service_id: hdr.table_id_extension,
            other_transport_stream,
            schedule,
            table_id,
            version_number: hdr.version_number,
            current_next_indicator: hdr.current_next_indicator,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            transport_stream_id,
            original_network_id,
            segment_last_section_number,
            last_table_id,
            events,
        })
    }
}

/// Parsed DVB Time and Date Table (ETSI EN 300 468 §5.2.5 Table 8).
///
/// The TDT is the simplest DVB SI table: a single **short-form** section
/// (`section_syntax_indicator == 0`, no `version_number` /
/// `section_number` / CRC trailer) carrying nothing but the current UTC
/// time and date. It is transmitted on the fixed PID [`TDT_TOT_PID`]
/// (`0x0014`) with `table_id` [`TDT_TABLE_ID`] (`0x70`).
///
/// The wall-clock value lets the `oxideav remux bluray://` path stamp an
/// absolute capture time on a title when the source TS carries a TDT;
/// the richer [`TimeOffsetTable`] (TOT) additionally describes the local
/// time offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeDateTable {
    /// Decoded `UTC_time` — the current UTC date and wall-clock time.
    /// `None` for the all-ones "undefined" sentinel (not expected on a
    /// real TDT, but handled the same way as the EIT `start_time`).
    pub utc_time: Option<EitDateTime>,
}

impl TimeDateTable {
    /// `table_id` this parser accepts (`0x70`).
    pub const TABLE_ID: u8 = TDT_TABLE_ID;

    /// Parse a single TDT section. The slice must run from `table_id`
    /// through the end of the section (the pointer_field has already been
    /// skipped). The TDT has no CRC, so the body is validated by length
    /// alone.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let table_id = section.first().copied().unwrap_or(0);
        if table_id != TDT_TABLE_ID {
            return Err(TsError::Unsupported(
                "PSI table_id does not match expected value",
            ));
        }
        let body = parse_short_section_body(section)?;
        // Table 8 body: UTC_time (40 bits = 5 bytes).
        if body.len() < 5 {
            return Err(TsError::Truncated {
                what: "TDT body",
                have: body.len(),
                need: 5,
            });
        }
        let utc_time = decode_utc_time([body[0], body[1], body[2], body[3], body[4]]);
        Ok(Self { utc_time })
    }
}

/// Parsed DVB Time Offset Table (ETSI EN 300 468 §5.2.6 Table 9).
///
/// The TOT extends the [`TimeDateTable`] with a descriptor loop and a
/// CRC trailer. It is a single **short-form** section
/// (`section_syntax_indicator == 0`) transmitted on the fixed PID
/// [`TDT_TOT_PID`] (`0x0014`) with `table_id` [`TOT_TABLE_ID`] (`0x73`).
/// Unlike the TDT, the section carries a CRC_32 (verified here), and the
/// descriptor loop almost always holds a `local_time_offset_descriptor`
/// (tag `0x58`) giving the country-specific local-time offset relative
/// to the [`Self::utc_time`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeOffsetTable {
    /// Decoded `UTC_time` — the current UTC date and wall-clock time.
    /// `None` for the all-ones sentinel.
    pub utc_time: Option<EitDateTime>,
    /// Raw bytes of the section's `descriptor()` loop — walk with
    /// [`Self::iter_descriptors`]. Normally a single
    /// `local_time_offset_descriptor` (tag `0x58`).
    pub descriptors: Vec<u8>,
}

impl TimeOffsetTable {
    /// `table_id` this parser accepts (`0x73`).
    pub const TABLE_ID: u8 = TOT_TABLE_ID;

    /// Parse a single TOT section. The slice must run from `table_id`
    /// through the CRC trailer (the pointer_field has already been
    /// skipped). The CRC_32 is verified the same way as a long-form PSI
    /// section.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let table_id = section.first().copied().unwrap_or(0);
        if table_id != TOT_TABLE_ID {
            return Err(TsError::Unsupported(
                "PSI table_id does not match expected value",
            ));
        }
        let body = parse_short_section_body(section)?;
        // Table 9 body: UTC_time (40) + reserved (4) + descriptors_length
        // (12) + descriptors + CRC_32 (32). parse_short_section_body
        // returns the bytes between section_length and the section end
        // (CRC included), so split the trailing CRC off here.
        if body.len() < 5 + 2 + SECTION_CRC_LEN {
            return Err(TsError::Truncated {
                what: "TOT body",
                have: body.len(),
                need: 5 + 2 + SECTION_CRC_LEN,
            });
        }
        // Verify the CRC over table_id .. end-4. The whole section slice
        // was already trimmed to `3 + section_length` by
        // parse_short_section_body; recompute over that.
        let total = 3 + (((section[1] as usize & 0x0F) << 8) | section[2] as usize);
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
        let utc_time = decode_utc_time([body[0], body[1], body[2], body[3], body[4]]);
        // 4 reserved bits + 12-bit descriptors_length.
        let descriptors_length = (((body[5] as usize) & 0x0F) << 8) | body[6] as usize;
        let descr_start = 7usize;
        let descr_end = descr_start + descriptors_length;
        // Descriptors must fit before the CRC trailer.
        let descr_limit = body.len() - SECTION_CRC_LEN;
        if descr_end > descr_limit {
            return Err(TsError::SectionLengthOverrun {
                claimed: descriptors_length,
                have: descr_limit - descr_start,
            });
        }
        Ok(Self {
            utc_time,
            descriptors: body[descr_start..descr_end].to_vec(),
        })
    }

    /// Walk the TOT's descriptor loop as typed TLV records. The
    /// `local_time_offset_descriptor` (tag `0x58`) decodes to
    /// `DescriptorBody::LocalTimeOffset`.
    pub fn iter_descriptors(&self) -> DescriptorIter<'_> {
        iter_descriptors(&self.descriptors)
    }
}

/// Validate a **short-form** DVB section header (TDT / TOT, §5.2.5 /
/// §5.2.6) and return the body bytes that follow the 12-bit
/// `section_length`.
///
/// Short-form sections set `section_syntax_indicator == 0` and have no
/// `table_id_extension` / `version_number` / `section_number` fields —
/// the body begins immediately at `section[3]`. The returned slice runs
/// from `section[3]` through `3 + section_length` (which for the TOT
/// still includes the trailing CRC_32; the caller splits it off).
fn parse_short_section_body(section: &[u8]) -> Result<&[u8], TsError> {
    if section.len() < 3 {
        return Err(TsError::Truncated {
            what: "short PSI section header",
            have: section.len(),
            need: 3,
        });
    }
    let section_length = (((section[1] as usize) & 0x0F) << 8) | section[2] as usize;
    let total = 3 + section_length;
    if total > section.len() {
        return Err(TsError::SectionLengthOverrun {
            claimed: section_length,
            have: section.len() - 3,
        });
    }
    Ok(&section[3..total])
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
    use crate::descriptor::DescriptorBody;

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
    fn pmt_dvb_es_descriptors_decode_through_typed_paths() {
        use crate::descriptor::DescriptorBody;
        // A DVB-style PMT: a private-data PES (0x06) carrying a DVB
        // subtitle stream tagged with a stream_identifier_descriptor +
        // a subtitling_descriptor, and an AC-3 stream (0x06 private PES
        // in DVB) tagged with an AC-3_descriptor. Walk each ES loop and
        // confirm the new typed variants decode end-to-end through the
        // PMT parse path.
        let mut sub_es: Vec<u8> = Vec::new();
        // stream_identifier_descriptor (0x52): component_tag 0x09.
        sub_es.extend_from_slice(&[0x52, 0x01, 0x09]);
        // subtitling_descriptor (0x59): one "eng" entry, type 0x10,
        // composition 0x0001, ancillary 0x0002.
        sub_es.extend_from_slice(&[0x59, 0x08, b'e', b'n', b'g', 0x10, 0x00, 0x01, 0x00, 0x02]);

        // AC-3_descriptor (0x6A): flags 0x40 → only bsid present (0x08).
        let ac3_es: &[u8] = &[0x6A, 0x02, 0x40, 0x08];

        let section = build_pmt_section(
            1,
            0,
            0x100,
            &[],
            &[(0x06, 0x1500, &sub_es), (0x06, 0x1600, ac3_es)],
        );
        let pmt = ProgramMapTable::parse(&section).unwrap();
        assert_eq!(pmt.streams.len(), 2);

        // Subtitle stream: two descriptors, both typed.
        let sub_descrs: Vec<_> = pmt.streams[0]
            .iter_descriptors()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(sub_descrs.len(), 2);
        match &sub_descrs[0].body {
            DescriptorBody::StreamIdentifier(s) => assert_eq!(s.component_tag, 0x09),
            other => panic!("expected StreamIdentifier, got {other:?}"),
        }
        match &sub_descrs[1].body {
            DescriptorBody::Subtitling(s) => {
                assert_eq!(s.entries.len(), 1);
                assert_eq!(&s.entries[0].language_code, b"eng");
                assert_eq!(s.entries[0].subtitling_type, 0x10);
                assert_eq!(s.entries[0].composition_page_id, 0x0001);
                assert_eq!(s.entries[0].ancillary_page_id, 0x0002);
            }
            other => panic!("expected Subtitling, got {other:?}"),
        }

        // AC-3 stream: one typed AC-3 descriptor.
        let ac3_descrs: Vec<_> = pmt.streams[1]
            .iter_descriptors()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ac3_descrs.len(), 1);
        match &ac3_descrs[0].body {
            DescriptorBody::Ac3(a) => {
                assert_eq!(a.component_type, None);
                assert_eq!(a.bsid, Some(0x08));
                assert_eq!(a.mainid, None);
                assert_eq!(a.asvc, None);
            }
            other => panic!("expected Ac3, got {other:?}"),
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

    /// Build a TSDT section (table_id 0x03) carrying `descriptors` as
    /// its body. Section bytes run from table_id through CRC. The TSDT
    /// shares the CAT's wire layout: a long-form header whose bytes 3–4
    /// are reserved, then a descriptor() loop, then CRC.
    fn build_tsdt_section(version: u8, section_number: u8, descriptors: &[u8]) -> Vec<u8> {
        let section_length = 5 + descriptors.len() + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(TSDT_TABLE_ID);
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        // reserved 16 bits at bytes 3–4 (no table_id_extension meaning).
        s.push(0xFF);
        s.push(0xFF);
        // reserved | version | current_next.
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(section_number);
        s.push(section_number); // last_section_number = section_number
        s.extend_from_slice(descriptors);
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    #[test]
    fn tsdt_round_trip_registration_descriptor() {
        // Table 2-39 restricts the TSDT to 2.6 descriptors; a
        // registration_descriptor (tag 0x05) is one such — carry
        // format_identifier "HDMV" + a private byte.
        let reg_descr: &[u8] = &[0x05, 0x05, b'H', b'D', b'M', b'V', 0xAB];
        let section = build_tsdt_section(9, 0, reg_descr);
        let tsdt = TransportStreamDescriptionTable::parse(&section).unwrap();
        assert_eq!(tsdt.version_number, 9);
        assert!(tsdt.current_next_indicator);
        assert_eq!(tsdt.section_number, 0);
        assert_eq!(tsdt.last_section_number, 0);
        let descrs: Vec<_> = tsdt.iter_descriptors().collect::<Result<_, _>>().unwrap();
        assert_eq!(descrs.len(), 1);
        match &descrs[0].body {
            crate::descriptor::DescriptorBody::Registration {
                format_identifier, ..
            } => assert_eq!(format_identifier, b"HDMV"),
            other => panic!("expected Registration, got {other:?}"),
        }
    }

    #[test]
    fn tsdt_empty_descriptor_loop() {
        // A TSDT with no descriptors is well-formed: header + CRC only.
        let section = build_tsdt_section(0, 0, &[]);
        let tsdt = TransportStreamDescriptionTable::parse(&section).unwrap();
        assert_eq!(tsdt.version_number, 0);
        assert!(tsdt.descriptors.is_empty());
        assert_eq!(tsdt.iter_descriptors().count(), 0);
    }

    #[test]
    fn tsdt_rejects_wrong_table_id() {
        // A CAT-shaped section (table_id 0x01) must not parse as TSDT.
        let section = build_cat_section(1, &[0x09, 0x04, 0x05, 0x00, 0xE1, 0x23]);
        let err = TransportStreamDescriptionTable::parse(&section).unwrap_err();
        match err {
            TsError::Unsupported(_) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn tsdt_reassembles_via_psi_assembler() {
        // The TSDT shares the PSI section envelope, so the generic
        // assembler must reassemble + hand it to TSDT::parse. Drive a
        // single-payload feed (pointer_field = 0).
        let reg_descr: &[u8] = &[0x05, 0x04, b'A', b'V', b'0', b'1'];
        let section = build_tsdt_section(2, 0, reg_descr);
        let mut payload = vec![0u8]; // pointer_field = 0
        payload.extend_from_slice(&section);
        payload.resize(184, 0xFF);
        let mut asm = PsiSectionAssembler::new();
        let out = asm.feed(&payload, true, 0).unwrap();
        assert_eq!(out.len(), 1);
        let tsdt = TransportStreamDescriptionTable::parse(&out[0]).unwrap();
        assert_eq!(tsdt.version_number, 2);
        assert_eq!(tsdt.iter_descriptors().count(), 1);
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

    /// Build one service-loop entry for an SDT section.
    fn build_sdt_service(
        service_id: u16,
        eit_sched: bool,
        eit_pf: bool,
        running_status: u8,
        free_ca: bool,
        descriptors: &[u8],
    ) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&service_id.to_be_bytes());
        // reserved_future_use (6) | EIT_schedule_flag | EIT_present_following.
        let mut b = 0b1111_1100u8;
        if eit_sched {
            b |= 0b10;
        }
        if eit_pf {
            b |= 0b01;
        }
        s.push(b);
        // running_status (3) | free_CA_mode (1) | descriptors_length (12).
        let dlen = descriptors.len() as u16;
        let b3 = ((running_status & 0b111) << 5)
            | (if free_ca { 0b0001_0000 } else { 0 })
            | ((dlen >> 8) & 0x0F) as u8;
        s.push(b3);
        s.push((dlen & 0xFF) as u8);
        s.extend_from_slice(descriptors);
        s
    }

    /// Build a full SDT section (table_id through CRC).
    fn build_sdt_section(
        table_id: u8,
        tsid: u16,
        version: u8,
        original_network_id: u16,
        services: &[Vec<u8>],
    ) -> Vec<u8> {
        // body = onid(2) + reserved(1) + Σ service entries.
        let body_len: usize = 3 + services.iter().map(|s| s.len()).sum::<usize>();
        let section_length = 5 + body_len + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(table_id);
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&tsid.to_be_bytes());
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(0); // section_number
        s.push(0); // last_section_number
        s.extend_from_slice(&original_network_id.to_be_bytes());
        s.push(0xFF); // reserved_future_use
        for svc in services {
            s.extend_from_slice(svc);
        }
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    /// Build a service_descriptor (tag 0x48) TLV.
    fn build_service_descriptor(service_type: u8, provider: &[u8], name: &[u8]) -> Vec<u8> {
        let mut body = vec![service_type, provider.len() as u8];
        body.extend_from_slice(provider);
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        let mut v = vec![0x48u8, body.len() as u8];
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn sdt_actual_single_service_round_trip() {
        let sd = build_service_descriptor(0x01, b"Provider", b"Channel One");
        let svc = build_sdt_service(0x0064, true, true, 4, false, &sd);
        let section = build_sdt_section(SDT_ACTUAL_TABLE_ID, 0x0001, 7, 0x2024, &[svc]);
        let sdt = ServiceDescriptionTable::parse(&section).unwrap();
        assert!(!sdt.other_transport_stream);
        assert_eq!(sdt.transport_stream_id, 0x0001);
        assert_eq!(sdt.version_number, 7);
        assert!(sdt.current_next_indicator);
        assert_eq!(sdt.original_network_id, 0x2024);
        assert_eq!(sdt.services.len(), 1);
        let s = &sdt.services[0];
        assert_eq!(s.service_id, 0x0064);
        assert!(s.eit_schedule_flag);
        assert!(s.eit_present_following_flag);
        assert_eq!(s.running_status, RunningStatus::Running);
        assert!(!s.free_ca_mode);
        let d = s.iter_descriptors().next().unwrap().unwrap();
        match d.body {
            crate::descriptor::DescriptorBody::Service(svc) => {
                assert_eq!(svc.service_type, 0x01);
                assert_eq!(svc.service_provider_name, b"Provider");
                assert_eq!(svc.service_name, b"Channel One");
            }
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[test]
    fn sdt_other_table_id_sets_flag() {
        let svc = build_sdt_service(0x0001, false, false, 1, true, &[]);
        let section = build_sdt_section(SDT_OTHER_TABLE_ID, 0x0009, 0, 0x0001, &[svc]);
        let sdt = ServiceDescriptionTable::parse(&section).unwrap();
        assert!(sdt.other_transport_stream);
        assert_eq!(sdt.services.len(), 1);
        let s = &sdt.services[0];
        assert_eq!(s.running_status, RunningStatus::NotRunning);
        assert!(s.free_ca_mode);
        assert!(!s.eit_schedule_flag);
        assert!(!s.eit_present_following_flag);
    }

    #[test]
    fn sdt_multiple_services() {
        let svc0 = build_sdt_service(0x0064, true, true, 4, false, &[]);
        let svc1 = build_sdt_service(0x0065, false, true, 5, true, &[]);
        let section = build_sdt_section(SDT_ACTUAL_TABLE_ID, 0x0002, 1, 0x1000, &[svc0, svc1]);
        let sdt = ServiceDescriptionTable::parse(&section).unwrap();
        assert_eq!(sdt.services.len(), 2);
        assert_eq!(sdt.services[0].service_id, 0x0064);
        assert_eq!(sdt.services[1].service_id, 0x0065);
        assert_eq!(sdt.services[1].running_status, RunningStatus::OffAir);
    }

    #[test]
    fn sdt_rejects_wrong_table_id() {
        // A PMT section fed to the SDT parser must be rejected.
        let section = build_pmt_section(1, 0, 0x100, &[], &[(0x1B, 0x1011, &[])]);
        assert!(ServiceDescriptionTable::parse(&section).is_err());
    }

    #[test]
    fn sdt_crc_mismatch_rejected() {
        let svc = build_sdt_service(0x0064, true, true, 4, false, &[]);
        let mut section = build_sdt_section(SDT_ACTUAL_TABLE_ID, 0x0001, 7, 0x2024, &[svc]);
        let last = section.len() - 1;
        section[last] ^= 0xFF;
        assert!(matches!(
            ServiceDescriptionTable::parse(&section),
            Err(TsError::PsiCrcMismatch { .. })
        ));
    }

    /// Build a network_name_descriptor (tag 0x40) TLV.
    fn build_network_name_descriptor(name: &[u8]) -> Vec<u8> {
        let mut v = vec![0x40u8, name.len() as u8];
        v.extend_from_slice(name);
        v
    }

    /// Build one NIT transport_stream loop entry (no CRC).
    fn build_nit_ts(tsid: u16, onid: u16, descriptors: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&tsid.to_be_bytes());
        s.extend_from_slice(&onid.to_be_bytes());
        // reserved_future_use (4) | transport_descriptors_length (12).
        let dlen = descriptors.len() as u16;
        s.push(0b1111_0000 | ((dlen >> 8) & 0x0F) as u8);
        s.push((dlen & 0xFF) as u8);
        s.extend_from_slice(descriptors);
        s
    }

    /// Build a full NIT section (table_id through CRC).
    fn build_nit_section(
        table_id: u8,
        network_id: u16,
        version: u8,
        net_descriptors: &[u8],
        ts_entries: &[Vec<u8>],
    ) -> Vec<u8> {
        let ts_loop_len: usize = ts_entries.iter().map(|e| e.len()).sum();
        // body = nd_len_field(2) + net_descriptors + ts_loop_len_field(2)
        //        + ts loop.
        let body_len = 2 + net_descriptors.len() + 2 + ts_loop_len;
        let section_length = 5 + body_len + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(table_id);
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&network_id.to_be_bytes());
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(0); // section_number
        s.push(0); // last_section_number
                   // reserved_future_use (4) | network_descriptors_length (12).
        let nd_len = net_descriptors.len() as u16;
        s.push(0b1111_0000 | ((nd_len >> 8) & 0x0F) as u8);
        s.push((nd_len & 0xFF) as u8);
        s.extend_from_slice(net_descriptors);
        // reserved_future_use (4) | transport_stream_loop_length (12).
        let tsl = ts_loop_len as u16;
        s.push(0b1111_0000 | ((tsl >> 8) & 0x0F) as u8);
        s.push((tsl & 0xFF) as u8);
        for e in ts_entries {
            s.extend_from_slice(e);
        }
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    #[test]
    fn nit_actual_with_network_name_and_ts_loop() {
        let nn = build_network_name_descriptor(b"Example Network");
        let ts0 = build_nit_ts(0x0001, 0x2024, &[]);
        let ts1 = build_nit_ts(0x0002, 0x2024, &[]);
        let section = build_nit_section(NIT_ACTUAL_TABLE_ID, 0x1234, 11, &nn, &[ts0, ts1]);
        let nit = NetworkInformationTable::parse(&section).unwrap();
        assert!(!nit.other_network);
        assert_eq!(nit.network_id, 0x1234);
        assert_eq!(nit.version_number, 11);
        assert!(nit.current_next_indicator);
        // network-level descriptor decodes to a NetworkName body.
        let d = nit.iter_descriptors().next().unwrap().unwrap();
        match d.body {
            crate::descriptor::DescriptorBody::NetworkName(n) => {
                assert_eq!(n.network_name, b"Example Network");
            }
            other => panic!("expected NetworkName, got {other:?}"),
        }
        assert_eq!(nit.transport_streams.len(), 2);
        assert_eq!(nit.transport_streams[0].transport_stream_id, 0x0001);
        assert_eq!(nit.transport_streams[0].original_network_id, 0x2024);
        assert_eq!(nit.transport_streams[1].transport_stream_id, 0x0002);
    }

    #[test]
    fn nit_other_table_id_sets_flag() {
        let section = build_nit_section(NIT_OTHER_TABLE_ID, 0x0009, 0, &[], &[]);
        let nit = NetworkInformationTable::parse(&section).unwrap();
        assert!(nit.other_network);
        assert_eq!(nit.network_id, 0x0009);
        assert!(nit.descriptors.is_empty());
        assert!(nit.transport_streams.is_empty());
    }

    #[test]
    fn nit_per_ts_descriptor_loop() {
        // A TS entry carrying a descriptor in its own loop is parsed and
        // the per-TS descriptor block is walkable.
        let raw = vec![0x83u8, 0x03, 0xAA, 0xBB, 0xCC]; // tag 0x83 (raw) len 3
        let ts0 = build_nit_ts(0x0064, 0x1000, &raw);
        let section = build_nit_section(NIT_ACTUAL_TABLE_ID, 0x0001, 1, &[], &[ts0]);
        let nit = NetworkInformationTable::parse(&section).unwrap();
        assert_eq!(nit.transport_streams.len(), 1);
        let entry = &nit.transport_streams[0];
        let d = entry.iter_descriptors().next().unwrap().unwrap();
        assert_eq!(d.tag, 0x83);
        assert_eq!(d.data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn nit_rejects_wrong_table_id() {
        // An SDT section fed to the NIT parser must be rejected.
        let svc = build_sdt_service(0x0064, true, true, 4, false, &[]);
        let section = build_sdt_section(SDT_ACTUAL_TABLE_ID, 0x0001, 7, 0x2024, &[svc]);
        assert!(NetworkInformationTable::parse(&section).is_err());
    }

    #[test]
    fn nit_crc_mismatch_rejected() {
        let nn = build_network_name_descriptor(b"Net");
        let mut section = build_nit_section(NIT_ACTUAL_TABLE_ID, 0x1234, 1, &nn, &[]);
        let last = section.len() - 1;
        section[last] ^= 0xFF;
        assert!(matches!(
            NetworkInformationTable::parse(&section),
            Err(TsError::PsiCrcMismatch { .. })
        ));
    }

    #[test]
    fn nit_is_nit_table_id() {
        assert!(NetworkInformationTable::is_nit_table_id(
            NIT_ACTUAL_TABLE_ID
        ));
        assert!(NetworkInformationTable::is_nit_table_id(NIT_OTHER_TABLE_ID));
        assert!(!NetworkInformationTable::is_nit_table_id(
            SDT_ACTUAL_TABLE_ID
        ));
        assert!(!NetworkInformationTable::is_nit_table_id(PMT_TABLE_ID));
    }

    #[test]
    fn running_status_reserved_values() {
        assert_eq!(RunningStatus::from_bits(6), RunningStatus::Reserved(6));
        assert_eq!(RunningStatus::from_bits(7), RunningStatus::Reserved(7));
        assert_eq!(RunningStatus::from_bits(0), RunningStatus::Undefined);
        assert_eq!(RunningStatus::from_bits(2), RunningStatus::StartsSoon);
        assert_eq!(RunningStatus::from_bits(3), RunningStatus::Pausing);
    }

    /// Build a short_event_descriptor (tag 0x4D) TLV.
    fn build_short_event_descriptor(lang: &[u8; 3], name: &[u8], text: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(lang);
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        body.push(text.len() as u8);
        body.extend_from_slice(text);
        let mut v = vec![0x4Du8, body.len() as u8];
        v.extend_from_slice(&body);
        v
    }

    /// Build one EIT event entry (event loop element, no CRC).
    #[allow(clippy::too_many_arguments)]
    fn build_eit_event(
        event_id: u16,
        start_time: [u8; 5],
        duration_bcd: [u8; 3],
        running_status: u8,
        free_ca: bool,
        descriptors: &[u8],
    ) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&event_id.to_be_bytes());
        s.extend_from_slice(&start_time);
        s.extend_from_slice(&duration_bcd);
        let dlen = descriptors.len() as u16;
        let b = ((running_status & 0b111) << 5)
            | (if free_ca { 0b0001_0000 } else { 0 })
            | ((dlen >> 8) & 0x0F) as u8;
        s.push(b);
        s.push((dlen & 0xFF) as u8);
        s.extend_from_slice(descriptors);
        s
    }

    /// Build a full EIT section (table_id through CRC).
    #[allow(clippy::too_many_arguments)]
    fn build_eit_section(
        table_id: u8,
        service_id: u16,
        version: u8,
        tsid: u16,
        onid: u16,
        segment_last: u8,
        last_table_id: u8,
        events: &[Vec<u8>],
    ) -> Vec<u8> {
        // body = tsid(2) + onid(2) + segment_last(1) + last_table_id(1)
        //        + Σ events.
        let body_len: usize = 6 + events.iter().map(|e| e.len()).sum::<usize>();
        let section_length = 5 + body_len + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(table_id);
        let len_hi = 0b1011_0000 | ((section_length >> 8) & 0x0F) as u8;
        s.push(len_hi);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&service_id.to_be_bytes());
        s.push(0b1100_0001 | ((version & 0b1_1111) << 1));
        s.push(0); // section_number
        s.push(0); // last_section_number
        s.extend_from_slice(&tsid.to_be_bytes());
        s.extend_from_slice(&onid.to_be_bytes());
        s.push(segment_last);
        s.push(last_table_id);
        for e in events {
            s.extend_from_slice(e);
        }
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    #[test]
    fn eit_start_time_spec_example() {
        // EN 300 468 §5.2.4 example 2: 93/10/13 12:45:00 is coded as
        // 0xC0 7912 4500 (MJD 0xC079 = 49273, then 12 45 00 in BCD).
        let dt = decode_utc_time([0xC0, 0x79, 0x12, 0x45, 0x00]).unwrap();
        assert_eq!(dt.mjd, 0xC079);
        assert_eq!(dt.year, 1993);
        assert_eq!(dt.month, 10);
        assert_eq!(dt.day, 13);
        assert_eq!(dt.hour, 12);
        assert_eq!(dt.minute, 45);
        assert_eq!(dt.second, 0);
    }

    #[test]
    fn eit_start_time_undefined_sentinel() {
        assert!(decode_utc_time([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn eit_duration_spec_example() {
        // EN 300 468 §5.2.4 example 3: 01:45:30 is coded as 0x01 4530.
        let d = EitDuration {
            hours: bcd_byte(0x01),
            minutes: bcd_byte(0x45),
            seconds: bcd_byte(0x30),
        };
        assert_eq!(d.hours, 1);
        assert_eq!(d.minutes, 45);
        assert_eq!(d.seconds, 30);
        assert_eq!(d.as_seconds(), 3600 + 45 * 60 + 30);
    }

    #[test]
    fn eit_actual_pf_single_event_round_trip() {
        let sed = build_short_event_descriptor(b"eng", b"The Event", b"A short description");
        let ev = build_eit_event(
            0x1234,
            [0xC0, 0x79, 0x12, 0x45, 0x00],
            [0x01, 0x45, 0x30],
            4, // running
            false,
            &sed,
        );
        let section = build_eit_section(
            EIT_ACTUAL_PF_TABLE_ID,
            0x0064, // service_id
            5,
            0x0001, // tsid
            0x2024, // onid
            0,
            EIT_ACTUAL_PF_TABLE_ID,
            &[ev],
        );
        let eit = EventInformationTable::parse(&section).unwrap();
        assert!(!eit.other_transport_stream);
        assert!(!eit.schedule);
        assert_eq!(eit.table_id, EIT_ACTUAL_PF_TABLE_ID);
        assert_eq!(eit.service_id, 0x0064);
        assert_eq!(eit.version_number, 5);
        assert!(eit.current_next_indicator);
        assert_eq!(eit.transport_stream_id, 0x0001);
        assert_eq!(eit.original_network_id, 0x2024);
        assert_eq!(eit.last_table_id, EIT_ACTUAL_PF_TABLE_ID);
        assert_eq!(eit.events.len(), 1);
        let e = &eit.events[0];
        assert_eq!(e.event_id, 0x1234);
        let st = e.start_time.unwrap();
        assert_eq!((st.year, st.month, st.day), (1993, 10, 13));
        assert_eq!((st.hour, st.minute, st.second), (12, 45, 0));
        assert_eq!(e.duration.as_seconds(), 6330);
        assert_eq!(e.running_status, RunningStatus::Running);
        assert!(!e.free_ca_mode);
        // The short_event_descriptor decodes to the event name + text.
        let d = e.iter_descriptors().next().unwrap().unwrap();
        match d.body {
            DescriptorBody::ShortEvent(se) => {
                assert_eq!(&se.language_code, b"eng");
                assert_eq!(se.event_name, b"The Event");
                assert_eq!(se.text, b"A short description");
            }
            other => panic!("expected ShortEvent, got {other:?}"),
        }
    }

    #[test]
    fn eit_schedule_and_other_flags() {
        // 0x60 = other-TS schedule.
        let ev = build_eit_event(1, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF], [0, 0, 0], 0, true, &[]);
        let section = build_eit_section(0x60, 0x0001, 0, 0x0001, 0x0001, 0, 0x62, &[ev]);
        let eit = EventInformationTable::parse(&section).unwrap();
        assert!(eit.other_transport_stream);
        assert!(eit.schedule);
        assert_eq!(eit.last_table_id, 0x62);
        // Undefined start time surfaces as None; free_CA_mode set.
        assert!(eit.events[0].start_time.is_none());
        assert!(eit.events[0].free_ca_mode);
    }

    #[test]
    fn eit_multiple_events() {
        let e0 = build_eit_event(
            10,
            [0xC0, 0x79, 0x12, 0x00, 0x00],
            [0, 0x30, 0],
            4,
            false,
            &[],
        );
        let e1 = build_eit_event(
            11,
            [0xC0, 0x79, 0x12, 0x30, 0x00],
            [0x01, 0, 0],
            1,
            false,
            &[],
        );
        let section = build_eit_section(
            EIT_ACTUAL_PF_TABLE_ID,
            0x0064,
            0,
            0x0001,
            0x0001,
            0,
            0x4E,
            &[e0, e1],
        );
        let eit = EventInformationTable::parse(&section).unwrap();
        assert_eq!(eit.events.len(), 2);
        assert_eq!(eit.events[0].event_id, 10);
        assert_eq!(eit.events[1].event_id, 11);
        assert_eq!(eit.events[0].duration.minutes, 30);
        assert_eq!(eit.events[1].duration.hours, 1);
    }

    #[test]
    fn eit_table_id_classification() {
        assert!(EventInformationTable::is_eit_table_id(0x4E));
        assert!(EventInformationTable::is_eit_table_id(0x4F));
        assert!(EventInformationTable::is_eit_table_id(0x50));
        assert!(EventInformationTable::is_eit_table_id(0x5F));
        assert!(EventInformationTable::is_eit_table_id(0x60));
        assert!(EventInformationTable::is_eit_table_id(0x6F));
        assert!(!EventInformationTable::is_eit_table_id(0x4D));
        assert!(!EventInformationTable::is_eit_table_id(0x70));
        assert!(!EventInformationTable::is_eit_table_id(0x42));
    }

    #[test]
    fn eit_rejects_wrong_table_id() {
        let ev = build_eit_event(1, [0xFF; 5], [0, 0, 0], 0, false, &[]);
        // Build with a valid EIT id, then corrupt the table_id byte so
        // the CRC still matches the original — parse must reject on id.
        let mut section = build_eit_section(0x70, 0, 0, 0, 0, 0, 0, &[ev]);
        section[0] = 0x70;
        assert!(matches!(
            EventInformationTable::parse(&section),
            Err(TsError::Unsupported(_))
        ));
    }

    #[test]
    fn eit_crc_mismatch_rejected() {
        let ev = build_eit_event(1, [0xC0, 0x79, 0x12, 0x45, 0x00], [0, 0, 0], 4, false, &[]);
        let mut section = build_eit_section(
            EIT_ACTUAL_PF_TABLE_ID,
            0x0064,
            0,
            0x0001,
            0x0001,
            0,
            0x4E,
            &[ev],
        );
        let last = section.len() - 1;
        section[last] ^= 0xFF;
        assert!(matches!(
            EventInformationTable::parse(&section),
            Err(TsError::PsiCrcMismatch { .. })
        ));
    }

    // ---- TDT / TOT (EN 300 468 §5.2.5 / §5.2.6) ----

    fn build_tdt_section(utc: [u8; 5]) -> Vec<u8> {
        // Short-form: table_id, then section_syntax_indicator=0 + '0' +
        // reserved + 12-bit section_length, then UTC_time (5 bytes).
        // section_length counts bytes after itself = UTC_time (5).
        let section_length = 5usize;
        let mut s = Vec::new();
        s.push(TDT_TABLE_ID);
        // ssi=0, '0', reserved=0b11 -> top nibble 0b0011 | length hi.
        s.push(0b0011_0000 | ((section_length >> 8) & 0x0F) as u8);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&utc);
        s
    }

    fn build_tot_section(utc: [u8; 5], descriptors: &[u8]) -> Vec<u8> {
        // Short-form body: UTC_time (5) + reserved/desc_len (2) +
        // descriptors + CRC_32 (4).
        let section_length = 5 + 2 + descriptors.len() + 4;
        let mut s = Vec::new();
        s.push(TOT_TABLE_ID);
        s.push(0b0011_0000 | ((section_length >> 8) & 0x0F) as u8);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&utc);
        // reserved_future_use (4) = 0b1111, then 12-bit descriptors_length.
        let dl = descriptors.len();
        s.push(0xF0 | ((dl >> 8) & 0x0F) as u8);
        s.push((dl & 0xFF) as u8);
        s.extend_from_slice(descriptors);
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    #[test]
    fn tdt_spec_example() {
        // EN 300 468 §5.2.5 example: 93/10/13 12:45:00 = 0xC0 7912 4500.
        let section = build_tdt_section([0xC0, 0x79, 0x12, 0x45, 0x00]);
        let tdt = TimeDateTable::parse(&section).unwrap();
        let dt = tdt.utc_time.unwrap();
        assert_eq!(dt.year, 1993);
        assert_eq!(dt.month, 10);
        assert_eq!(dt.day, 13);
        assert_eq!(dt.hour, 12);
        assert_eq!(dt.minute, 45);
        assert_eq!(dt.second, 0);
    }

    #[test]
    fn tdt_wrong_table_id_rejected() {
        let mut section = build_tdt_section([0xC0, 0x79, 0x12, 0x45, 0x00]);
        section[0] = 0x71; // RST table_id
        assert!(matches!(
            TimeDateTable::parse(&section),
            Err(TsError::Unsupported(_))
        ));
    }

    #[test]
    fn tot_no_descriptors() {
        let section = build_tot_section([0xC0, 0x79, 0x12, 0x45, 0x00], &[]);
        let tot = TimeOffsetTable::parse(&section).unwrap();
        let dt = tot.utc_time.unwrap();
        assert_eq!((dt.year, dt.month, dt.day), (1993, 10, 13));
        assert_eq!((dt.hour, dt.minute, dt.second), (12, 45, 0));
        assert!(tot.descriptors.is_empty());
        assert_eq!(tot.iter_descriptors().count(), 0);
    }

    #[test]
    fn tot_with_local_time_offset_descriptor() {
        // local_time_offset_descriptor (tag 0x58): one 13-byte entry.
        //   country_code "GBR"
        //   country_region_id=1, reserved, polarity=1 (negative)
        //     -> 0b000001_0_1 = 0x05
        //   local_time_offset BCD 0100 -> 01:00
        //   time_of_change = 0xC0 7912 4500
        //   next_time_offset BCD 0200 -> 02:00
        let mut entry = Vec::new();
        entry.extend_from_slice(b"GBR");
        entry.push(0b0000_0101);
        entry.extend_from_slice(&[0x01, 0x00]);
        entry.extend_from_slice(&[0xC0, 0x79, 0x12, 0x45, 0x00]);
        entry.extend_from_slice(&[0x02, 0x00]);
        let mut descr = vec![0x58u8, entry.len() as u8];
        descr.extend_from_slice(&entry);

        let section = build_tot_section([0xC0, 0x79, 0x12, 0x45, 0x00], &descr);
        let tot = TimeOffsetTable::parse(&section).unwrap();
        assert_eq!(tot.utc_time.unwrap().year, 1993);

        let d = tot.iter_descriptors().next().unwrap().unwrap();
        match d.body {
            crate::descriptor::DescriptorBody::LocalTimeOffset(ref lto) => {
                assert_eq!(lto.entries.len(), 1);
                let e = lto.entries[0];
                assert_eq!(&e.country_code, b"GBR");
                assert_eq!(e.country_region_id, 1);
                assert!(e.offset_negative);
                assert_eq!(e.local_time_offset_minutes, 60);
                assert_eq!(e.next_time_offset_minutes, 120);
                let toc = e.time_of_change.unwrap();
                assert_eq!((toc.year, toc.month, toc.day), (1993, 10, 13));
                assert_eq!((toc.hour, toc.minute, toc.second), (12, 45, 0));
            }
            ref other => panic!("expected LocalTimeOffset, got {other:?}"),
        }
    }

    #[test]
    fn tot_crc_mismatch_rejected() {
        let mut section = build_tot_section([0xC0, 0x79, 0x12, 0x45, 0x00], &[]);
        let last = section.len() - 1;
        section[last] ^= 0xFF;
        assert!(matches!(
            TimeOffsetTable::parse(&section),
            Err(TsError::PsiCrcMismatch { .. })
        ));
    }

    #[test]
    fn tot_truncated_body_rejected() {
        // section_length claims 5 but a TOT needs UTC(5)+declen(2)+CRC(4).
        let section = vec![TOT_TABLE_ID, 0b0011_0000, 0x05, 0, 0, 0, 0, 0];
        assert!(TimeOffsetTable::parse(&section).is_err());
    }
}
