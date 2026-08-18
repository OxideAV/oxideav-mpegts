//! Write-side builders for MPEG-TS PSI sections and §2.6 / DVB SI
//! descriptors.
//!
//! This module is the mirror image of the parse surface in [`crate::psi`]
//! and [`crate::descriptor`]: each function emits the exact on-wire bytes
//! the corresponding parser reads back. Every builder is a pure function
//! (`&[…] -> Vec<u8>`) that carries no muxer state, so the same routines
//! back both the [`crate::muxer`] multi-program / DVB-SI emission path and
//! any caller that just wants to synthesise a spec-conformant section.
//!
//! Two layers are provided:
//!
//! * **Descriptor builders** — emit one complete `descriptor()` TLV
//!   (`descriptor_tag` + `descriptor_length` + body) for the §2.6 base
//!   descriptors and the DVB SI extensions the demuxer decodes
//!   (`service`, `stream_identifier`, `teletext`, `subtitling`, `AC-3`,
//!   `enhanced_AC-3`, `DTS`, `AAC`, `network_name`, plus delivery-system
//!   descriptors). A descriptor body is always ≤ 255 bytes by
//!   construction; callers that assemble a descriptor loop simply
//!   concatenate the returned buffers.
//! * **Section builders** — emit a complete long-form PSI section
//!   (`table_id` through the CRC-32 trailer) for the PAT, PMT, CAT,
//!   TSDT, SDT, NIT, BAT, SIT, and present/following EIT, plus the
//!   short-form DVB SI sections (TDT, TOT with its CRC, RST, ST, DIT).
//!   The section is ready to hand to
//!   [`crate::psi::PsiSectionAssembler`]-style fragmentation and, once
//!   inside a TS packet, reads back identically through the matching
//!   `parse` routine.
//!
//! Time-carrying tables (EIT `start_time`) use the DVB 40-bit
//! MJD + BCD `UTC_time` encoding — the inverse of
//! [`crate::psi::decode_utc_time`] — implemented with the ETSI EN 300 468
//! annex-C integer formula so no floating point enters the wire path.

use crate::descriptor::{SubtitlingEntry, TeletextEntry};
use crate::psi::{
    mpeg2_crc32, EitDateTime, EitDuration, RstEntry, RunningStatus, BAT_TABLE_ID, CAT_TABLE_ID,
    DIT_TABLE_ID, NIT_ACTUAL_TABLE_ID, NIT_OTHER_TABLE_ID, PAT_TABLE_ID, PMT_TABLE_ID,
    RST_TABLE_ID, SDT_ACTUAL_TABLE_ID, SDT_OTHER_TABLE_ID, SIT_TABLE_ID, ST_TABLE_ID, TDT_TABLE_ID,
    TOT_TABLE_ID, TSDT_TABLE_ID,
};

/// DVB present/following EIT `table_id` for the actual TS (`0x4E`).
const EIT_ACTUAL_PF_TABLE_ID: u8 = 0x4E;
/// DVB present/following EIT `table_id` for other TSs (`0x4F`).
const EIT_OTHER_PF_TABLE_ID: u8 = 0x4F;

// ---------------------------------------------------------------------------
// Descriptor TLV envelope
// ---------------------------------------------------------------------------

/// Wrap a descriptor body in its `descriptor_tag` / `descriptor_length`
/// TLV envelope. The body must be ≤ 255 bytes (the `descriptor_length`
/// field width); longer bodies are truncated to 255 to keep the TLV
/// self-consistent — every builder below constructs bodies well under
/// that bound.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len().min(0xFF);
    let mut out = Vec::with_capacity(2 + len);
    out.push(tag);
    out.push(len as u8);
    out.extend_from_slice(&body[..len]);
    out
}

/// `registration_descriptor` (tag `0x05`, ISO/IEC 13818-1 §2.6.8) — a
/// 4-byte `format_identifier` FOURCC plus optional
/// `additional_identification_info`.
pub fn registration_descriptor(format_identifier: [u8; 4], extra: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + extra.len());
    body.extend_from_slice(&format_identifier);
    body.extend_from_slice(extra);
    tlv(0x05, &body)
}

/// `ISO_639_language_descriptor` (tag `0x0A`, §2.6.18) — a flat run of
/// `(ISO_639_language_code, audio_type)` records.
pub fn iso639_language_descriptor(entries: &[([u8; 3], u8)]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 4);
    for (code, audio_type) in entries {
        body.extend_from_slice(code);
        body.push(*audio_type);
    }
    tlv(0x0A, &body)
}

/// `stream_identifier_descriptor` (tag `0x52`, EN 300 468 §6.2.39) — the
/// single-byte `component_tag` cross-reference key.
pub fn stream_identifier_descriptor(component_tag: u8) -> Vec<u8> {
    tlv(0x52, &[component_tag])
}

/// `service_descriptor` (tag `0x48`, EN 300 468 §6.2.33) — the SDT
/// service-loop descriptor naming a service and its provider. The two
/// name runs are raw DVB text-string bytes (annex A charset selection is
/// the caller's).
pub fn service_descriptor(service_type: u8, provider: &[u8], name: &[u8]) -> Vec<u8> {
    let plen = provider.len().min(0xFF);
    let nlen = name.len().min(0xFF);
    let mut body = Vec::with_capacity(2 + plen + nlen);
    body.push(service_type);
    body.push(plen as u8);
    body.extend_from_slice(&provider[..plen]);
    body.push(nlen as u8);
    body.extend_from_slice(&name[..nlen]);
    tlv(0x48, &body)
}

/// `network_name_descriptor` (tag `0x40`, EN 300 468 §6.2.27) — names the
/// delivery system in the NIT network-level loop.
pub fn network_name_descriptor(name: &[u8]) -> Vec<u8> {
    tlv(0x40, name)
}

/// `bouquet_name_descriptor` (tag `0x47`, EN 300 468 §6.2.4).
pub fn bouquet_name_descriptor(name: &[u8]) -> Vec<u8> {
    tlv(0x47, name)
}

/// `short_event_descriptor` (tag `0x4D`, EN 300 468 §6.2.37) — the EIT
/// event-loop descriptor naming an event plus a short free-text
/// description, both under one language code.
pub fn short_event_descriptor(language_code: [u8; 3], event_name: &[u8], text: &[u8]) -> Vec<u8> {
    let nlen = event_name.len().min(0xFF);
    let tlen = text.len().min(0xFF);
    let mut body = Vec::with_capacity(3 + 2 + nlen + tlen);
    body.extend_from_slice(&language_code);
    body.push(nlen as u8);
    body.extend_from_slice(&event_name[..nlen]);
    body.push(tlen as u8);
    body.extend_from_slice(&text[..tlen]);
    tlv(0x4D, &body)
}

/// `service_list_descriptor` (tag `0x41`, EN 300 468 §6.2.35) — the
/// NIT / BAT transport-stream-loop descriptor listing a TS's services by
/// `(service_id, service_type)`.
pub fn service_list_descriptor(entries: &[(u16, u8)]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 3);
    for (service_id, service_type) in entries {
        body.extend_from_slice(&service_id.to_be_bytes());
        body.push(*service_type);
    }
    tlv(0x41, &body)
}

/// `teletext_descriptor` (tag `0x56`, EN 300 468 §6.2.43) — a flat run of
/// 5-byte EBU teletext page records.
pub fn teletext_descriptor(entries: &[TeletextEntry]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 5);
    for e in entries {
        body.extend_from_slice(&e.language_code);
        // teletext_type (5) | teletext_magazine_number (3).
        body.push(((e.teletext_type & 0x1F) << 3) | (e.teletext_magazine_number & 0x07));
        body.push(e.teletext_page_number);
    }
    tlv(0x56, &body)
}

/// `subtitling_descriptor` (tag `0x59`, EN 300 468 §6.2.41) — a flat run
/// of 8-byte DVB subtitle service records.
pub fn subtitling_descriptor(entries: &[SubtitlingEntry]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 8);
    for e in entries {
        body.extend_from_slice(&e.language_code);
        body.push(e.subtitling_type);
        body.extend_from_slice(&e.composition_page_id.to_be_bytes());
        body.extend_from_slice(&e.ancillary_page_id.to_be_bytes());
    }
    tlv(0x59, &body)
}

/// Shared body builder for the AC-3 (`0x6A`) and E-AC-3 (`0x7A`) flag /
/// optional-field layout (EN 300 468 annex D Table D.6 / D.7). The four
/// most-significant flag bits gate the four optional bytes; `mixinfoexists`
/// (E-AC-3 only) rides bit 3 and is passed as part of `extra_flag_bits`.
fn ac3_family_body(
    component_type: Option<u8>,
    bsid: Option<u8>,
    mainid: Option<u8>,
    asvc: Option<u8>,
    extra_flag_bits: u8,
    tail: &[u8],
) -> Vec<u8> {
    let mut flags = extra_flag_bits & 0x0F;
    if component_type.is_some() {
        flags |= 0b1000_0000;
    }
    if bsid.is_some() {
        flags |= 0b0100_0000;
    }
    if mainid.is_some() {
        flags |= 0b0010_0000;
    }
    if asvc.is_some() {
        flags |= 0b0001_0000;
    }
    let mut body = vec![flags];
    for opt in [component_type, bsid, mainid, asvc].into_iter().flatten() {
        body.push(opt);
    }
    body.extend_from_slice(tail);
    body
}

/// `AC-3_descriptor` (tag `0x6A`, EN 300 468 annex D Table D.6).
pub fn ac3_descriptor(
    component_type: Option<u8>,
    bsid: Option<u8>,
    mainid: Option<u8>,
    asvc: Option<u8>,
    additional_info: &[u8],
) -> Vec<u8> {
    let body = ac3_family_body(component_type, bsid, mainid, asvc, 0, additional_info);
    tlv(0x6A, &body)
}

/// `enhanced_AC-3_descriptor` (tag `0x7A`, EN 300 468 annex D Table D.7).
/// The three independent-substream flags plus `mixinfoexists` map onto the
/// low nibble of the flags byte per the demuxer's decode.
pub fn enhanced_ac3_descriptor(
    component_type: Option<u8>,
    bsid: Option<u8>,
    mainid: Option<u8>,
    asvc: Option<u8>,
    mixinfoexists: bool,
    additional_info: &[u8],
) -> Vec<u8> {
    let extra = if mixinfoexists { 0b0000_1000 } else { 0 };
    let body = ac3_family_body(component_type, bsid, mainid, asvc, extra, additional_info);
    tlv(0x7A, &body)
}

/// `DTS_descriptor` (tag `0x7B`, EN 300 468 annex G Table G.1). The body
/// is passed verbatim — the fixed DTS parameter layout is the caller's to
/// assemble — so a demuxer that surfaces it as raw selector bytes reads
/// back identically.
pub fn dts_descriptor(body: &[u8]) -> Vec<u8> {
    tlv(0x7B, body)
}

/// `AAC_descriptor` (tag `0x7C`, EN 300 468 annex H Table H.1).
pub fn aac_descriptor(
    profile_and_level: u8,
    aac_type: Option<u8>,
    saoc_de: bool,
    additional_info: &[u8],
) -> Vec<u8> {
    let mut body = vec![profile_and_level];
    // The flags byte is only emitted when a second-level field follows —
    // the decoder treats a 1-byte body as "profile only".
    if aac_type.is_some() || saoc_de || !additional_info.is_empty() {
        let mut flags = 0u8;
        if aac_type.is_some() {
            flags |= 0b1000_0000;
        }
        if saoc_de {
            flags |= 0b0100_0000;
        }
        body.push(flags);
        if let Some(t) = aac_type {
            body.push(t);
        }
        body.extend_from_slice(additional_info);
    }
    tlv(0x7C, &body)
}

/// Generic descriptor TLV — wrap arbitrary body bytes under a caller's
/// `descriptor_tag`. The escape hatch for tags without a dedicated
/// builder; the body is truncated to the 255-byte `descriptor_length`
/// ceiling like every other builder.
pub fn raw_descriptor(tag: u8, body: &[u8]) -> Vec<u8> {
    tlv(tag, body)
}

/// `CA_descriptor` (tag `0x09`, ISO/IEC 13818-1 §2.6.16 Table 2-50) —
/// the `CA_system_ID` plus the 13-bit `CA_PID` carrying the ECM (PMT
/// placement) or EMM (CAT placement) stream, plus private data.
pub fn ca_descriptor(ca_system_id: u16, ca_pid: u16, private_data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + private_data.len());
    body.extend_from_slice(&ca_system_id.to_be_bytes());
    body.push(0b1110_0000 | ((ca_pid >> 8) & 0x1F) as u8);
    body.push((ca_pid & 0xFF) as u8);
    body.extend_from_slice(private_data);
    tlv(0x09, &body)
}

/// `stuffing_descriptor` (tag `0x42`, EN 300 468 §6.2.40) — `len` bytes
/// of `0xFF` padding (the `stuffing_byte` run carries no meaning).
pub fn stuffing_descriptor(len: u8) -> Vec<u8> {
    tlv(0x42, &vec![0xFF; len as usize])
}

/// `extended_event_descriptor` (tag `0x4E`, EN 300 468 §6.2.15) — the
/// long-form EIT event synopsis: the `descriptor_number` /
/// `last_descriptor_number` association pair, the language code, the
/// two-column `(item_description, item)` list, and the non-itemized
/// free text. Item / text runs are raw DVB text-string bytes (annex A
/// charset selection is the caller's). Over-long items or text are
/// truncated to their 8-bit length prefixes; a body pushing the
/// descriptor past 255 bytes is truncated by the TLV envelope, so
/// callers splitting a long synopsis across an associated set should
/// size each descriptor's content themselves.
pub fn extended_event_descriptor(
    descriptor_number: u8,
    last_descriptor_number: u8,
    language_code: [u8; 3],
    items: &[(&[u8], &[u8])],
    text: &[u8],
) -> Vec<u8> {
    let mut item_loop = Vec::new();
    for (description, item) in items {
        let dl = description.len().min(0xFF);
        item_loop.push(dl as u8);
        item_loop.extend_from_slice(&description[..dl]);
        let il = item.len().min(0xFF);
        item_loop.push(il as u8);
        item_loop.extend_from_slice(&item[..il]);
    }
    let ill = item_loop.len().min(0xFF);
    item_loop.truncate(ill);
    let tl = text.len().min(0xFF);
    let mut body = Vec::with_capacity(5 + ill + tl);
    body.push((descriptor_number << 4) | (last_descriptor_number & 0x0F));
    body.extend_from_slice(&language_code);
    body.push(ill as u8);
    body.extend_from_slice(&item_loop);
    body.push(tl as u8);
    body.extend_from_slice(&text[..tl]);
    tlv(0x4E, &body)
}

/// `content_descriptor` (tag `0x54`, EN 300 468 §6.2.9) — the per-event
/// genre classification: a flat run of `(content_nibble_level_1,
/// content_nibble_level_2, user_byte)` triples (Table 29 indexes the
/// two nibbles).
pub fn content_descriptor(entries: &[(u8, u8, u8)]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 2);
    for (level_1, level_2, user_byte) in entries {
        body.push((level_1 << 4) | (level_2 & 0x0F));
        body.push(*user_byte);
    }
    tlv(0x54, &body)
}

/// `parental_rating_descriptor` (tag `0x55`, EN 300 468 §6.2.28) — a
/// flat run of `(country_code, rating)` records (Table 83: `0x01..=0x0F`
/// codes minimum age `rating + 3`).
pub fn parental_rating_descriptor(entries: &[([u8; 3], u8)]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 4);
    for (country_code, rating) in entries {
        body.extend_from_slice(country_code);
        body.push(*rating);
    }
    tlv(0x55, &body)
}

/// One country entry for a `local_time_offset_descriptor` (write-side
/// mirror of [`crate::descriptor::LocalTimeOffsetEntry`], minus the raw
/// MJD bookkeeping the parser preserves).
#[derive(Debug, Clone, Copy)]
pub struct LocalTimeOffsetSpec {
    /// 3-byte ISO 3166 alpha-3 country code (e.g. `b"GBR"`).
    pub country_code: [u8; 3],
    /// 6-bit `country_region_id` (`0` = no time-zone subdivision).
    pub country_region_id: u8,
    /// `local_time_offset_polarity` — `true` when local time is behind
    /// UTC (negative offset). Applies to both offsets.
    pub offset_negative: bool,
    /// Current offset in whole minutes (encoded as BCD `HHMM`).
    pub local_time_offset_minutes: u16,
    /// The UTC instant at which the offset changes; `None` encodes the
    /// all-ones sentinel.
    pub time_of_change: Option<EitDateTime>,
    /// Offset in force after `time_of_change`, in whole minutes.
    pub next_time_offset_minutes: u16,
}

/// Encode a whole-minutes offset as the §6.2.20 16-bit BCD `HHMM` pair.
fn bcd_hhmm(minutes: u16) -> [u8; 2] {
    [to_bcd((minutes / 60) as u8), to_bcd((minutes % 60) as u8)]
}

/// `local_time_offset_descriptor` (tag `0x58`, EN 300 468 §6.2.20
/// Table 69) — per-country local-time-offset entries, 13 bytes each.
pub fn local_time_offset_descriptor(entries: &[LocalTimeOffsetSpec]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 13);
    for e in entries {
        body.extend_from_slice(&e.country_code);
        // country_region_id (6) | reserved_future_use (1) | polarity (1).
        body.push((e.country_region_id << 2) | 0b10 | u8::from(e.offset_negative));
        body.extend_from_slice(&bcd_hhmm(e.local_time_offset_minutes));
        body.extend_from_slice(&encode_utc_time(e.time_of_change));
        body.extend_from_slice(&bcd_hhmm(e.next_time_offset_minutes));
    }
    tlv(0x58, &body)
}

/// `partial_transport_stream_descriptor` (tag `0x63`, EN 300 468 §7.2.1
/// Table 165) — the SIT transmission-info descriptor carrying the
/// partial-TS play-out rates: 22-bit `peak_rate` and
/// `minimum_overall_smoothing_rate` (units of 400 bit/s; all-ones =
/// undefined) plus the 14-bit `maximum_overall_smoothing_buffer` (bytes;
/// all-ones = undefined). Values are masked to their field widths.
pub fn partial_transport_stream_descriptor(
    peak_rate: u32,
    minimum_overall_smoothing_rate: u32,
    maximum_overall_smoothing_buffer: u16,
) -> Vec<u8> {
    let pr = peak_rate & 0x3F_FFFF;
    let sr = minimum_overall_smoothing_rate & 0x3F_FFFF;
    let sb = maximum_overall_smoothing_buffer & 0x3FFF;
    let body = [
        0b1100_0000 | (pr >> 16) as u8,
        (pr >> 8) as u8,
        pr as u8,
        0b1100_0000 | (sr >> 16) as u8,
        (sr >> 8) as u8,
        sr as u8,
        0b1100_0000 | (sb >> 8) as u8,
        sb as u8,
    ];
    tlv(0x63, &body)
}

// ---------------------------------------------------------------------------
// Long-form PSI section envelope
// ---------------------------------------------------------------------------

/// Assemble a long-form PSI section: `table_id`, the
/// `section_syntax_indicator` / `section_length` word, the 5-byte fixed
/// tail (`table_id_extension`, `version` / `current_next`,
/// `section_number`, `last_section_number`), the caller's body, and the
/// MPEG-2 CRC-32 trailer.
///
/// `section_length` counts every byte after itself — the 5-byte fixed
/// tail + body + 4-byte CRC — per §2.4.4.
fn long_section(
    table_id: u8,
    table_id_extension: u16,
    version: u8,
    current_next: bool,
    section_number: u8,
    last_section_number: u8,
    body: &[u8],
) -> Vec<u8> {
    let section_length = 5 + body.len() + 4;
    let mut s = Vec::with_capacity(3 + section_length);
    s.push(table_id);
    // section_syntax_indicator=1, '0', reserved=0b11, section_length high.
    s.push(0b1011_0000 | ((section_length >> 8) & 0x0F) as u8);
    s.push((section_length & 0xFF) as u8);
    s.extend_from_slice(&table_id_extension.to_be_bytes());
    // reserved=0b11, version_number (5), current_next_indicator (1).
    s.push(0b1100_0000 | ((version & 0x1F) << 1) | u8::from(current_next));
    s.push(section_number);
    s.push(last_section_number);
    s.extend_from_slice(body);
    let crc = mpeg2_crc32(&s);
    s.extend_from_slice(&crc.to_be_bytes());
    s
}

/// Build a Program Association Table section (§2.4.4.3). `programs` is a
/// list of `(program_number, pmt_pid)` entries; a `program_number` of `0`
/// designates the `network_PID`.
pub fn build_pat(transport_stream_id: u16, version: u8, programs: &[(u16, u16)]) -> Vec<u8> {
    let mut body = Vec::with_capacity(programs.len() * 4);
    for (program_number, pid) in programs {
        body.extend_from_slice(&program_number.to_be_bytes());
        body.push(0b1110_0000 | ((pid >> 8) & 0x1F) as u8);
        body.push((pid & 0xFF) as u8);
    }
    long_section(
        PAT_TABLE_ID,
        transport_stream_id,
        version,
        true,
        0,
        0,
        &body,
    )
}

/// One elementary-stream entry of a PMT: `stream_type`, `elementary_PID`,
/// and the pre-built `ES_info` descriptor loop (concatenated descriptor
/// TLVs — see the `*_descriptor` builders).
#[derive(Debug, Clone)]
pub struct PmtStreamEntry {
    /// ISO/IEC 13818-1 Table 2-29 `stream_type`.
    pub stream_type: u8,
    /// 13-bit `elementary_PID`.
    pub elementary_pid: u16,
    /// Pre-assembled `ES_info` descriptor loop bytes.
    pub es_info: Vec<u8>,
}

/// Build a Program Map Table section (§2.4.4.8) for one program.
/// `program_info` is the program-level descriptor loop (may be empty).
pub fn build_pmt(
    program_number: u16,
    version: u8,
    pcr_pid: u16,
    program_info: &[u8],
    streams: &[PmtStreamEntry],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0b1110_0000 | ((pcr_pid >> 8) & 0x1F) as u8);
    body.push((pcr_pid & 0xFF) as u8);
    let pil = program_info.len().min(0x0FFF) as u16;
    body.push(0b1111_0000 | ((pil >> 8) & 0x0F) as u8);
    body.push((pil & 0xFF) as u8);
    body.extend_from_slice(&program_info[..pil as usize]);
    for st in streams {
        body.push(st.stream_type);
        body.push(0b1110_0000 | ((st.elementary_pid >> 8) & 0x1F) as u8);
        body.push((st.elementary_pid & 0xFF) as u8);
        let el = st.es_info.len().min(0x0FFF) as u16;
        body.push(0b1111_0000 | ((el >> 8) & 0x0F) as u8);
        body.push((el & 0xFF) as u8);
        body.extend_from_slice(&st.es_info[..el as usize]);
    }
    long_section(PMT_TABLE_ID, program_number, version, true, 0, 0, &body)
}

/// One service entry for a Service Description Table (EN 300 468 §5.2.3).
#[derive(Debug, Clone)]
pub struct SdtServiceEntry {
    /// 16-bit `service_id` (equals the PMT `program_number`).
    pub service_id: u16,
    /// `EIT_schedule_flag`.
    pub eit_schedule: bool,
    /// `EIT_present_following_flag`.
    pub eit_present_following: bool,
    /// 3-bit `running_status`.
    pub running_status: RunningStatus,
    /// `free_CA_mode`.
    pub free_ca_mode: bool,
    /// Per-service descriptor loop (typically a `service_descriptor`).
    pub descriptors: Vec<u8>,
}

/// Build a DVB Service Description Table section (EN 300 468 §5.2.3).
/// `actual` selects `table_id` `0x42` (this TS) vs `0x46` (another TS).
pub fn build_sdt(
    actual: bool,
    transport_stream_id: u16,
    original_network_id: u16,
    version: u8,
    services: &[SdtServiceEntry],
) -> Vec<u8> {
    let table_id = if actual {
        SDT_ACTUAL_TABLE_ID
    } else {
        SDT_OTHER_TABLE_ID
    };
    let mut body = Vec::new();
    body.extend_from_slice(&original_network_id.to_be_bytes());
    body.push(0xFF); // reserved_future_use
    for svc in services {
        body.extend_from_slice(&svc.service_id.to_be_bytes());
        // reserved_future_use (6) | EIT_schedule_flag | EIT_present_following.
        let mut b = 0b1111_1100u8;
        if svc.eit_schedule {
            b |= 0b10;
        }
        if svc.eit_present_following {
            b |= 0b01;
        }
        body.push(b);
        let dlen = svc.descriptors.len().min(0x0FFF) as u16;
        // running_status (3) | free_CA_mode (1) | descriptors_length high (4).
        body.push(
            (svc.running_status.to_bits() << 5)
                | (u8::from(svc.free_ca_mode) << 4)
                | ((dlen >> 8) & 0x0F) as u8,
        );
        body.push((dlen & 0xFF) as u8);
        body.extend_from_slice(&svc.descriptors[..dlen as usize]);
    }
    long_section(table_id, transport_stream_id, version, true, 0, 0, &body)
}

/// One `transport_stream_loop` entry for a NIT (EN 300 468 §5.2.1).
#[derive(Debug, Clone)]
pub struct NitTsEntry {
    /// 16-bit `transport_stream_id`.
    pub transport_stream_id: u16,
    /// 16-bit `original_network_id`.
    pub original_network_id: u16,
    /// Per-TS descriptor loop (delivery-system / service_list, etc.).
    pub descriptors: Vec<u8>,
}

/// Build a DVB Network Information Table section (EN 300 468 §5.2.1).
/// `actual` selects `table_id` `0x40` (actual network) vs `0x41` (other).
pub fn build_nit(
    actual: bool,
    network_id: u16,
    version: u8,
    network_descriptors: &[u8],
    transport_streams: &[NitTsEntry],
) -> Vec<u8> {
    let table_id = if actual {
        NIT_ACTUAL_TABLE_ID
    } else {
        NIT_OTHER_TABLE_ID
    };
    let mut ts_loop = Vec::new();
    for ts in transport_streams {
        ts_loop.extend_from_slice(&ts.transport_stream_id.to_be_bytes());
        ts_loop.extend_from_slice(&ts.original_network_id.to_be_bytes());
        let dlen = ts.descriptors.len().min(0x0FFF) as u16;
        ts_loop.push(0b1111_0000 | ((dlen >> 8) & 0x0F) as u8);
        ts_loop.push((dlen & 0xFF) as u8);
        ts_loop.extend_from_slice(&ts.descriptors[..dlen as usize]);
    }
    let ndl = network_descriptors.len().min(0x0FFF) as u16;
    let tsll = ts_loop.len().min(0x0FFF) as u16;
    let mut body = Vec::new();
    body.push(0b1111_0000 | ((ndl >> 8) & 0x0F) as u8);
    body.push((ndl & 0xFF) as u8);
    body.extend_from_slice(&network_descriptors[..ndl as usize]);
    body.push(0b1111_0000 | ((tsll >> 8) & 0x0F) as u8);
    body.push((tsll & 0xFF) as u8);
    body.extend_from_slice(&ts_loop);
    long_section(table_id, network_id, version, true, 0, 0, &body)
}

/// One event entry for a present/following EIT (EN 300 468 §5.2.4).
#[derive(Debug, Clone)]
pub struct EitEventEntry {
    /// 16-bit `event_id`.
    pub event_id: u16,
    /// Decoded start time, or `None` for the all-ones undefined sentinel.
    pub start_time: Option<EitDateTime>,
    /// Event duration (BCD hours/minutes/seconds).
    pub duration: EitDuration,
    /// 3-bit `running_status`.
    pub running_status: RunningStatus,
    /// `free_CA_mode`.
    pub free_ca_mode: bool,
    /// Per-event descriptor loop (typically a `short_event_descriptor`).
    pub descriptors: Vec<u8>,
}

/// Build a DVB present/following Event Information Table section
/// (EN 300 468 §5.2.4). `actual` selects `table_id` `0x4E` (this TS) vs
/// `0x4F` (another TS).
pub fn build_eit_pf(
    actual: bool,
    service_id: u16,
    transport_stream_id: u16,
    original_network_id: u16,
    version: u8,
    events: &[EitEventEntry],
) -> Vec<u8> {
    let table_id = if actual {
        EIT_ACTUAL_PF_TABLE_ID
    } else {
        EIT_OTHER_PF_TABLE_ID
    };
    let mut body = Vec::new();
    body.extend_from_slice(&transport_stream_id.to_be_bytes());
    body.extend_from_slice(&original_network_id.to_be_bytes());
    // For an unsegmented present/following sub_table both fields equal the
    // section's own last_section_number / table_id.
    body.push(0); // segment_last_section_number
    body.push(table_id); // last_table_id
    for ev in events {
        body.extend_from_slice(&ev.event_id.to_be_bytes());
        body.extend_from_slice(&encode_utc_time(ev.start_time));
        body.push(to_bcd(ev.duration.hours));
        body.push(to_bcd(ev.duration.minutes));
        body.push(to_bcd(ev.duration.seconds));
        let dlen = ev.descriptors.len().min(0x0FFF) as u16;
        body.push(
            (ev.running_status.to_bits() << 5)
                | (u8::from(ev.free_ca_mode) << 4)
                | ((dlen >> 8) & 0x0F) as u8,
        );
        body.push((dlen & 0xFF) as u8);
        body.extend_from_slice(&ev.descriptors[..dlen as usize]);
    }
    long_section(table_id, service_id, version, true, 0, 0, &body)
}

/// Build a Conditional Access Table section (§2.4.4.6 Table 2-27). The
/// body is one `descriptor()` loop — normally `CA_descriptor`s (see
/// [`ca_descriptor`]) pointing at the EMM PIDs. The 18 reserved bits in
/// the `table_id_extension` slot are transmitted as `1`s.
pub fn build_cat(version: u8, descriptors: &[u8]) -> Vec<u8> {
    long_section(CAT_TABLE_ID, 0xFFFF, version, true, 0, 0, descriptors)
}

/// Build a Transport Stream Description Table section (§2.4.4.12
/// Table 2-30-1) — a TS-wide `descriptor()` loop on PID `0x0002`,
/// structurally the CAT's twin.
pub fn build_tsdt(version: u8, descriptors: &[u8]) -> Vec<u8> {
    long_section(TSDT_TABLE_ID, 0xFFFF, version, true, 0, 0, descriptors)
}

/// Build a DVB Bouquet Association Table section (EN 300 468 §5.2.2).
/// The body is byte-for-byte the NIT shape — a bouquet-level descriptor
/// loop then a `transport_stream_loop` — keyed by `bouquet_id` in the
/// `table_id_extension` slot; [`NitTsEntry`] doubles as the BAT's TS
/// entry.
pub fn build_bat(
    bouquet_id: u16,
    version: u8,
    bouquet_descriptors: &[u8],
    transport_streams: &[NitTsEntry],
) -> Vec<u8> {
    let mut ts_loop = Vec::new();
    for ts in transport_streams {
        ts_loop.extend_from_slice(&ts.transport_stream_id.to_be_bytes());
        ts_loop.extend_from_slice(&ts.original_network_id.to_be_bytes());
        let dlen = ts.descriptors.len().min(0x0FFF) as u16;
        ts_loop.push(0b1111_0000 | ((dlen >> 8) & 0x0F) as u8);
        ts_loop.push((dlen & 0xFF) as u8);
        ts_loop.extend_from_slice(&ts.descriptors[..dlen as usize]);
    }
    let bdl = bouquet_descriptors.len().min(0x0FFF) as u16;
    let tsll = ts_loop.len().min(0x0FFF) as u16;
    let mut body = Vec::new();
    body.push(0b1111_0000 | ((bdl >> 8) & 0x0F) as u8);
    body.push((bdl & 0xFF) as u8);
    body.extend_from_slice(&bouquet_descriptors[..bdl as usize]);
    body.push(0b1111_0000 | ((tsll >> 8) & 0x0F) as u8);
    body.push((tsll & 0xFF) as u8);
    body.extend_from_slice(&ts_loop);
    long_section(BAT_TABLE_ID, bouquet_id, version, true, 0, 0, &body)
}

/// One service entry for a Selection Information Table (EN 300 468
/// §7.1.2 Table 164).
#[derive(Debug, Clone)]
pub struct SitServiceEntry {
    /// 16-bit `service_id` (equals the PMT `program_number`).
    pub service_id: u16,
    /// 3-bit `running_status` of the original present event.
    pub running_status: RunningStatus,
    /// Per-service descriptor loop.
    pub descriptors: Vec<u8>,
}

/// Build a DVB Selection Information Table section (EN 300 468 §5.2.10 /
/// §7.1.2 Table 164) — the partial-TS description: a transmission-info
/// descriptor loop (usually a [`partial_transport_stream_descriptor`])
/// plus per-service entries. `section_number` / `last_section_number`
/// are fixed at `0` per §7.1.2; the `table_id_extension` bits are
/// reserved and transmitted as `1`s.
pub fn build_sit(
    version: u8,
    transmission_info_descriptors: &[u8],
    services: &[SitServiceEntry],
) -> Vec<u8> {
    let til = transmission_info_descriptors.len().min(0x0FFF) as u16;
    let mut body = Vec::new();
    body.push(0b1111_0000 | ((til >> 8) & 0x0F) as u8);
    body.push((til & 0xFF) as u8);
    body.extend_from_slice(&transmission_info_descriptors[..til as usize]);
    for svc in services {
        body.extend_from_slice(&svc.service_id.to_be_bytes());
        let dlen = svc.descriptors.len().min(0x0FFF) as u16;
        // reserved_future_use (1) | running_status (3) | length high (4).
        body.push(0b1000_0000 | (svc.running_status.to_bits() << 4) | ((dlen >> 8) & 0x0F) as u8);
        body.push((dlen & 0xFF) as u8);
        body.extend_from_slice(&svc.descriptors[..dlen as usize]);
    }
    long_section(SIT_TABLE_ID, 0xFFFF, version, true, 0, 0, &body)
}

// ---------------------------------------------------------------------------
// Short-form DVB SI section envelope
// ---------------------------------------------------------------------------

/// Assemble a short-form DVB SI section (`section_syntax_indicator == 0`,
/// EN 300 468 §5.2.5–§5.2.9): `table_id`, the syntax/length word, and the
/// caller's body verbatim (any CRC is the caller's to append inside
/// `body`). `syntax` sets the `section_syntax_indicator` bit — only the
/// ST may legally carry `1` here.
fn short_section(table_id: u8, syntax: bool, body: &[u8]) -> Vec<u8> {
    let section_length = body.len().min(0x0FFD);
    let mut s = Vec::with_capacity(3 + section_length);
    s.push(table_id);
    // section_syntax_indicator | reserved_future_use=1 | reserved=0b11 |
    // section_length high.
    s.push((u8::from(syntax) << 7) | 0b0111_0000 | ((section_length >> 8) & 0x0F) as u8);
    s.push((section_length & 0xFF) as u8);
    s.extend_from_slice(&body[..section_length]);
    s
}

/// Build a DVB Time and Date Table section (EN 300 468 §5.2.5 Table 8) —
/// a short-form section whose whole body is the 40-bit MJD + BCD
/// `UTC_time`. `None` encodes the all-ones sentinel.
pub fn build_tdt(utc_time: Option<EitDateTime>) -> Vec<u8> {
    short_section(TDT_TABLE_ID, false, &encode_utc_time(utc_time))
}

/// Build a DVB Time Offset Table section (EN 300 468 §5.2.6 Table 9) —
/// the TDT plus a descriptor loop (normally a
/// [`local_time_offset_descriptor`]) and a CRC-32 trailer.
pub fn build_tot(utc_time: Option<EitDateTime>, descriptors: &[u8]) -> Vec<u8> {
    let dlen = descriptors.len().min(0x0FFF);
    let mut body = Vec::with_capacity(5 + 2 + dlen + 4);
    body.extend_from_slice(&encode_utc_time(utc_time));
    body.push(0b1111_0000 | ((dlen >> 8) & 0x0F) as u8);
    body.push((dlen & 0xFF) as u8);
    body.extend_from_slice(&descriptors[..dlen]);
    // Reserve the CRC's four bytes inside section_length, then compute it
    // over table_id .. the byte before the CRC slot.
    body.extend_from_slice(&[0; 4]);
    let mut s = short_section(TOT_TABLE_ID, false, &body);
    let crc_pos = s.len() - 4;
    let crc = mpeg2_crc32(&s[..crc_pos]);
    s[crc_pos..].copy_from_slice(&crc.to_be_bytes());
    s
}

/// Build a DVB Running Status Table section (EN 300 468 §5.2.7
/// Table 10) — a short-form section whose body is a flat run of 9-byte
/// event-status entries, no CRC.
pub fn build_rst(entries: &[RstEntry]) -> Vec<u8> {
    let mut body = Vec::with_capacity(entries.len() * 9);
    for e in entries {
        body.extend_from_slice(&e.transport_stream_id.to_be_bytes());
        body.extend_from_slice(&e.original_network_id.to_be_bytes());
        body.extend_from_slice(&e.service_id.to_be_bytes());
        body.extend_from_slice(&e.event_id.to_be_bytes());
        // reserved_future_use (5) | running_status (3).
        body.push(0b1111_1000 | e.running_status.to_bits());
    }
    short_section(RST_TABLE_ID, false, &body)
}

/// Build a DVB Stuffing Table section (EN 300 468 §5.2.8 Table 11) —
/// `len` `data_byte`s of `0xFF` (their value carries no meaning). The
/// ST is the section-invalidation mechanism at a delivery-system
/// boundary; `section_syntax_indicator` may be either value, so it is
/// caller-selected.
pub fn build_st(section_syntax_indicator: bool, len: usize) -> Vec<u8> {
    short_section(
        ST_TABLE_ID,
        section_syntax_indicator,
        &vec![0xFF; len.min(0x0FFD)],
    )
}

/// Build a DVB Discontinuity Information Table section (EN 300 468
/// §5.2.9 / §7.1.1 Table 163) — the single `transition_flag` bit padded
/// with 7 `reserved_future_use` bits, `section_length` fixed at 1.
pub fn build_dit(transition_flag: bool) -> Vec<u8> {
    short_section(
        DIT_TABLE_ID,
        false,
        &[(u8::from(transition_flag) << 7) | 0b0111_1111],
    )
}

// ---------------------------------------------------------------------------
// DVB 40-bit MJD + BCD UTC_time encoding (inverse of decode_utc_time)
// ---------------------------------------------------------------------------

/// Encode a 0–99 integer into one 4-bit-BCD byte.
pub(crate) fn to_bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

/// Encode a Gregorian `(year, month, day)` into the 16-bit Modified
/// Julian Date, using the ETSI EN 300 468 annex-C forward integer
/// formula (the inverse of the arithmetic in
/// [`crate::psi::decode_utc_time`]):
///
/// ```text
/// L   = 1 if month == 1 or month == 2 else 0
/// MJD = 14956 + day + int((Y − L) × 365,25) + int((M + 1 + L × 12) × 30,6001)
/// ```
///
/// where `Y = year − 1900` and `M = month`.
pub(crate) fn encode_mjd(year: u16, month: u8, day: u8) -> u16 {
    let y = year as i64 - 1900;
    let m = month as i64;
    let l: i64 = if m == 1 || m == 2 { 1 } else { 0 };
    let mjd = 14956 + day as i64 + ((y - l) * 36525) / 100 + ((m + 1 + l * 12) * 306001) / 10000;
    mjd as u16
}

/// Encode an [`EitDateTime`] into the DVB 40-bit `UTC_time` field
/// (16-bit MJD + 24-bit BCD time). `None` produces the all-ones
/// "undefined" sentinel that [`crate::psi::decode_utc_time`] maps back to
/// `None`.
fn encode_utc_time(dt: Option<EitDateTime>) -> [u8; 5] {
    match dt {
        None => [0xFF; 5],
        Some(dt) => {
            let mjd = encode_mjd(dt.year, dt.month, dt.day);
            let [m0, m1] = mjd.to_be_bytes();
            [
                m0,
                m1,
                to_bcd(dt.hour),
                to_bcd(dt.minute),
                to_bcd(dt.second),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{iter_descriptors, DescriptorBody};
    use crate::psi::{
        EventInformationTable, NetworkInformationTable, ProgramAssociationTable, ProgramMapTable,
        ServiceDescriptionTable,
    };

    fn one_descriptor(bytes: &[u8]) -> DescriptorBody<'_> {
        iter_descriptors(bytes).next().unwrap().unwrap().body
    }

    #[test]
    fn registration_descriptor_round_trips() {
        let d = registration_descriptor(*b"HDMV", &[0x01, 0x02]);
        match one_descriptor(&d) {
            DescriptorBody::Registration {
                format_identifier,
                additional_identification_info,
            } => {
                assert_eq!(&format_identifier, b"HDMV");
                assert_eq!(additional_identification_info, &[0x01, 0x02]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn iso639_descriptor_round_trips() {
        let d = iso639_language_descriptor(&[(*b"eng", 0x00), (*b"fra", 0x03)]);
        match one_descriptor(&d) {
            DescriptorBody::Iso639Language(langs) => {
                assert_eq!(langs.len(), 2);
                assert_eq!(langs[0].language, *b"eng");
                assert_eq!(langs[1].language, *b"fra");
                assert_eq!(langs[1].audio_type, 0x03);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stream_identifier_round_trips() {
        let d = stream_identifier_descriptor(0x42);
        match one_descriptor(&d) {
            DescriptorBody::StreamIdentifier(s) => assert_eq!(s.component_tag, 0x42),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn short_event_descriptor_round_trips() {
        let d = short_event_descriptor(*b"eng", b"News", b"Evening bulletin");
        match one_descriptor(&d) {
            DescriptorBody::ShortEvent(s) => {
                assert_eq!(s.language_code, *b"eng");
                assert_eq!(s.event_name, b"News");
                assert_eq!(s.text, b"Evening bulletin");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn service_list_descriptor_round_trips() {
        let d = service_list_descriptor(&[(0x0064, 0x01), (0x0065, 0x02)]);
        match one_descriptor(&d) {
            DescriptorBody::ServiceList(s) => {
                assert_eq!(s.entries.len(), 2);
                assert_eq!(s.entries[0].service_id, 0x0064);
                assert_eq!(s.entries[1].service_type, 0x02);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn service_descriptor_round_trips() {
        let d = service_descriptor(0x19, b"OxideAV", b"Channel One");
        match one_descriptor(&d) {
            DescriptorBody::Service(s) => {
                assert_eq!(s.service_type, 0x19);
                assert_eq!(s.service_provider_name, b"OxideAV");
                assert_eq!(s.service_name, b"Channel One");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn teletext_descriptor_round_trips() {
        let entries = [
            TeletextEntry {
                language_code: *b"eng",
                teletext_type: 0x02,
                teletext_magazine_number: 0x05,
                teletext_page_number: 0x88,
            },
            TeletextEntry {
                language_code: *b"deu",
                teletext_type: 0x01,
                teletext_magazine_number: 0x01,
                teletext_page_number: 0x00,
            },
        ];
        let d = teletext_descriptor(&entries);
        match one_descriptor(&d) {
            DescriptorBody::Teletext(t) => assert_eq!(t.entries, entries),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn subtitling_descriptor_round_trips() {
        let entries = [SubtitlingEntry {
            language_code: *b"eng",
            subtitling_type: 0x10,
            composition_page_id: 0x0001,
            ancillary_page_id: 0x0002,
        }];
        let d = subtitling_descriptor(&entries);
        match one_descriptor(&d) {
            DescriptorBody::Subtitling(s) => assert_eq!(s.entries, entries),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ac3_descriptor_round_trips_all_optionals() {
        let d = ac3_descriptor(Some(0x42), Some(0x08), Some(0x01), Some(0xF0), &[0xAB]);
        match one_descriptor(&d) {
            DescriptorBody::Ac3(a) => {
                assert_eq!(a.component_type, Some(0x42));
                assert_eq!(a.bsid, Some(0x08));
                assert_eq!(a.mainid, Some(0x01));
                assert_eq!(a.asvc, Some(0xF0));
                assert_eq!(a.additional_info, &[0xAB]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ac3_descriptor_round_trips_partial_optionals() {
        let d = ac3_descriptor(Some(0x42), None, None, None, &[]);
        match one_descriptor(&d) {
            DescriptorBody::Ac3(a) => {
                assert_eq!(a.component_type, Some(0x42));
                assert_eq!(a.bsid, None);
                assert_eq!(a.mainid, None);
                assert_eq!(a.asvc, None);
                assert!(a.additional_info.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn eac3_descriptor_round_trips() {
        let d = enhanced_ac3_descriptor(Some(0x01), None, Some(0x02), None, true, &[]);
        match one_descriptor(&d) {
            DescriptorBody::EnhancedAc3(a) => {
                assert_eq!(a.component_type, Some(0x01));
                assert_eq!(a.bsid, None);
                assert_eq!(a.mainid, Some(0x02));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn aac_descriptor_round_trips_profile_only() {
        let d = aac_descriptor(0x51, None, false, &[]);
        match one_descriptor(&d) {
            DescriptorBody::Aac(a) => {
                assert_eq!(a.profile_and_level, 0x51);
                assert!(!a.aac_type_flag);
                assert_eq!(a.aac_type, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn aac_descriptor_round_trips_with_type() {
        let d = aac_descriptor(0x51, Some(0x03), true, &[0x99]);
        match one_descriptor(&d) {
            DescriptorBody::Aac(a) => {
                assert_eq!(a.profile_and_level, 0x51);
                assert!(a.aac_type_flag);
                assert!(a.saoc_de_flag);
                assert_eq!(a.aac_type, Some(0x03));
                assert_eq!(a.additional_info, &[0x99]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn pat_multi_program_round_trips() {
        let s = build_pat(0x1234, 5, &[(1, 0x0100), (2, 0x0200), (3, 0x0300)]);
        let pat = ProgramAssociationTable::parse(&s).unwrap();
        assert_eq!(pat.transport_stream_id, 0x1234);
        assert_eq!(pat.version_number, 5);
        assert_eq!(pat.programs, vec![(1, 0x0100), (2, 0x0200), (3, 0x0300)]);
    }

    #[test]
    fn pmt_with_descriptors_round_trips() {
        let streams = [
            PmtStreamEntry {
                stream_type: 0x1B,
                elementary_pid: 0x1011,
                es_info: Vec::new(),
            },
            PmtStreamEntry {
                stream_type: 0x81,
                elementary_pid: 0x1100,
                es_info: {
                    let mut v = iso639_language_descriptor(&[(*b"jpn", 0)]);
                    v.extend_from_slice(&ac3_descriptor(Some(0x42), None, None, None, &[]));
                    v
                },
            },
        ];
        let prog_info = registration_descriptor(*b"HDMV", &[]);
        let s = build_pmt(1, 2, 0x1011, &prog_info, &streams);
        let pmt = ProgramMapTable::parse(&s).unwrap();
        assert_eq!(pmt.program_number, 1);
        assert_eq!(pmt.version_number, 2);
        assert_eq!(pmt.pcr_pid, 0x1011);
        assert_eq!(pmt.streams.len(), 2);
        assert_eq!(pmt.streams[1].stream_type, 0x81);
        assert_eq!(pmt.streams[1].elementary_pid, 0x1100);
        // Program-info registration descriptor.
        let pd = pmt.iter_program_descriptors().next().unwrap().unwrap();
        assert!(matches!(pd.body, DescriptorBody::Registration { .. }));
        // ES-info descriptors on the AC-3 stream.
        let mut tags = Vec::new();
        for d in pmt.streams[1].iter_descriptors() {
            tags.push(d.unwrap().tag);
        }
        assert!(tags.contains(&0x0A));
        assert!(tags.contains(&0x6A));
    }

    #[test]
    fn sdt_round_trips() {
        let svc = SdtServiceEntry {
            service_id: 0x0064,
            eit_schedule: true,
            eit_present_following: true,
            running_status: RunningStatus::Running,
            free_ca_mode: false,
            descriptors: service_descriptor(0x01, b"Prov", b"Name"),
        };
        let s = build_sdt(true, 0x0001, 0x2024, 7, &[svc]);
        let sdt = ServiceDescriptionTable::parse(&s).unwrap();
        assert!(!sdt.other_transport_stream);
        assert_eq!(sdt.transport_stream_id, 0x0001);
        assert_eq!(sdt.original_network_id, 0x2024);
        assert_eq!(sdt.services.len(), 1);
        let e = &sdt.services[0];
        assert_eq!(e.service_id, 0x0064);
        assert!(e.eit_schedule_flag);
        assert_eq!(e.running_status, RunningStatus::Running);
        match e.iter_descriptors().next().unwrap().unwrap().body {
            DescriptorBody::Service(sv) => {
                assert_eq!(sv.service_name, b"Name");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nit_round_trips() {
        let ts = NitTsEntry {
            transport_stream_id: 0x0001,
            original_network_id: 0x2024,
            descriptors: Vec::new(),
        };
        let s = build_nit(
            true,
            0x1000,
            3,
            &network_name_descriptor(b"OxideNet"),
            &[ts],
        );
        let nit = NetworkInformationTable::parse(&s).unwrap();
        assert!(!nit.other_network);
        assert_eq!(nit.network_id, 0x1000);
        assert_eq!(nit.transport_streams.len(), 1);
        assert_eq!(nit.transport_streams[0].transport_stream_id, 0x0001);
        match nit.iter_descriptors().next().unwrap().unwrap().body {
            DescriptorBody::NetworkName(n) => assert_eq!(n.network_name, b"OxideNet"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn eit_pf_round_trips_with_time() {
        let dt = EitDateTime {
            year: 2003,
            month: 4,
            day: 27,
            hour: 12,
            minute: 45,
            second: 0,
            mjd: 0,
        };
        let ev = EitEventEntry {
            event_id: 0x0001,
            start_time: Some(dt),
            duration: EitDuration {
                hours: 1,
                minutes: 30,
                seconds: 0,
            },
            running_status: RunningStatus::Running,
            free_ca_mode: false,
            descriptors: Vec::new(),
        };
        let s = build_eit_pf(true, 0x0064, 0x0001, 0x2024, 1, &[ev]);
        let eit = EventInformationTable::parse(&s).unwrap();
        assert_eq!(eit.service_id, 0x0064);
        assert!(!eit.schedule);
        assert_eq!(eit.events.len(), 1);
        let e = &eit.events[0];
        assert_eq!(e.event_id, 0x0001);
        let st = e.start_time.unwrap();
        assert_eq!((st.year, st.month, st.day), (2003, 4, 27));
        assert_eq!((st.hour, st.minute, st.second), (12, 45, 0));
        assert_eq!(e.duration.as_seconds(), 5400);
    }

    #[test]
    fn eit_pf_undefined_start_time() {
        let ev = EitEventEntry {
            event_id: 0x0002,
            start_time: None,
            duration: EitDuration::default(),
            running_status: RunningStatus::Undefined,
            free_ca_mode: false,
            descriptors: Vec::new(),
        };
        let s = build_eit_pf(true, 0x0064, 0x0001, 0x2024, 0, &[ev]);
        let eit = EventInformationTable::parse(&s).unwrap();
        assert!(eit.events[0].start_time.is_none());
    }

    #[test]
    fn mjd_round_trips_against_decoder() {
        // A spread of dates the decoder should reproduce exactly.
        for &(y, m, d) in &[
            (1993u16, 1u8, 1u8),
            (2000, 2, 29),
            (2003, 4, 27),
            (2024, 12, 31),
            // The DVB MJD field is 16 bits, so the representable range
            // ends around 2038-04-22 (MJD 65535); stay inside it.
            (2037, 6, 1),
        ] {
            let mjd = encode_mjd(y, m, d);
            let decoded =
                crate::psi::decode_utc_time([mjd.to_be_bytes()[0], mjd.to_be_bytes()[1], 0, 0, 0])
                    .unwrap();
            assert_eq!((decoded.year, decoded.month, decoded.day), (y, m, d));
        }
    }

    #[test]
    fn ca_descriptor_round_trips() {
        let d = ca_descriptor(0x0B00, 0x1F00, &[0xDE, 0xAD]);
        match one_descriptor(&d) {
            DescriptorBody::Ca(ca) => {
                assert_eq!(ca.ca_system_id, 0x0B00);
                assert_eq!(ca.ca_pid, 0x1F00);
                assert_eq!(ca.private_data, &[0xDE, 0xAD]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stuffing_descriptor_round_trips() {
        let d = stuffing_descriptor(3);
        match one_descriptor(&d) {
            DescriptorBody::Stuffing(s) => assert_eq!(s.stuffing_bytes, &[0xFF, 0xFF, 0xFF]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn extended_event_descriptor_round_trips() {
        let d = extended_event_descriptor(
            1,
            2,
            *b"eng",
            &[(b"Director", b"A. Person"), (b"Year", b"1999")],
            b"A long synopsis.",
        );
        match one_descriptor(&d) {
            DescriptorBody::ExtendedEvent(e) => {
                assert_eq!(e.descriptor_number, 1);
                assert_eq!(e.last_descriptor_number, 2);
                assert_eq!(e.language_code, *b"eng");
                assert_eq!(e.items.len(), 2);
                assert_eq!(e.items[0].item_description, b"Director");
                assert_eq!(e.items[0].item, b"A. Person");
                assert_eq!(e.items[1].item_description, b"Year");
                assert_eq!(e.text, b"A long synopsis.");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn content_descriptor_round_trips() {
        let d = content_descriptor(&[(0x1, 0x4, 0x00), (0x4, 0x3, 0xAB)]);
        match one_descriptor(&d) {
            DescriptorBody::Content(c) => {
                assert_eq!(c.entries.len(), 2);
                assert_eq!((c.entries[0].level_1, c.entries[0].level_2), (0x1, 0x4));
                assert_eq!(c.entries[1].user_byte, 0xAB);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parental_rating_descriptor_round_trips() {
        let d = parental_rating_descriptor(&[(*b"FRA", 0x09), (*b"GBR", 0x00)]);
        match one_descriptor(&d) {
            DescriptorBody::ParentalRating(p) => {
                assert_eq!(p.entries.len(), 2);
                assert_eq!(p.entries[0].country_code, *b"FRA");
                assert_eq!(p.entries[0].rating, 0x09);
                assert_eq!(p.entries[0].minimum_age_years(), Some(12));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn local_time_offset_descriptor_round_trips() {
        let change = EitDateTime {
            year: 2026,
            month: 10,
            day: 25,
            hour: 1,
            minute: 0,
            second: 0,
            mjd: 0,
        };
        let spec = LocalTimeOffsetSpec {
            country_code: *b"GBR",
            country_region_id: 0,
            offset_negative: false,
            local_time_offset_minutes: 60,
            time_of_change: Some(change),
            next_time_offset_minutes: 0,
        };
        let d = local_time_offset_descriptor(&[spec]);
        match one_descriptor(&d) {
            DescriptorBody::LocalTimeOffset(l) => {
                assert_eq!(l.entries.len(), 1);
                let e = &l.entries[0];
                assert_eq!(e.country_code, *b"GBR");
                assert!(!e.offset_negative);
                assert_eq!(e.local_time_offset_minutes, 60);
                assert_eq!(e.next_time_offset_minutes, 0);
                let t = e.time_of_change.unwrap();
                assert_eq!((t.year, t.month, t.day, t.hour), (2026, 10, 25, 1));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn partial_transport_stream_descriptor_round_trips() {
        let d = partial_transport_stream_descriptor(20_000, 15_000, 1_400);
        match one_descriptor(&d) {
            DescriptorBody::PartialTransportStream(p) => {
                assert_eq!(p.peak_rate, 20_000);
                assert_eq!(p.minimum_overall_smoothing_rate, 15_000);
                assert_eq!(p.maximum_overall_smoothing_buffer, 1_400);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cat_round_trips() {
        let s = build_cat(4, &ca_descriptor(0x0B00, 0x1F00, &[]));
        let cat = crate::psi::ConditionalAccessTable::parse(&s).unwrap();
        assert_eq!(cat.version_number, 4);
        match cat.iter_descriptors().next().unwrap().unwrap().body {
            DescriptorBody::Ca(ca) => assert_eq!(ca.ca_pid, 0x1F00),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tsdt_round_trips() {
        let s = build_tsdt(1, &registration_descriptor(*b"OXAV", &[]));
        let tsdt = crate::psi::TransportStreamDescriptionTable::parse(&s).unwrap();
        assert_eq!(tsdt.version_number, 1);
        assert!(matches!(
            tsdt.iter_descriptors().next().unwrap().unwrap().body,
            DescriptorBody::Registration { .. }
        ));
    }

    #[test]
    fn bat_round_trips() {
        let ts = NitTsEntry {
            transport_stream_id: 0x0007,
            original_network_id: 0x2024,
            descriptors: service_list_descriptor(&[(0x0064, 0x01)]),
        };
        let s = build_bat(0x0042, 9, &bouquet_name_descriptor(b"Premium"), &[ts]);
        let bat = crate::psi::BouquetAssociationTable::parse(&s).unwrap();
        assert_eq!(bat.bouquet_id, 0x0042);
        assert_eq!(bat.version_number, 9);
        match bat.iter_descriptors().next().unwrap().unwrap().body {
            DescriptorBody::BouquetName(b) => assert_eq!(b.bouquet_name, b"Premium"),
            other => panic!("{other:?}"),
        }
        assert_eq!(bat.transport_streams.len(), 1);
        let e = &bat.transport_streams[0];
        assert_eq!(e.transport_stream_id, 0x0007);
        assert_eq!(e.original_network_id, 0x2024);
        assert!(matches!(
            e.iter_descriptors().next().unwrap().unwrap().body,
            DescriptorBody::ServiceList(_)
        ));
    }

    #[test]
    fn sit_round_trips() {
        let svc = SitServiceEntry {
            service_id: 0x0064,
            running_status: RunningStatus::Running,
            descriptors: service_descriptor(0x01, b"Prov", b"Name"),
        };
        let s = build_sit(
            2,
            &partial_transport_stream_descriptor(20_000, 0x3F_FFFF, 0x3FFF),
            &[svc],
        );
        let sit = crate::psi::SelectionInformationTable::parse(&s).unwrap();
        assert_eq!(sit.version_number, 2);
        match sit.iter_descriptors().next().unwrap().unwrap().body {
            DescriptorBody::PartialTransportStream(p) => {
                assert_eq!(p.peak_rate, 20_000);
                assert!(p.minimum_overall_smoothing_rate_undefined());
                assert!(p.maximum_overall_smoothing_buffer_undefined());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(sit.services.len(), 1);
        assert_eq!(sit.services[0].service_id, 0x0064);
        assert_eq!(sit.services[0].running_status, RunningStatus::Running);
        assert!(matches!(
            sit.services[0]
                .iter_descriptors()
                .next()
                .unwrap()
                .unwrap()
                .body,
            DescriptorBody::Service(_)
        ));
    }

    #[test]
    fn tdt_round_trips_spec_example() {
        // The EN 300 468 annex-C worked example: 1993-10-13 12:45:00.
        let dt = EitDateTime {
            year: 1993,
            month: 10,
            day: 13,
            hour: 12,
            minute: 45,
            second: 0,
            mjd: 0,
        };
        let s = build_tdt(Some(dt));
        assert_eq!(&s[3..8], &[0xC0, 0x79, 0x12, 0x45, 0x00]);
        let tdt = crate::psi::TimeDateTable::parse(&s).unwrap();
        let u = tdt.utc_time.unwrap();
        assert_eq!((u.year, u.month, u.day), (1993, 10, 13));
        assert_eq!((u.hour, u.minute, u.second), (12, 45, 0));
        // The all-ones sentinel round-trips to None.
        assert!(crate::psi::TimeDateTable::parse(&build_tdt(None))
            .unwrap()
            .utc_time
            .is_none());
    }

    #[test]
    fn tot_round_trips_with_offset_descriptor() {
        let dt = EitDateTime {
            year: 2026,
            month: 8,
            day: 18,
            hour: 6,
            minute: 30,
            second: 15,
            mjd: 0,
        };
        let spec = LocalTimeOffsetSpec {
            country_code: *b"JPN",
            country_region_id: 0,
            offset_negative: false,
            local_time_offset_minutes: 9 * 60,
            time_of_change: None,
            next_time_offset_minutes: 9 * 60,
        };
        let s = build_tot(Some(dt), &local_time_offset_descriptor(&[spec]));
        let tot = crate::psi::TimeOffsetTable::parse(&s).unwrap();
        let u = tot.utc_time.unwrap();
        assert_eq!((u.year, u.month, u.day), (2026, 8, 18));
        assert_eq!((u.hour, u.minute, u.second), (6, 30, 15));
        match tot.iter_descriptors().next().unwrap().unwrap().body {
            DescriptorBody::LocalTimeOffset(l) => {
                assert_eq!(l.entries[0].country_code, *b"JPN");
                assert_eq!(l.entries[0].local_time_offset_minutes, 540);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tot_crc_corruption_is_rejected() {
        let mut s = build_tot(None, &[]);
        let last = s.len() - 1;
        s[last] ^= 0xFF;
        assert!(crate::psi::TimeOffsetTable::parse(&s).is_err());
    }

    #[test]
    fn rst_round_trips() {
        let entries = [
            RstEntry {
                transport_stream_id: 1,
                original_network_id: 2,
                service_id: 3,
                event_id: 4,
                running_status: RunningStatus::Running,
            },
            RstEntry {
                transport_stream_id: 5,
                original_network_id: 6,
                service_id: 7,
                event_id: 8,
                running_status: RunningStatus::NotRunning,
            },
        ];
        let s = build_rst(&entries);
        let rst = crate::psi::RunningStatusTable::parse(&s).unwrap();
        assert_eq!(rst.entries, entries);
    }

    #[test]
    fn st_round_trips_both_syntax_forms() {
        for syntax in [false, true] {
            let s = build_st(syntax, 16);
            let st = crate::psi::StuffingTable::parse(&s).unwrap();
            assert_eq!(st.section_syntax_indicator, syntax);
            assert_eq!(st.data_bytes, vec![0xFF; 16]);
        }
    }

    #[test]
    fn dit_round_trips_both_flags() {
        for flag in [false, true] {
            let s = build_dit(flag);
            let dit = crate::psi::DiscontinuityInformationTable::parse(&s).unwrap();
            assert_eq!(dit.transition_flag, flag);
        }
    }
}
