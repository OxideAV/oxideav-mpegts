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
//!   (`table_id` through the CRC-32 trailer) for the PAT, PMT, SDT, NIT,
//!   and present/following EIT. The section is ready to hand to
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
    mpeg2_crc32, EitDateTime, EitDuration, RunningStatus, NIT_ACTUAL_TABLE_ID, NIT_OTHER_TABLE_ID,
    PAT_TABLE_ID, PMT_TABLE_ID, SDT_ACTUAL_TABLE_ID, SDT_OTHER_TABLE_ID,
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

// ---------------------------------------------------------------------------
// DVB 40-bit MJD + BCD UTC_time encoding (inverse of decode_utc_time)
// ---------------------------------------------------------------------------

/// Encode a 0–99 integer into one 4-bit-BCD byte.
fn to_bcd(v: u8) -> u8 {
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
fn encode_mjd(year: u16, month: u8, day: u8) -> u16 {
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
}
