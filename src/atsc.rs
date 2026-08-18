//! ATSC PSIP — the Program and System Information Protocol table
//! family per ATSC A/65:2013.
//!
//! PSIP is the ATSC (North-American terrestrial / cable broadcast)
//! counterpart of the DVB SI family in [`crate::psi`]: a hierarchy of
//! MPEG-2 `private_section`-derived tables that describe the virtual
//! channels, events, ratings, and system time of a transport stream.
//! Every PSIP section follows the A/65 §4.1 Table 4.1 generic format —
//! the ISO/IEC 13818-1 long-form section header, then a
//! `protocol_version` byte (zero in the current protocol), the
//! table-specific payload, and the MPEG-2 CRC-32 trailer.
//!
//! The base-PID tables (A/65 §5) ride the fixed PID [`ATSC_BASE_PID`]
//! (`0x1FFB`):
//!
//! | Table | `table_id` | Contents |
//! |-------|-----------|----------|
//! | [`SystemTimeTable`] (STT, §6.1) | `0xCD` | current time as GPS seconds + daylight-saving control |
//! | [`MasterGuideTable`] (MGT, §6.2) | `0xC7` | version / PID / size directory for all other PSIP tables |
//! | [`VirtualChannelTable`] (TVCT §6.3.1 / CVCT §6.3.2) | `0xC8` / `0xC9` | virtual-channel attributes (name, number, tuning, `source_id`) |
//! | [`RatingRegionTable`] (RRT, §6.4) | `0xCA` | rating-system dimensions / values for one region |
//!
//! The guide tables live on MGT-announced PIDs: up to 128
//! [`AtscEventInformationTable`]s (EIT-k, §6.5, `table_id 0xCB`) each
//! covering one 3-hour slot, and the [`ExtendedTextTable`]s (ETT, §6.6,
//! `table_id 0xCC`) carrying long descriptions keyed by `ETM_id`.
//!
//! The optional directed-channel-change pair also rides the base PID:
//! the [`DirectedChannelChangeTable`] (DCCT, §6.7, `table_id 0xD3`)
//! carries channel-change requests — per-test "from"/"to" virtual
//! channels, a GPS start/end window, and ANDed Table 6.17 selection
//! terms (postal code / demographic / genre / geographic tests, with
//! the [`dcc_demographic`] Table 6.18 bit assignments) — and the
//! [`DccSelectionCodeTable`] (DCCSCT, §6.8, `table_id 0xD4`) extends
//! the genre / state / county code sets those terms reference.
//!
//! Text in PSIP is never a bare byte run: titles, channel names, and
//! rating labels are all [`MultipleStringStructure`]s (§6.10) — a list
//! of per-language strings, each a run of segments with their own
//! `compression_type` / `mode`. [`MssSegment::decode`] resolves the
//! uncompressed modes (the Table 6.41 Unicode range-select modes and
//! UTF-16 mode `0x3F`) and the annex-C standard Huffman compressions
//! (`compression_type` `0x01` title / `0x02` description) via the
//! transcribed Table C4/C6 order-1 code tables, including the §C.2.1
//! escape-to-uncompressed and ≥128-raw-follow rules.
//!
//! PSIP descriptors use tags in the MPEG-2 *user private* range
//! (`0x80`–`0xAB`), which collides with how other systems (e.g. DVB)
//! assign that space — so PSIP descriptor decoding is deliberately kept
//! separate from [`crate::descriptor`]: [`iter_atsc_descriptors`] walks
//! a PSIP descriptor loop into typed [`AtscDescriptorBody`] records
//! (caption service, content advisory, extended channel name, service
//! location, time-shifted service, component name, DCC requests,
//! redistribution control, genre) per A/65 §6.9 Table 6.25.

use crate::error::TsError;
use crate::psi::parse_section_header;

/// The PSIP base PID (`0x1FFB`) carrying STT / MGT / VCT / RRT (and the
/// optional DCCT / DCCSCT) per A/65 §5.
pub const ATSC_BASE_PID: u16 = 0x1FFB;

/// `table_id` of the Master Guide Table (A/65 §6.2).
pub const MGT_TABLE_ID: u8 = 0xC7;
/// `table_id` of the Terrestrial Virtual Channel Table (A/65 §6.3.1).
pub const TVCT_TABLE_ID: u8 = 0xC8;
/// `table_id` of the Cable Virtual Channel Table (A/65 §6.3.2).
pub const CVCT_TABLE_ID: u8 = 0xC9;
/// `table_id` of the Rating Region Table (A/65 §6.4).
pub const RRT_TABLE_ID: u8 = 0xCA;
/// `table_id` of the ATSC Event Information Table (A/65 §6.5).
pub const ATSC_EIT_TABLE_ID: u8 = 0xCB;
/// `table_id` of the Extended Text Table (A/65 §6.6).
pub const ETT_TABLE_ID: u8 = 0xCC;
/// `table_id` of the System Time Table (A/65 §6.1).
pub const STT_TABLE_ID: u8 = 0xCD;
/// `table_id` of the Directed Channel Change Table (A/65 §6.7).
pub const DCCT_TABLE_ID: u8 = 0xD3;
/// `table_id` of the DCC Selection Code Table (A/65 §6.8).
pub const DCCSCT_TABLE_ID: u8 = 0xD4;

/// The Unix timestamp of the GPS epoch (1980-01-06 00:00:00 UTC) —
/// the zero point of every PSIP `system_time` / `start_time` field.
pub const GPS_EPOCH_UNIX: i64 = 315_964_800;

/// Convert a PSIP GPS-seconds instant to Unix time (seconds since
/// 1970-01-01 00:00:00 UTC). PSIP time fields count seconds since the
/// GPS epoch *without* leap seconds; subtracting the STT-carried
/// `GPS_UTC_offset` (the accumulated leap-second count) lands the value
/// on the UTC timeline.
pub fn gps_to_unix(gps_seconds: u32, gps_utc_offset: u8) -> i64 {
    GPS_EPOCH_UNIX + gps_seconds as i64 - gps_utc_offset as i64
}

// ---------------------------------------------------------------------------
// Multiple String Structure (§6.10)
// ---------------------------------------------------------------------------

/// One segment of a [`MssString`] (A/65 §6.10 Table 6.39) — a
/// `compression_type` / `mode` pair plus the raw segment bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssSegment {
    /// Table 6.40 `compression_type` — `0x00` uncompressed; `0x01` /
    /// `0x02` Huffman-coded with the annex-C standard tables (only
    /// legal with `mode == 0x00`).
    pub compression_type: u8,
    /// Table 6.41 `mode` — a Unicode range selector (`0x00`–`0x33`:
    /// each byte is the low half of a code point whose high byte is
    /// implied by the mode), `0x3E` SCSU, or `0x3F` UTF-16.
    pub mode: u8,
    /// The raw `compressed_string_byte` run.
    pub bytes: Vec<u8>,
}

impl MssSegment {
    /// True when `mode` is one of the Table 6.41 Unicode range-select
    /// values (`0x00`–`0x06`, `0x09`–`0x10`, `0x20`–`0x27`,
    /// `0x30`–`0x33`) where each segment byte carries the low 8 bits of
    /// a code point in the `mode << 8` range.
    fn is_range_select_mode(mode: u8) -> bool {
        matches!(mode, 0x00..=0x06 | 0x09..=0x10 | 0x20..=0x27 | 0x30..=0x33)
    }

    /// Decode this segment to text: the uncompressed Table 6.41
    /// range-select modes, uncompressed UTF-16 (`mode 0x3F`), and the
    /// annex-C standard Huffman compressions (`compression_type`
    /// `0x01` title / `0x02` description — order-1 code tables with
    /// the §C.2.1 escape-to-uncompressed rule, output interpreted as
    /// ISO/IEC 8859-1). Returns `None` for SCSU (`0x3E`), reserved /
    /// other-system modes, and corrupt Huffman streams — the raw
    /// bytes stay available in [`Self::bytes`].
    pub fn decode(&self) -> Option<String> {
        match self.compression_type {
            0x00 => {}
            // Annex C Huffman: §6.10 ties compression types 0x01/0x02
            // to text mode 0x00, while §C.3/§C.4 describe them with
            // mode 0xFF ("not applicable") — accept both spellings.
            0x01 | 0x02 if matches!(self.mode, 0x00 | 0xFF) => {
                let table = if self.compression_type == 0x01 {
                    crate::atsc_huffman::TITLE_CODES
                } else {
                    crate::atsc_huffman::DESCRIPTION_CODES
                };
                return huffman_decode_text(&self.bytes, table);
            }
            _ => return None,
        }
        if Self::is_range_select_mode(self.mode) {
            let base = (self.mode as u32) << 8;
            let mut out = String::with_capacity(self.bytes.len());
            for &b in &self.bytes {
                out.push(char::from_u32(base | b as u32)?);
            }
            return Some(out);
        }
        if self.mode == 0x3F {
            // UTF-16, big-endian 16-bit code units (uimsbf).
            if self.bytes.len() % 2 != 0 {
                return None;
            }
            let units: Vec<u16> = self
                .bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            return String::from_utf16(&units).ok();
        }
        None
    }
}

/// MSB-first bit reader over a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    /// Next bit index (0 = MSB of byte 0).
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn bit(&mut self) -> Option<u16> {
        let byte = *self.data.get(self.pos / 8)?;
        let bit = (byte >> (7 - (self.pos % 8))) & 1;
        self.pos += 1;
        Some(bit as u16)
    }

    fn byte(&mut self) -> Option<u8> {
        let mut v = 0u8;
        for _ in 0..8 {
            v = (v << 1) | self.bit()? as u8;
        }
        Some(v)
    }
}

/// The `(prior, symbol, len, bits)` slice for one order-1 context of
/// an annex-C code table (entries are sorted by `prior`).
fn huffman_context(table: &'static [(u8, u8, u8, u16)], prior: u8) -> &'static [(u8, u8, u8, u16)] {
    let start = table.partition_point(|e| e.0 < prior);
    let end = table.partition_point(|e| e.0 <= prior);
    &table[start..end]
}

/// Decode an annex-C Huffman-compressed PSIP text segment
/// (A/65 §C.2): the first character decodes from the Terminate (0)
/// context, each decoded character selects the next order-1 context,
/// symbol 27 escapes to one uncompressed 8-bit character, characters
/// ≥ 128 force the following character uncompressed, and symbol 0
/// terminates the string. Output bytes are ISO/IEC 8859-1. Returns
/// `None` on a corrupt stream (a bit pattern no code in the active
/// context matches); a stream that runs out of bits before the
/// Terminate yields the text decoded so far.
fn huffman_decode_text(bytes: &[u8], table: &'static [(u8, u8, u8, u16)]) -> Option<String> {
    let mut r = BitReader::new(bytes);
    let mut prior: u8 = 0;
    let mut out = String::new();
    loop {
        let ch = if prior >= 128 {
            // §C.2.1: any character following a (128..255) character
            // is uncompressed.
            match r.byte() {
                Some(b) => b,
                None => break,
            }
        } else {
            let ctx = huffman_context(table, prior);
            if ctx.is_empty() {
                return None;
            }
            let max_len = ctx.iter().map(|e| e.2).max().unwrap_or(0);
            let mut acc = 0u16;
            let mut n = 0u8;
            let sym = loop {
                let Some(b) = r.bit() else {
                    // Bits exhausted mid-code: truncated stream (the
                    // Terminate normally lands first) — keep what
                    // decoded cleanly.
                    return Some(out);
                };
                acc = (acc << 1) | b;
                n += 1;
                if let Some(e) = ctx.iter().find(|e| e.2 == n && e.3 == acc) {
                    break e.1;
                }
                if n >= max_len {
                    return None;
                }
            };
            if sym == 27 {
                // Order-1 escape: the next 8 bits are an uncompressed
                // character.
                match r.byte() {
                    Some(b) => b,
                    None => break,
                }
            } else {
                sym
            }
        };
        if ch == 0 {
            break; // string Terminate
        }
        // ISO/IEC 8859-1 maps byte values directly onto U+0000..U+00FF.
        out.push(char::from(ch));
        prior = ch;
    }
    Some(out)
}

/// One per-language string of a [`MultipleStringStructure`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssString {
    /// 3-byte ISO 639.2/B language code.
    pub language_code: [u8; 3],
    /// The string's segments, in wire order. The full text is the
    /// concatenation of the decoded segments.
    pub segments: Vec<MssSegment>,
}

impl MssString {
    /// Concatenate every segment's decoded text. Returns `None` when
    /// any segment cannot be decoded without the annex-C Huffman
    /// tables (see [`MssSegment::decode`]).
    pub fn decode(&self) -> Option<String> {
        let mut out = String::new();
        for seg in &self.segments {
            out.push_str(&seg.decode()?);
        }
        Some(out)
    }
}

/// A PSIP Multiple String Structure (A/65 §6.10 Table 6.39) — the
/// carrier of every human-readable text in PSIP (event titles, long
/// channel names, ETT messages, RRT labels).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultipleStringStructure {
    /// Per-language strings, in wire order.
    pub strings: Vec<MssString>,
}

impl MultipleStringStructure {
    /// Parse a multiple string structure from the start of `data`.
    /// Returns the structure and the number of bytes it consumed —
    /// callers embedding an MSS inside a length-prefixed field can
    /// check the two agree.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), TsError> {
        let mut i = 0usize;
        let number_strings = *data.first().ok_or(TsError::Truncated {
            what: "MSS number_strings",
            have: 0,
            need: 1,
        })? as usize;
        i += 1;
        let mut strings = Vec::with_capacity(number_strings.min(64));
        for _ in 0..number_strings {
            if i + 4 > data.len() {
                return Err(TsError::Truncated {
                    what: "MSS string header",
                    have: data.len() - i,
                    need: 4,
                });
            }
            let language_code = [data[i], data[i + 1], data[i + 2]];
            let number_segments = data[i + 3] as usize;
            i += 4;
            let mut segments = Vec::with_capacity(number_segments.min(64));
            for _ in 0..number_segments {
                if i + 3 > data.len() {
                    return Err(TsError::Truncated {
                        what: "MSS segment header",
                        have: data.len() - i,
                        need: 3,
                    });
                }
                let compression_type = data[i];
                let mode = data[i + 1];
                let number_bytes = data[i + 2] as usize;
                i += 3;
                if i + number_bytes > data.len() {
                    return Err(TsError::Truncated {
                        what: "MSS segment bytes",
                        have: data.len() - i,
                        need: number_bytes,
                    });
                }
                segments.push(MssSegment {
                    compression_type,
                    mode,
                    bytes: data[i..i + number_bytes].to_vec(),
                });
                i += number_bytes;
            }
            strings.push(MssString {
                language_code,
                segments,
            });
        }
        Ok((Self { strings }, i))
    }

    /// Decoded text of the first string, when decodable — the common
    /// single-language case (see [`MssString::decode`]).
    pub fn first_text(&self) -> Option<String> {
        self.strings.first().and_then(MssString::decode)
    }
}

// ---------------------------------------------------------------------------
// PSIP descriptors (§6.9)
// ---------------------------------------------------------------------------

/// One closed-caption service entry of a `caption_service_descriptor`
/// (A/65 §6.9.2 Table 6.26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptionServiceEntry {
    /// 3-byte ISO 639.2/B language code of the caption service.
    pub language: [u8; 3],
    /// `digital_cc` — `true` for a CEA-708 digital service, `false`
    /// for a CEA-608 data stream.
    pub digital_cc: bool,
    /// `line21_field` — only meaningful when `digital_cc` is `false`
    /// (and even then not expected to be used by receivers).
    pub line21_field: bool,
    /// 6-bit CEA-708 `caption_service_number` — only meaningful when
    /// `digital_cc` is `true` (zero is prohibited there).
    pub caption_service_number: u8,
    /// `easy_reader` — the service is an easy-reader type (meaningful
    /// only when `digital_cc` is `true`).
    pub easy_reader: bool,
    /// `wide_aspect_ratio` — `true` = 16:9, `false` = 4:3 (meaningful
    /// only when `digital_cc` is `true`).
    pub wide_aspect_ratio: bool,
}

/// One `(rating_dimension_j, rating_value)` pair of a
/// `content_advisory_descriptor` region (A/65 §6.9.3 Table 6.27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentAdvisoryDimension {
    /// Dimension index into the region's RRT instance.
    pub rating_dimension: u8,
    /// 4-bit rating value within that dimension.
    pub rating_value: u8,
}

/// One per-region block of a `content_advisory_descriptor`
/// (A/65 §6.9.3 Table 6.27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAdvisoryRegion {
    /// The `rating_region` this block's dimensions refer to (matches
    /// an RRT instance's `rating_region`).
    pub rating_region: u8,
    /// The rated dimensions, in ascending `rating_dimension` order per
    /// §6.9.3.
    pub dimensions: Vec<ContentAdvisoryDimension>,
    /// The abbreviated on-screen rating text (≤ 16 display characters).
    pub rating_description: MultipleStringStructure,
}

/// One elementary-stream entry of a `service_location_descriptor`
/// (A/65 §6.9.5 Table 6.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceLocationEntry {
    /// ISO/IEC 13818-1 `stream_type` of the elementary stream.
    pub stream_type: u8,
    /// 13-bit `elementary_PID`.
    pub elementary_pid: u16,
    /// ISO 639.2/B language code; all-zero when no language applies
    /// (e.g. video).
    pub language_code: [u8; 3],
}

/// One entry of a `time_shifted_service_descriptor`
/// (A/65 §6.9.6 Table 6.31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeShiftedServiceEntry {
    /// 10-bit `time_shift` — minutes (1–720) the listed channel lags
    /// the channel carrying this descriptor.
    pub time_shift_minutes: u16,
    /// 10-bit major channel number of the time-shifted service.
    pub major_channel_number: u16,
    /// 10-bit minor channel number of the time-shifted service.
    pub minor_channel_number: u16,
}

/// Typed body of one PSIP descriptor (A/65 §6.9 Table 6.25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtscDescriptorBody {
    /// `stuffing_descriptor` (tag `0x80`, §6.9.8) — contents are to be
    /// disregarded.
    Stuffing(Vec<u8>),
    /// `AC-3_audio_stream_descriptor` (tag `0x81`) — body defined in
    /// ATSC A/52 Annex A as constrained by A/53 Part 3; surfaced raw.
    Ac3AudioStream(Vec<u8>),
    /// `caption_service_descriptor` (tag `0x86`, §6.9.2).
    CaptionService(Vec<CaptionServiceEntry>),
    /// `content_advisory_descriptor` (tag `0x87`, §6.9.3) — up to 8
    /// per-region rating blocks.
    ContentAdvisory(Vec<ContentAdvisoryRegion>),
    /// `extended_channel_name_descriptor` (tag `0xA0`, §6.9.4) — the
    /// long channel name.
    ExtendedChannelName(MultipleStringStructure),
    /// `service_location_descriptor` (tag `0xA1`, §6.9.5) — PCR PID +
    /// per-stream `(stream_type, PID, language)` entries.
    ServiceLocation {
        /// 13-bit `PCR_PID` (`0x1FFF` when none applies).
        pcr_pid: u16,
        /// Elementary-stream entries.
        elements: Vec<ServiceLocationEntry>,
    },
    /// `time_shifted_service_descriptor` (tag `0xA2`, §6.9.6) — NVOD
    /// linkage to time-shifted channels.
    TimeShiftedService(Vec<TimeShiftedServiceEntry>),
    /// `component_name_descriptor` (tag `0xA3`, §6.9.7).
    ComponentName(MultipleStringStructure),
    /// `dcc_departing_request_descriptor` (tag `0xA8`, §6.9.10).
    DccDepartingRequest {
        /// Table 6.34 request type.
        request_type: u8,
        /// The departing-request window text.
        text: MultipleStringStructure,
    },
    /// `dcc_arriving_request_descriptor` (tag `0xA9`, §6.9.11).
    DccArrivingRequest {
        /// Table 6.36 request type.
        request_type: u8,
        /// The arriving-request window text.
        text: MultipleStringStructure,
    },
    /// `redistribution_control_descriptor` (tag `0xAA`, §6.9.12) — its
    /// presence signals "technological control of consumer
    /// redistribution is signaled"; the `rc_information` bytes are
    /// reserved for the future (empty today).
    RedistributionControl(Vec<u8>),
    /// `genre_descriptor` (tag `0xAB`, §6.9.13) — Table 6.20
    /// categorical genre code attributes.
    Genre(Vec<u8>),
    /// Any other tag — payload preserved verbatim.
    Raw,
}

/// One walked PSIP descriptor: the TLV `tag`, the raw payload, and the
/// typed decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtscDescriptor {
    /// `descriptor_tag`.
    pub tag: u8,
    /// Raw payload bytes (after `descriptor_length`).
    pub payload: Vec<u8>,
    /// Typed body; [`AtscDescriptorBody::Raw`] for unknown tags or
    /// malformed bodies.
    pub body: AtscDescriptorBody,
}

/// Iterator over a PSIP descriptor loop (see [`iter_atsc_descriptors`]).
#[derive(Debug)]
pub struct AtscDescriptorIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Iterator for AtscDescriptorIter<'_> {
    type Item = Result<AtscDescriptor, TsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        if self.pos + 2 > self.data.len() {
            self.pos = self.data.len();
            return Some(Err(TsError::Truncated {
                what: "ATSC descriptor TLV header",
                have: 1,
                need: 2,
            }));
        }
        let tag = self.data[self.pos];
        let len = self.data[self.pos + 1] as usize;
        let start = self.pos + 2;
        if start + len > self.data.len() {
            self.pos = self.data.len();
            return Some(Err(TsError::Truncated {
                what: "ATSC descriptor payload",
                have: self.data.len() - start,
                need: len,
            }));
        }
        self.pos = start + len;
        let payload = &self.data[start..start + len];
        let body = decode_atsc_descriptor(tag, payload);
        Some(Ok(AtscDescriptor {
            tag,
            payload: payload.to_vec(),
            body,
        }))
    }
}

/// Walk a PSIP `descriptor()` loop as typed TLV records. Tags outside
/// the A/65 §6.9 set (and malformed bodies) surface as
/// [`AtscDescriptorBody::Raw`] with the payload preserved.
pub fn iter_atsc_descriptors(data: &[u8]) -> AtscDescriptorIter<'_> {
    AtscDescriptorIter { data, pos: 0 }
}

fn decode_caption_service(data: &[u8]) -> Option<AtscDescriptorBody> {
    // §6.9.2 Table 6.26: reserved (3) | number_of_services (5), then
    // 6-byte entries: language (24), digital_cc (1) | reserved (1) |
    // [reserved (5) | line21_field (1)] or [caption_service_number (6)],
    // easy_reader (1) | wide_aspect_ratio (1) | reserved (14).
    let count = (*data.first()? & 0x1F) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut i = 1usize;
    for _ in 0..count {
        if i + 6 > data.len() {
            return None;
        }
        let language = [data[i], data[i + 1], data[i + 2]];
        let b = data[i + 3];
        let digital_cc = (b & 0b1000_0000) != 0;
        let (line21_field, caption_service_number) = if digital_cc {
            (false, b & 0b0011_1111)
        } else {
            ((b & 0b0000_0001) != 0, 0)
        };
        let f = data[i + 4];
        entries.push(CaptionServiceEntry {
            language,
            digital_cc,
            line21_field,
            caption_service_number,
            easy_reader: (f & 0b1000_0000) != 0,
            wide_aspect_ratio: (f & 0b0100_0000) != 0,
        });
        i += 6;
    }
    Some(AtscDescriptorBody::CaptionService(entries))
}

fn decode_content_advisory(data: &[u8]) -> Option<AtscDescriptorBody> {
    // §6.9.3 Table 6.27: reserved (2) | rating_region_count (6), then
    // per region: rating_region (8), rated_dimensions (8),
    // { rating_dimension_j (8), reserved (4) | rating_value (4) } ...,
    // rating_description_length (8), rating_description_text().
    let region_count = (*data.first()? & 0x3F) as usize;
    let mut regions = Vec::with_capacity(region_count.min(8));
    let mut i = 1usize;
    for _ in 0..region_count {
        if i + 2 > data.len() {
            return None;
        }
        let rating_region = data[i];
        let rated_dimensions = data[i + 1] as usize;
        i += 2;
        let mut dimensions = Vec::with_capacity(rated_dimensions.min(64));
        for _ in 0..rated_dimensions {
            if i + 2 > data.len() {
                return None;
            }
            dimensions.push(ContentAdvisoryDimension {
                rating_dimension: data[i],
                rating_value: data[i + 1] & 0x0F,
            });
            i += 2;
        }
        let desc_len = *data.get(i)? as usize;
        i += 1;
        if i + desc_len > data.len() {
            return None;
        }
        let (rating_description, used) =
            MultipleStringStructure::parse(&data[i..i + desc_len]).ok()?;
        if used != desc_len {
            return None;
        }
        i += desc_len;
        regions.push(ContentAdvisoryRegion {
            rating_region,
            dimensions,
            rating_description,
        });
    }
    Some(AtscDescriptorBody::ContentAdvisory(regions))
}

fn decode_service_location(data: &[u8]) -> Option<AtscDescriptorBody> {
    // §6.9.5 Table 6.29: reserved (3) | PCR_PID (13), number_elements
    // (8), then 6-byte entries: stream_type (8), reserved (3) |
    // elementary_PID (13), ISO_639_language_code (24).
    if data.len() < 3 {
        return None;
    }
    let pcr_pid = u16::from_be_bytes([data[0] & 0x1F, data[1]]);
    let count = data[2] as usize;
    let mut elements = Vec::with_capacity(count.min(64));
    let mut i = 3usize;
    for _ in 0..count {
        if i + 6 > data.len() {
            return None;
        }
        elements.push(ServiceLocationEntry {
            stream_type: data[i],
            elementary_pid: u16::from_be_bytes([data[i + 1] & 0x1F, data[i + 2]]),
            language_code: [data[i + 3], data[i + 4], data[i + 5]],
        });
        i += 6;
    }
    Some(AtscDescriptorBody::ServiceLocation { pcr_pid, elements })
}

fn decode_time_shifted_service(data: &[u8]) -> Option<AtscDescriptorBody> {
    // §6.9.6 Table 6.31: reserved (3) | number_of_services (5), then
    // 5-byte entries: reserved (6) | time_shift (10), reserved (4) |
    // major_channel_number (10) | minor_channel_number (10).
    let count = (*data.first()? & 0x1F) as usize;
    let mut entries = Vec::with_capacity(count.min(20));
    let mut i = 1usize;
    for _ in 0..count {
        if i + 5 > data.len() {
            return None;
        }
        let time_shift_minutes = (((data[i] & 0x03) as u16) << 8) | data[i + 1] as u16;
        let major = (((data[i + 2] & 0x0F) as u16) << 6) | (data[i + 3] >> 2) as u16;
        let minor = (((data[i + 3] & 0x03) as u16) << 8) | data[i + 4] as u16;
        entries.push(TimeShiftedServiceEntry {
            time_shift_minutes,
            major_channel_number: major,
            minor_channel_number: minor,
        });
        i += 5;
    }
    Some(AtscDescriptorBody::TimeShiftedService(entries))
}

fn decode_dcc_request(data: &[u8], departing: bool) -> Option<AtscDescriptorBody> {
    // §6.9.10 / §6.9.11 Tables 6.33 / 6.35: request_type (8),
    // request_text_length (8), request_text() (an MSS).
    if data.len() < 2 {
        return None;
    }
    let request_type = data[0];
    let text_len = data[1] as usize;
    if 2 + text_len > data.len() {
        return None;
    }
    let (text, used) = MultipleStringStructure::parse(&data[2..2 + text_len]).ok()?;
    if used != text_len {
        return None;
    }
    Some(if departing {
        AtscDescriptorBody::DccDepartingRequest { request_type, text }
    } else {
        AtscDescriptorBody::DccArrivingRequest { request_type, text }
    })
}

fn decode_atsc_descriptor(tag: u8, data: &[u8]) -> AtscDescriptorBody {
    match tag {
        0x80 => AtscDescriptorBody::Stuffing(data.to_vec()),
        0x81 => AtscDescriptorBody::Ac3AudioStream(data.to_vec()),
        0x86 => decode_caption_service(data).unwrap_or(AtscDescriptorBody::Raw),
        0x87 => decode_content_advisory(data).unwrap_or(AtscDescriptorBody::Raw),
        0xA0 => match MultipleStringStructure::parse(data) {
            Ok((mss, used)) if used == data.len() => AtscDescriptorBody::ExtendedChannelName(mss),
            _ => AtscDescriptorBody::Raw,
        },
        0xA1 => decode_service_location(data).unwrap_or(AtscDescriptorBody::Raw),
        0xA2 => decode_time_shifted_service(data).unwrap_or(AtscDescriptorBody::Raw),
        0xA3 => match MultipleStringStructure::parse(data) {
            Ok((mss, used)) if used == data.len() => AtscDescriptorBody::ComponentName(mss),
            _ => AtscDescriptorBody::Raw,
        },
        0xA8 => decode_dcc_request(data, true).unwrap_or(AtscDescriptorBody::Raw),
        0xA9 => decode_dcc_request(data, false).unwrap_or(AtscDescriptorBody::Raw),
        0xAA => AtscDescriptorBody::RedistributionControl(data.to_vec()),
        0xAB => {
            // §6.9.13 Table 6.38: reserved (3) | attribute_count (5),
            // then attribute bytes.
            match data.first() {
                Some(&head) => {
                    let count = (head & 0x1F) as usize;
                    if 1 + count > data.len() {
                        AtscDescriptorBody::Raw
                    } else {
                        AtscDescriptorBody::Genre(data[1..1 + count].to_vec())
                    }
                }
                None => AtscDescriptorBody::Raw,
            }
        }
        _ => AtscDescriptorBody::Raw,
    }
}

// ---------------------------------------------------------------------------
// PSIP section-header helper
// ---------------------------------------------------------------------------

/// Parse the A/65 §4.1 generic PSIP section: the long-form section
/// header (CRC-verified via the shared [`crate::psi`] machinery) plus
/// the mandatory `protocol_version` byte. Only `protocol_version == 0`
/// is defined by A/65; non-zero values signal a structurally different
/// future table and are rejected as unsupported.
fn parse_psip_section(
    section: &[u8],
    expected_table_id: u8,
) -> Result<(crate::psi::SectionHeader, &[u8]), TsError> {
    let (hdr, body) = parse_section_header(section, expected_table_id)?;
    let (&protocol_version, rest) = body.split_first().ok_or(TsError::Truncated {
        what: "PSIP protocol_version",
        have: 0,
        need: 1,
    })?;
    if protocol_version != 0 {
        return Err(TsError::Unsupported(
            "PSIP protocol_version is not zero (A/65 defines only zero)",
        ));
    }
    Ok((hdr, rest))
}

// ---------------------------------------------------------------------------
// System Time Table (§6.1)
// ---------------------------------------------------------------------------

/// Parsed ATSC System Time Table (A/65 §6.1 Table 6.1) — the PSIP
/// wall-clock anchor carried on [`ATSC_BASE_PID`] with
/// `table_id == 0xCD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTimeTable {
    /// `system_time` — seconds since the GPS epoch (1980-01-06
    /// 00:00:00 UTC), leap seconds *not* subtracted.
    pub system_time: u32,
    /// `GPS_UTC_offset` — the current whole-second offset between GPS
    /// and UTC (subtract from GPS time to get UTC).
    pub gps_utc_offset: u8,
    /// Raw 16-bit `daylight_saving` field (annex A Table A1) — see the
    /// accessors.
    pub daylight_saving: u16,
    /// Raw bytes of the trailing descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl SystemTimeTable {
    /// Parse a single STT section (from `table_id` through the CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (_hdr, body) = parse_psip_section(section, STT_TABLE_ID)?;
        if body.len() < 7 {
            return Err(TsError::Truncated {
                what: "STT body",
                have: body.len(),
                need: 7,
            });
        }
        Ok(Self {
            system_time: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            gps_utc_offset: body[4],
            daylight_saving: u16::from_be_bytes([body[5], body[6]]),
            descriptors: body[7..].to_vec(),
        })
    }

    /// The system time on the Unix/UTC timeline (leap seconds applied
    /// via `GPS_UTC_offset`).
    pub fn unix_time(&self) -> i64 {
        gps_to_unix(self.system_time, self.gps_utc_offset)
    }

    /// Annex A `DS_status` — `true` while daylight saving time is in
    /// effect.
    pub fn ds_status(&self) -> bool {
        (self.daylight_saving & 0x8000) != 0
    }

    /// Annex A `DS_day_of_month` — the local day of month (1–31) of
    /// the upcoming DST transition, or `0` when none is imminent.
    pub fn ds_day_of_month(&self) -> u8 {
        ((self.daylight_saving >> 8) & 0x1F) as u8
    }

    /// Annex A `DS_hour` — the local hour (0–18) of the upcoming DST
    /// transition.
    pub fn ds_hour(&self) -> u8 {
        (self.daylight_saving & 0xFF) as u8
    }

    /// Walk the STT descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

// ---------------------------------------------------------------------------
// Master Guide Table (§6.2)
// ---------------------------------------------------------------------------

/// One `tables_defined` entry of the MGT (A/65 §6.2 Table 6.2) —
/// announces one PSIP table instance's PID, version, and size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgtTableEntry {
    /// Table 6.3 `table_type` — e.g. `0x0000` current TVCT, `0x0002`
    /// current CVCT, `0x0004` channel ETT, `0x0100 + k` EIT-k,
    /// `0x0200 + k` event ETT-k, `0x0301..=0x03FF` RRT per region.
    pub table_type: u16,
    /// 13-bit `table_type_PID` the announced table rides on.
    pub pid: u16,
    /// 5-bit `table_type_version_number` — mirrors the announced
    /// table's own `version_number`.
    pub version_number: u8,
    /// 32-bit `number_bytes` — total size of the announced table.
    pub number_bytes: u32,
    /// Raw bytes of the entry's descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl MgtTableEntry {
    /// The EIT index `k` when this entry announces EIT-k
    /// (`table_type 0x0100..=0x017F`).
    pub fn eit_index(&self) -> Option<u8> {
        if (0x0100..=0x017F).contains(&self.table_type) {
            Some((self.table_type - 0x0100) as u8)
        } else {
            None
        }
    }

    /// The event-ETT index `k` when this entry announces event ETT-k
    /// (`table_type 0x0200..=0x027F`).
    pub fn event_ett_index(&self) -> Option<u8> {
        if (0x0200..=0x027F).contains(&self.table_type) {
            Some((self.table_type - 0x0200) as u8)
        } else {
            None
        }
    }

    /// The `rating_region` when this entry announces an RRT instance
    /// (`table_type 0x0301..=0x03FF`).
    pub fn rrt_rating_region(&self) -> Option<u8> {
        if (0x0301..=0x03FF).contains(&self.table_type) {
            Some((self.table_type - 0x0300) as u8)
        } else {
            None
        }
    }

    /// The `dcc_id` when this entry announces a DCCT instance
    /// (`table_type 0x1400..=0x14FF`, Table 6.3).
    pub fn dcct_dcc_id(&self) -> Option<u8> {
        if (0x1400..=0x14FF).contains(&self.table_type) {
            Some((self.table_type - 0x1400) as u8)
        } else {
            None
        }
    }

    /// `true` when this entry announces the DCCSCT
    /// (`table_type 0x0005`, Table 6.3).
    pub fn is_dccsct(&self) -> bool {
        self.table_type == 0x0005
    }

    /// Walk this entry's descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

/// Parsed ATSC Master Guide Table (A/65 §6.2 Table 6.2) — the PSIP
/// directory listing sizes, PIDs, and versions of every other PSIP
/// table (except the STT), carried in a single section on
/// [`ATSC_BASE_PID`] with `table_id == 0xC7`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterGuideTable {
    /// 5-bit `version_number` of the MGT itself.
    pub version_number: u8,
    /// The announced tables.
    pub tables: Vec<MgtTableEntry>,
    /// Raw bytes of the MGT-level descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl MasterGuideTable {
    /// Parse a single MGT section (from `table_id` through the CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_psip_section(section, MGT_TABLE_ID)?;
        if body.len() < 2 {
            return Err(TsError::Truncated {
                what: "MGT tables_defined",
                have: body.len(),
                need: 2,
            });
        }
        let tables_defined = u16::from_be_bytes([body[0], body[1]]) as usize;
        let mut i = 2usize;
        let mut tables = Vec::with_capacity(tables_defined.min(370));
        for _ in 0..tables_defined {
            // table_type (16) + PID (16 w/ reserved) + version (8 w/
            // reserved) + number_bytes (32) + descriptors_length (16 w/
            // reserved) = 11 fixed bytes.
            if i + 11 > body.len() {
                return Err(TsError::Truncated {
                    what: "MGT table entry",
                    have: body.len() - i,
                    need: 11,
                });
            }
            let table_type = u16::from_be_bytes([body[i], body[i + 1]]);
            let pid = u16::from_be_bytes([body[i + 2] & 0x1F, body[i + 3]]);
            let version_number = body[i + 4] & 0x1F;
            let number_bytes =
                u32::from_be_bytes([body[i + 5], body[i + 6], body[i + 7], body[i + 8]]);
            let desc_len = (((body[i + 9] as usize) & 0x0F) << 8) | body[i + 10] as usize;
            i += 11;
            if i + desc_len > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: desc_len,
                    have: body.len() - i,
                });
            }
            tables.push(MgtTableEntry {
                table_type,
                pid,
                version_number,
                number_bytes,
                descriptors: body[i..i + desc_len].to_vec(),
            });
            i += desc_len;
        }
        if i + 2 > body.len() {
            return Err(TsError::Truncated {
                what: "MGT descriptors_length",
                have: body.len() - i,
                need: 2,
            });
        }
        let mgt_desc_len = (((body[i] as usize) & 0x0F) << 8) | body[i + 1] as usize;
        i += 2;
        if i + mgt_desc_len > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: mgt_desc_len,
                have: body.len() - i,
            });
        }
        Ok(Self {
            version_number: hdr.version_number,
            tables,
            descriptors: body[i..i + mgt_desc_len].to_vec(),
        })
    }

    /// Walk the MGT-level descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

// ---------------------------------------------------------------------------
// Virtual Channel Table (§6.3)
// ---------------------------------------------------------------------------

/// One virtual channel of a [`VirtualChannelTable`]
/// (A/65 §6.3 Tables 6.4 / 6.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VctChannel {
    /// `short_name` — up to 7 UTF-16 code units, NUL-padded on the
    /// wire; see [`Self::short_name_text`].
    pub short_name: [u16; 7],
    /// 10-bit `major_channel_number` (see also
    /// [`Self::one_part_number`] for the CVCT one-part form).
    pub major_channel_number: u16,
    /// 10-bit `minor_channel_number` (`0` for analog channels).
    pub minor_channel_number: u16,
    /// Table 6.5 `modulation_mode` (`0x01` analog, `0x02`/`0x03` SCTE
    /// modes, `0x04` 8-VSB, `0x05` 16-VSB).
    pub modulation_mode: u8,
    /// `carrier_frequency` — deprecated, transmitted as zero.
    pub carrier_frequency: u32,
    /// `channel_TSID` — the `transport_stream_id` of the TS actually
    /// carrying this channel.
    pub channel_tsid: u16,
    /// The channel's MPEG-2 `program_number` (`0xFFFF` for analog
    /// channels, `0` for inactive ones).
    pub program_number: u16,
    /// 2-bit `ETM_location` (Table 6.6).
    pub etm_location: u8,
    /// `access_controlled` — events on this channel may be access
    /// controlled.
    pub access_controlled: bool,
    /// `hidden` — not reachable by direct channel entry.
    pub hidden: bool,
    /// `path_select` — CVCT only (`false` = path 1); transmitted as a
    /// reserved bit in the TVCT.
    pub path_select: bool,
    /// `out_of_band` — CVCT only: carried on the out-of-band channel;
    /// transmitted as a reserved bit in the TVCT.
    pub out_of_band: bool,
    /// `hide_guide` — a hidden channel's events also stay out of EPG
    /// displays when set.
    pub hide_guide: bool,
    /// 6-bit `service_type` (A/53 Part 1 / Part 3 — `0x01` analog,
    /// `0x02` ATSC digital television, `0x03` audio only, `0x04`
    /// data-only).
    pub service_type: u8,
    /// 16-bit `source_id` linking this channel to its EIT/ETT
    /// programming data (zero = not identified).
    pub source_id: u16,
    /// Raw bytes of this channel's descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl VctChannel {
    /// Decode the NUL-padded UTF-16 `short_name` to text.
    pub fn short_name_text(&self) -> String {
        let end = self
            .short_name
            .iter()
            .position(|&u| u == 0)
            .unwrap_or(self.short_name.len());
        String::from_utf16_lossy(&self.short_name[..end])
    }

    /// The CVCT one-part channel number, when
    /// `major_channel_number`'s six most significant bits are
    /// `'11 1111'` (A/65 §6.3.2):
    /// `(major & 0x00F) << 10 + minor`.
    pub fn one_part_number(&self) -> Option<u16> {
        if self.major_channel_number >> 4 == 0b11_1111 {
            Some(((self.major_channel_number & 0x00F) << 10) + self.minor_channel_number)
        } else {
            None
        }
    }

    /// Walk this channel's descriptor loop (the
    /// `service_location_descriptor` rides here in the TVCT).
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

/// Parsed ATSC Virtual Channel Table (A/65 §6.3) — terrestrial
/// (`table_id 0xC8`) or cable (`0xC9`), both on [`ATSC_BASE_PID`]. The
/// two share one wire shape; `cable` records which one parsed, and the
/// CVCT-only bits (`path_select` / `out_of_band`) sit where the TVCT
/// has reserved bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualChannelTable {
    /// `true` when this section is a Cable VCT (`table_id 0xC9`).
    pub cable: bool,
    /// The `transport_stream_id` of the multiplex (from
    /// `table_id_extension`).
    pub transport_stream_id: u16,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// `section_number` of this section.
    pub section_number: u8,
    /// `last_section_number` of the complete VCT.
    pub last_section_number: u8,
    /// The virtual channels in this section.
    pub channels: Vec<VctChannel>,
    /// Raw bytes of the VCT-level `additional_descriptor` loop — walk
    /// with [`Self::iter_additional_descriptors`].
    pub additional_descriptors: Vec<u8>,
}

impl VirtualChannelTable {
    /// Parse a single TVCT or CVCT section (from `table_id` through
    /// the CRC); the `table_id` byte selects which.
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let table_id = section.first().copied().unwrap_or(0);
        let cable = match table_id {
            TVCT_TABLE_ID => false,
            CVCT_TABLE_ID => true,
            _ => {
                return Err(TsError::Unsupported(
                    "PSI table_id does not match expected value",
                ))
            }
        };
        let (hdr, body) = parse_psip_section(section, table_id)?;
        let num_channels = *body.first().ok_or(TsError::Truncated {
            what: "VCT num_channels_in_section",
            have: 0,
            need: 1,
        })? as usize;
        let mut i = 1usize;
        let mut channels = Vec::with_capacity(num_channels.min(64));
        for _ in 0..num_channels {
            // Fixed prefix: short_name (14) + channel numbers (3) +
            // modulation (1) + carrier (4) + TSID (2) + program (2) +
            // flags/service_type (2) + source_id (2) +
            // descriptors_length (2) = 32 bytes.
            if i + 32 > body.len() {
                return Err(TsError::Truncated {
                    what: "VCT channel entry",
                    have: body.len() - i,
                    need: 32,
                });
            }
            let mut short_name = [0u16; 7];
            for (k, unit) in short_name.iter_mut().enumerate() {
                *unit = u16::from_be_bytes([body[i + 2 * k], body[i + 2 * k + 1]]);
            }
            let b0 = body[i + 14];
            let b1 = body[i + 15];
            let b2 = body[i + 16];
            // reserved (4) | major (10) | minor (10).
            let major = (((b0 & 0x0F) as u16) << 6) | (b1 >> 2) as u16;
            let minor = (((b1 & 0x03) as u16) << 8) | b2 as u16;
            let modulation_mode = body[i + 17];
            let carrier_frequency =
                u32::from_be_bytes([body[i + 18], body[i + 19], body[i + 20], body[i + 21]]);
            let channel_tsid = u16::from_be_bytes([body[i + 22], body[i + 23]]);
            let program_number = u16::from_be_bytes([body[i + 24], body[i + 25]]);
            // f0: ETM_location (2) | access_controlled (1) | hidden (1)
            // | path_select (1, CVCT) | out_of_band (1, CVCT) |
            // hide_guide (1) | reserved (1); f1: reserved (2) |
            // service_type (6).
            let f0 = body[i + 26];
            let f1 = body[i + 27];
            let source_id = u16::from_be_bytes([body[i + 28], body[i + 29]]);
            let desc_len = (((body[i + 30] as usize) & 0x03) << 8) | body[i + 31] as usize;
            i += 32;
            if i + desc_len > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: desc_len,
                    have: body.len() - i,
                });
            }
            channels.push(VctChannel {
                short_name,
                major_channel_number: major,
                minor_channel_number: minor,
                modulation_mode,
                carrier_frequency,
                channel_tsid,
                program_number,
                etm_location: f0 >> 6,
                access_controlled: (f0 & 0b0010_0000) != 0,
                hidden: (f0 & 0b0001_0000) != 0,
                path_select: cable && (f0 & 0b0000_1000) != 0,
                out_of_band: cable && (f0 & 0b0000_0100) != 0,
                hide_guide: (f0 & 0b0000_0010) != 0,
                service_type: f1 & 0x3F,
                source_id,
                descriptors: body[i..i + desc_len].to_vec(),
            });
            i += desc_len;
        }
        if i + 2 > body.len() {
            return Err(TsError::Truncated {
                what: "VCT additional_descriptors_length",
                have: body.len() - i,
                need: 2,
            });
        }
        let add_len = (((body[i] as usize) & 0x03) << 8) | body[i + 1] as usize;
        i += 2;
        if i + add_len > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: add_len,
                have: body.len() - i,
            });
        }
        Ok(Self {
            cable,
            transport_stream_id: hdr.table_id_extension,
            version_number: hdr.version_number,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            channels,
            additional_descriptors: body[i..i + add_len].to_vec(),
        })
    }

    /// Walk the VCT-level `additional_descriptor` loop.
    pub fn iter_additional_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.additional_descriptors)
    }
}

// ---------------------------------------------------------------------------
// Rating Region Table (§6.4)
// ---------------------------------------------------------------------------

/// One rating value of an [`RrtDimension`] — abbreviated and full
/// display names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrtRatingValue {
    /// Abbreviated display name (≤ 8 characters; empty MSS for rating
    /// value 0).
    pub abbrev_rating_value: MultipleStringStructure,
    /// Full display name (≤ 150 characters; empty MSS for rating
    /// value 0).
    pub rating_value: MultipleStringStructure,
}

/// One rating dimension of a [`RatingRegionTable`] (e.g. an age-based
/// scale or a content-category scale).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrtDimension {
    /// Dimension display name (≤ 20 characters).
    pub dimension_name: MultipleStringStructure,
    /// `graduated_scale` — higher rating values represent increasing
    /// levels of rated content.
    pub graduated_scale: bool,
    /// The dimension's rating values, indexed by `rating_value` as
    /// carried in a `content_advisory_descriptor`.
    pub values: Vec<RrtRatingValue>,
}

/// Parsed ATSC Rating Region Table (A/65 §6.4 Table 6.10) — the rating
/// system for one region, carried on [`ATSC_BASE_PID`] with
/// `table_id == 0xCA`; the `rating_region` rides in the low byte of
/// `table_id_extension`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatingRegionTable {
    /// 8-bit `rating_region` this instance defines (`0x01`–`0xFF`).
    pub rating_region: u8,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// Region display name (≤ 32 characters).
    pub rating_region_name: MultipleStringStructure,
    /// The region's rating dimensions.
    pub dimensions: Vec<RrtDimension>,
    /// Raw bytes of the trailing descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl RatingRegionTable {
    /// Parse a single RRT section (from `table_id` through the CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_psip_section(section, RRT_TABLE_ID)?;
        let mut i = 0usize;
        let name_len = *body.first().ok_or(TsError::Truncated {
            what: "RRT rating_region_name_length",
            have: 0,
            need: 1,
        })? as usize;
        i += 1;
        if i + name_len > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: name_len,
                have: body.len() - i,
            });
        }
        let (rating_region_name, used) = MultipleStringStructure::parse(&body[i..i + name_len])?;
        if used != name_len {
            return Err(TsError::Unsupported(
                "RRT rating_region_name_length does not frame the MSS exactly",
            ));
        }
        i += name_len;
        let dimensions_defined = *body.get(i).ok_or(TsError::Truncated {
            what: "RRT dimensions_defined",
            have: 0,
            need: 1,
        })? as usize;
        i += 1;
        let mut dimensions = Vec::with_capacity(dimensions_defined.min(255));
        for _ in 0..dimensions_defined {
            let dn_len = *body.get(i).ok_or(TsError::Truncated {
                what: "RRT dimension_name_length",
                have: 0,
                need: 1,
            })? as usize;
            i += 1;
            if i + dn_len > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: dn_len,
                    have: body.len() - i,
                });
            }
            let (dimension_name, used) = MultipleStringStructure::parse(&body[i..i + dn_len])?;
            if used != dn_len {
                return Err(TsError::Unsupported(
                    "RRT dimension_name_length does not frame the MSS exactly",
                ));
            }
            i += dn_len;
            // reserved (3) | graduated_scale (1) | values_defined (4).
            let gb = *body.get(i).ok_or(TsError::Truncated {
                what: "RRT graduated_scale / values_defined",
                have: 0,
                need: 1,
            })?;
            i += 1;
            let graduated_scale = (gb & 0b0001_0000) != 0;
            let values_defined = (gb & 0x0F) as usize;
            let mut values = Vec::with_capacity(values_defined);
            for _ in 0..values_defined {
                let ab_len = *body.get(i).ok_or(TsError::Truncated {
                    what: "RRT abbrev_rating_value_length",
                    have: 0,
                    need: 1,
                })? as usize;
                i += 1;
                if i + ab_len > body.len() {
                    return Err(TsError::SectionLengthOverrun {
                        claimed: ab_len,
                        have: body.len() - i,
                    });
                }
                let (abbrev, used) = MultipleStringStructure::parse(&body[i..i + ab_len])?;
                if used != ab_len {
                    return Err(TsError::Unsupported(
                        "RRT abbrev_rating_value_length does not frame the MSS exactly",
                    ));
                }
                i += ab_len;
                let rv_len = *body.get(i).ok_or(TsError::Truncated {
                    what: "RRT rating_value_length",
                    have: 0,
                    need: 1,
                })? as usize;
                i += 1;
                if i + rv_len > body.len() {
                    return Err(TsError::SectionLengthOverrun {
                        claimed: rv_len,
                        have: body.len() - i,
                    });
                }
                let (full, used) = MultipleStringStructure::parse(&body[i..i + rv_len])?;
                if used != rv_len {
                    return Err(TsError::Unsupported(
                        "RRT rating_value_length does not frame the MSS exactly",
                    ));
                }
                i += rv_len;
                values.push(RrtRatingValue {
                    abbrev_rating_value: abbrev,
                    rating_value: full,
                });
            }
            dimensions.push(RrtDimension {
                dimension_name,
                graduated_scale,
                values,
            });
        }
        if i + 2 > body.len() {
            return Err(TsError::Truncated {
                what: "RRT descriptors_length",
                have: body.len() - i,
                need: 2,
            });
        }
        let desc_len = (((body[i] as usize) & 0x03) << 8) | body[i + 1] as usize;
        i += 2;
        if i + desc_len > body.len() {
            return Err(TsError::SectionLengthOverrun {
                claimed: desc_len,
                have: body.len() - i,
            });
        }
        Ok(Self {
            rating_region: (hdr.table_id_extension & 0xFF) as u8,
            version_number: hdr.version_number,
            rating_region_name,
            dimensions,
            descriptors: body[i..i + desc_len].to_vec(),
        })
    }

    /// Walk the RRT descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

// ---------------------------------------------------------------------------
// Event Information Table (§6.5)
// ---------------------------------------------------------------------------

/// One event of an [`AtscEventInformationTable`]
/// (A/65 §6.5 Table 6.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtscEitEvent {
    /// 14-bit `event_id` (also the low half of the event's `ETM_id`).
    pub event_id: u16,
    /// `start_time` — GPS seconds since 1980-01-06 00:00:00 UTC (see
    /// [`gps_to_unix`]).
    pub start_time: u32,
    /// 2-bit `ETM_location` (Table 6.12).
    pub etm_location: u8,
    /// 20-bit `length_in_seconds` — the event duration.
    pub length_in_seconds: u32,
    /// The event title.
    pub title: MultipleStringStructure,
    /// Raw bytes of the event's descriptor loop (content advisory,
    /// caption service, AC-3 audio, …) — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl AtscEitEvent {
    /// Walk this event's descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

/// Parsed ATSC Event Information Table section (A/65 §6.5 Table 6.11)
/// — one virtual channel's events for one 3-hour slot, carried on an
/// MGT-announced PID with `table_id == 0xCB` and keyed by the
/// channel's `source_id` in `table_id_extension`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtscEventInformationTable {
    /// The `source_id` of the virtual channel these events belong to.
    pub source_id: u16,
    /// 5-bit `version_number` of this EIT-k instance.
    pub version_number: u8,
    /// `section_number` of this section.
    pub section_number: u8,
    /// `last_section_number` of the instance.
    pub last_section_number: u8,
    /// The events, in start-time order per §6.5.
    pub events: Vec<AtscEitEvent>,
}

impl AtscEventInformationTable {
    /// Parse a single ATSC EIT section (from `table_id` through the
    /// CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_psip_section(section, ATSC_EIT_TABLE_ID)?;
        let num_events = *body.first().ok_or(TsError::Truncated {
            what: "ATSC EIT num_events_in_section",
            have: 0,
            need: 1,
        })? as usize;
        let mut i = 1usize;
        let mut events = Vec::with_capacity(num_events.min(64));
        for _ in 0..num_events {
            // Fixed prefix: event_id (2) + start_time (4) +
            // ETM_location / length_in_seconds (3) + title_length (1)
            // = 10 bytes.
            if i + 10 > body.len() {
                return Err(TsError::Truncated {
                    what: "ATSC EIT event entry",
                    have: body.len() - i,
                    need: 10,
                });
            }
            let event_id = u16::from_be_bytes([body[i] & 0x3F, body[i + 1]]);
            let start_time =
                u32::from_be_bytes([body[i + 2], body[i + 3], body[i + 4], body[i + 5]]);
            // reserved (2) | ETM_location (2) | length_in_seconds (20).
            let etm_location = (body[i + 6] >> 4) & 0x03;
            let length_in_seconds = (((body[i + 6] & 0x0F) as u32) << 16)
                | ((body[i + 7] as u32) << 8)
                | body[i + 8] as u32;
            let title_len = body[i + 9] as usize;
            i += 10;
            if i + title_len > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: title_len,
                    have: body.len() - i,
                });
            }
            let title = if title_len == 0 {
                MultipleStringStructure::default()
            } else {
                let (t, used) = MultipleStringStructure::parse(&body[i..i + title_len])?;
                if used != title_len {
                    return Err(TsError::Unsupported(
                        "ATSC EIT title_length does not frame the MSS exactly",
                    ));
                }
                t
            };
            i += title_len;
            if i + 2 > body.len() {
                return Err(TsError::Truncated {
                    what: "ATSC EIT descriptors_length",
                    have: body.len() - i,
                    need: 2,
                });
            }
            let desc_len = (((body[i] as usize) & 0x0F) << 8) | body[i + 1] as usize;
            i += 2;
            if i + desc_len > body.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: desc_len,
                    have: body.len() - i,
                });
            }
            events.push(AtscEitEvent {
                event_id,
                start_time,
                etm_location,
                length_in_seconds,
                title,
                descriptors: body[i..i + desc_len].to_vec(),
            });
            i += desc_len;
        }
        Ok(Self {
            source_id: hdr.table_id_extension,
            version_number: hdr.version_number,
            section_number: hdr.section_number,
            last_section_number: hdr.last_section_number,
            events,
        })
    }
}

// ---------------------------------------------------------------------------
// Extended Text Table (§6.6)
// ---------------------------------------------------------------------------

/// Parsed ATSC Extended Text Table section (A/65 §6.6 Table 6.13) —
/// one Extended Text Message on an MGT-announced PID with
/// `table_id == 0xCC`, keyed by its 32-bit `ETM_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedTextTable {
    /// `ETT_table_id_extension` — instance disambiguator when several
    /// ETTs share a PID.
    pub ett_table_id_extension: u16,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// 32-bit `ETM_id` (Table 6.14) — see the accessors.
    pub etm_id: u32,
    /// The extended text message.
    pub message: MultipleStringStructure,
}

impl ExtendedTextTable {
    /// Parse a single ETT section (from `table_id` through the CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_psip_section(section, ETT_TABLE_ID)?;
        if body.len() < 4 {
            return Err(TsError::Truncated {
                what: "ETT ETM_id",
                have: body.len(),
                need: 4,
            });
        }
        let etm_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        let (message, used) = MultipleStringStructure::parse(&body[4..])?;
        if used != body.len() - 4 {
            return Err(TsError::Unsupported(
                "ETT extended_text_message does not fill the section exactly",
            ));
        }
        Ok(Self {
            ett_table_id_extension: hdr.table_id_extension,
            version_number: hdr.version_number,
            etm_id,
            message,
        })
    }

    /// The `source_id` half of the `ETM_id` (Table 6.14).
    pub fn source_id(&self) -> u16 {
        (self.etm_id >> 16) as u16
    }

    /// `true` when this is an event ETM (`ETM_id` bit 1 set), `false`
    /// for a channel ETM.
    pub fn is_event_etm(&self) -> bool {
        (self.etm_id & 0b10) != 0
    }

    /// The `event_id` of an event ETM (bits 15..2 of `ETM_id`);
    /// `None` for a channel ETM.
    pub fn event_id(&self) -> Option<u16> {
        if self.is_event_etm() {
            Some(((self.etm_id >> 2) & 0x3FFF) as u16)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Directed Channel Change Table (§6.7)
// ---------------------------------------------------------------------------

/// Table 6.18 demographic-category bit assignments for the
/// `dcc_selection_id` of the demographic [`DccSelectionCategory`]
/// tests (`dcc_selection_type` `0x05`/`0x06`/`0x15`/`0x16`) — OR the
/// bits together to form the selection bit vector.
pub mod dcc_demographic {
    /// Males.
    pub const MALES: u64 = 0x0000_0000_0000_0001;
    /// Females.
    pub const FEMALES: u64 = 0x0000_0000_0000_0002;
    /// Ages 2–5.
    pub const AGES_2_5: u64 = 0x0000_0000_0000_0004;
    /// Ages 6–11.
    pub const AGES_6_11: u64 = 0x0000_0000_0000_0008;
    /// Ages 12–17.
    pub const AGES_12_17: u64 = 0x0000_0000_0000_0010;
    /// Ages 18–34.
    pub const AGES_18_34: u64 = 0x0000_0000_0000_0020;
    /// Ages 35–49.
    pub const AGES_35_49: u64 = 0x0000_0000_0000_0040;
    /// Ages 50–54.
    pub const AGES_50_54: u64 = 0x0000_0000_0000_0080;
    /// Ages 55–64.
    pub const AGES_55_64: u64 = 0x0000_0000_0000_0100;
    /// Ages 65+.
    pub const AGES_65_PLUS: u64 = 0x0000_0000_0000_0200;
    /// Working.
    pub const WORKING: u64 = 0x0000_0000_0000_0400;
}

/// How a DCC directive interacts with navigation / channel-number
/// display (A/65 §6.7 Table 6.16, the `dcc_context` bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DccContext {
    /// `'0'` — Temporary Retune: acquire the "to" channel but keep
    /// displaying the "from" channel number; only a Return-to-Original
    /// request (or the end time / a manual change) undoes it (§6.7.1).
    TemporaryRetune,
    /// `'1'` — Channel Redirect: an ordinary channel change to the
    /// "to" channel; further DCC requests stay accepted (§6.7.2).
    ChannelRedirect,
}

/// Classified `dcc_selection_type` per A/65 §6.7 Table 6.17.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DccSelectionCategory {
    /// `0x00` — term always evaluates True.
    Unconditional,
    /// `0x01` / `0x11` — numeric postal-code test (the flag is `true`
    /// for the `0x11` exclusion form). `dcc_selection_id` carries 8
    /// ASCII characters, `'?'` wild-carding a digit.
    NumericPostalCode { exclusion: bool },
    /// `0x02` / `0x12` — alphanumeric postal-code test (the flag is
    /// `true` for the `0x12` exclusion form).
    AlphanumericPostalCode { exclusion: bool },
    /// `0x05` / `0x15` — membership (or non-membership, `negated`)
    /// in at least one Table 6.18 demographic category.
    DemographicOneOrMore { negated: bool },
    /// `0x06` / `0x16` — membership (or non-membership, `negated`)
    /// in all indicated Table 6.18 demographic categories.
    DemographicAll { negated: bool },
    /// `0x07` / `0x17` — interest (or non-interest, `negated`) in at
    /// least one Table 6.20 genre category.
    GenreOneOrMore { negated: bool },
    /// `0x08` / `0x18` — interest (or non-interest, `negated`) in all
    /// indicated Table 6.20 genre categories.
    GenreAll { negated: bool },
    /// `0x09` — True when the receiver cannot be authorized to decode
    /// the "from" channel's services.
    CannotBeAuthorized,
    /// `0x0C` / `0x1C` — geographic location_code test (the flag is
    /// `true` for the `0x1C` exclusion form).
    GeographicLocation { exclusion: bool },
    /// `0x0D` — True when the current program is rating-blocked.
    RatingBlocked,
    /// `0x0F` — unconditional return to the original channel.
    ReturnToOriginalChannel,
    /// `0x20..=0x23` — Viewer Direct Select buttons A–D (`button` is
    /// 0 for A .. 3 for D).
    ViewerDirectSelect { button: u8 },
    /// Any Table 6.17 reserved code point.
    Reserved,
}

impl DccSelectionCategory {
    /// Classify a raw `dcc_selection_type` per Table 6.17.
    pub fn classify(selection_type: u8) -> Self {
        match selection_type {
            0x00 => Self::Unconditional,
            0x01 => Self::NumericPostalCode { exclusion: false },
            0x02 => Self::AlphanumericPostalCode { exclusion: false },
            0x05 => Self::DemographicOneOrMore { negated: false },
            0x06 => Self::DemographicAll { negated: false },
            0x07 => Self::GenreOneOrMore { negated: false },
            0x08 => Self::GenreAll { negated: false },
            0x09 => Self::CannotBeAuthorized,
            0x0C => Self::GeographicLocation { exclusion: false },
            0x0D => Self::RatingBlocked,
            0x0F => Self::ReturnToOriginalChannel,
            0x11 => Self::NumericPostalCode { exclusion: true },
            0x12 => Self::AlphanumericPostalCode { exclusion: true },
            0x15 => Self::DemographicOneOrMore { negated: true },
            0x16 => Self::DemographicAll { negated: true },
            0x17 => Self::GenreOneOrMore { negated: true },
            0x18 => Self::GenreAll { negated: true },
            0x1C => Self::GeographicLocation { exclusion: true },
            0x20..=0x23 => Self::ViewerDirectSelect {
                button: selection_type - 0x20,
            },
            _ => Self::Reserved,
        }
    }
}

/// One `dcc_term_count` entry of a [`DccTest`] (A/65 §6.7 Table 6.15)
/// — a single selection criterion; all terms of a test AND together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccTerm {
    /// Raw 8-bit `dcc_selection_type` (Table 6.17) — see
    /// [`Self::category`].
    pub selection_type: u8,
    /// 64-bit `dcc_selection_id` — the data the selection type tests
    /// against; see [`Self::postal_code_text`] / [`Self::genre_codes`]
    /// and the [`dcc_demographic`] bit assignments.
    pub selection_id: u64,
    /// Raw bytes of the term's descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl DccTerm {
    /// The Table 6.17 classification of [`Self::selection_type`].
    pub fn category(&self) -> DccSelectionCategory {
        DccSelectionCategory::classify(self.selection_type)
    }

    /// The postal-code characters of a postal-code term — the eight
    /// `dcc_selection_id` bytes as ISO/IEC 8859-1 text (numeric codes
    /// are right-justified five digits padded with `'0'`; alphanumeric
    /// codes are right-justified padded with spaces; `'?'` is a wild
    /// card). `None` when the term is not a postal-code test.
    pub fn postal_code_text(&self) -> Option<String> {
        match self.category() {
            DccSelectionCategory::NumericPostalCode { .. }
            | DccSelectionCategory::AlphanumericPostalCode { .. } => Some(
                self.selection_id
                    .to_be_bytes()
                    .iter()
                    .map(|&b| b as char)
                    .collect(),
            ),
            _ => None,
        }
    }

    /// The genre-category selection codes of a genre term — the
    /// non-zero `dcc_selection_id` bytes (codes pack right-justified,
    /// `0x00` marks an unused slot per Table 6.19), most significant
    /// first. `None` when the term is not a genre test.
    pub fn genre_codes(&self) -> Option<Vec<u8>> {
        match self.category() {
            DccSelectionCategory::GenreOneOrMore { .. } | DccSelectionCategory::GenreAll { .. } => {
                Some(
                    self.selection_id
                        .to_be_bytes()
                        .iter()
                        .copied()
                        .filter(|&b| b != 0)
                        .collect(),
                )
            }
            _ => None,
        }
    }

    /// Walk this term's descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

/// One `dcc_test_count` entry of a [`DirectedChannelChangeTable`]
/// (A/65 §6.7 Table 6.15) — a single DCC request: change from one
/// virtual channel to another between two GPS instants when every
/// term evaluates True.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccTest {
    /// The Table 6.16 `dcc_context` — Temporary Retune vs Channel
    /// Redirect handling.
    pub context: DccContext,
    /// 10-bit `dcc_from_major_channel_number` (1–999).
    pub from_major_channel_number: u16,
    /// 10-bit `dcc_from_minor_channel_number` (1–999).
    pub from_minor_channel_number: u16,
    /// 10-bit `dcc_to_major_channel_number` (1–999).
    pub to_major_channel_number: u16,
    /// 10-bit `dcc_to_minor_channel_number` (1–999).
    pub to_minor_channel_number: u16,
    /// `dcc_start_time` — GPS seconds (see [`gps_to_unix`]).
    pub start_time: u32,
    /// `dcc_end_time` — GPS seconds (see [`gps_to_unix`]).
    pub end_time: u32,
    /// The request's terms — all must evaluate True (an OR is spelled
    /// as separate tests).
    pub terms: Vec<DccTerm>,
    /// Raw bytes of the test's descriptor loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl DccTest {
    /// Walk this test's descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

/// Read the §6.7/§6.8 `reserved (6) | length (10)` descriptor-loop
/// header at `body[i..]` and return `(loop_bytes, next_index)`.
fn dcc_descriptor_loop<'a>(
    body: &'a [u8],
    i: usize,
    what: &'static str,
) -> Result<(&'a [u8], usize), TsError> {
    if i + 2 > body.len() {
        return Err(TsError::Truncated {
            what,
            have: body.len().saturating_sub(i),
            need: 2,
        });
    }
    let len = (((body[i] & 0x03) as usize) << 8) | body[i + 1] as usize;
    let start = i + 2;
    if start + len > body.len() {
        return Err(TsError::SectionLengthOverrun {
            claimed: len,
            have: body.len() - start,
        });
    }
    Ok((&body[start..start + len], start + len))
}

/// Parsed Directed Channel Change Table section (A/65 §6.7
/// Table 6.15) — carried on [`ATSC_BASE_PID`] with `table_id == 0xD3`,
/// always a single section (`section_number == 0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectedChannelChangeTable {
    /// 8-bit `dcc_id` distinguishing concurrently transmitted DCCT
    /// instances (the MGT announces each as `table_type 0x1400 +
    /// dcc_id`).
    pub dcc_id: u8,
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// The channel-change requests; the receiver acts on the first
    /// eligible one.
    pub tests: Vec<DccTest>,
    /// Raw bytes of the `dcc_additional_descriptors` loop — walk with
    /// [`Self::iter_descriptors`].
    pub additional_descriptors: Vec<u8>,
}

impl DirectedChannelChangeTable {
    /// Parse a single DCCT section (from `table_id` through the CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_psip_section(section, DCCT_TABLE_ID)?;
        // The table_id_extension position carries dcc_subtype (high
        // byte) + dcc_id (low byte). Only dcc_subtype 0x00 is defined;
        // a non-zero value signals a structurally different future
        // table (§6.7).
        if hdr.table_id_extension >> 8 != 0 {
            return Err(TsError::Unsupported(
                "DCCT dcc_subtype is not zero (A/65 defines only zero)",
            ));
        }
        let dcc_id = (hdr.table_id_extension & 0xFF) as u8;
        let (&test_count, rest) = body.split_first().ok_or(TsError::Truncated {
            what: "DCCT dcc_test_count",
            have: 0,
            need: 1,
        })?;
        let mut i = 0usize;
        let mut tests = Vec::with_capacity((test_count as usize).min(64));
        for _ in 0..test_count {
            // dcc_context (1) + reserved (3) + from major/minor (20),
            // reserved (4) + to major/minor (20), start (32), end
            // (32), dcc_term_count (8) = 15 fixed bytes.
            if i + 15 > rest.len() {
                return Err(TsError::Truncated {
                    what: "DCCT test entry",
                    have: rest.len() - i,
                    need: 15,
                });
            }
            let context = if rest[i] & 0x80 != 0 {
                DccContext::ChannelRedirect
            } else {
                DccContext::TemporaryRetune
            };
            let from_major = (((rest[i] & 0x0F) as u16) << 6) | (rest[i + 1] >> 2) as u16;
            let from_minor = (((rest[i + 1] & 0x03) as u16) << 8) | rest[i + 2] as u16;
            let to_major = (((rest[i + 3] & 0x0F) as u16) << 6) | (rest[i + 4] >> 2) as u16;
            let to_minor = (((rest[i + 4] & 0x03) as u16) << 8) | rest[i + 5] as u16;
            let start_time =
                u32::from_be_bytes([rest[i + 6], rest[i + 7], rest[i + 8], rest[i + 9]]);
            let end_time =
                u32::from_be_bytes([rest[i + 10], rest[i + 11], rest[i + 12], rest[i + 13]]);
            let term_count = rest[i + 14] as usize;
            i += 15;
            let mut terms = Vec::with_capacity(term_count.min(64));
            for _ in 0..term_count {
                // dcc_selection_type (8) + dcc_selection_id (64) = 9
                // fixed bytes, then the term descriptor loop.
                if i + 9 > rest.len() {
                    return Err(TsError::Truncated {
                        what: "DCCT term entry",
                        have: rest.len() - i,
                        need: 9,
                    });
                }
                let selection_type = rest[i];
                let selection_id = u64::from_be_bytes([
                    rest[i + 1],
                    rest[i + 2],
                    rest[i + 3],
                    rest[i + 4],
                    rest[i + 5],
                    rest[i + 6],
                    rest[i + 7],
                    rest[i + 8],
                ]);
                let (descs, next) =
                    dcc_descriptor_loop(rest, i + 9, "DCCT dcc_term_descriptors_length")?;
                terms.push(DccTerm {
                    selection_type,
                    selection_id,
                    descriptors: descs.to_vec(),
                });
                i = next;
            }
            let (descs, next) = dcc_descriptor_loop(rest, i, "DCCT dcc_test_descriptors_length")?;
            tests.push(DccTest {
                context,
                from_major_channel_number: from_major,
                from_minor_channel_number: from_minor,
                to_major_channel_number: to_major,
                to_minor_channel_number: to_minor,
                start_time,
                end_time,
                terms,
                descriptors: descs.to_vec(),
            });
            i = next;
        }
        let (descs, next) = dcc_descriptor_loop(rest, i, "DCCT dcc_additional_descriptors_length")?;
        if next != rest.len() {
            return Err(TsError::Unsupported(
                "DCCT loops do not fill the section exactly",
            ));
        }
        Ok(Self {
            dcc_id,
            version_number: hdr.version_number,
            tests,
            additional_descriptors: descs.to_vec(),
        })
    }

    /// Walk the `dcc_additional_descriptors` loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.additional_descriptors)
    }
}

// ---------------------------------------------------------------------------
// DCC Selection Code Table (§6.8)
// ---------------------------------------------------------------------------

/// One update of a [`DccSelectionCodeTable`] (A/65 §6.8 Table 6.23) —
/// an extension of the Table 6.20 genre codes or the annex-H
/// state / county location codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DccsctUpdate {
    /// `update_type 0x01` — a new Table 6.20 genre category: the code
    /// (`0x01..=0x1F` basic / `0xAE..=0xFE` detailed) plus its display
    /// name (≤ 24 characters).
    NewGenreCategory {
        /// 8-bit `genre_category_code`.
        genre_category_code: u8,
        /// The genre category name.
        name: MultipleStringStructure,
    },
    /// `update_type 0x02` — a new State / Territory: the location code
    /// (79–99) plus its name.
    NewState {
        /// 8-bit `dcc_state_location_code`.
        dcc_state_location_code: u8,
        /// The State / Territory name.
        name: MultipleStringStructure,
    },
    /// `update_type 0x03` — a new county within a State: the FIPS
    /// `state_code` (0–99), the 10-bit county code (1–999), and the
    /// county name.
    NewCounty {
        /// 8-bit `state_code`.
        state_code: u8,
        /// 10-bit `dcc_county_location_code`.
        dcc_county_location_code: u16,
        /// The county name.
        name: MultipleStringStructure,
    },
    /// A Table 6.24 reserved `update_type` — skipped via
    /// `update_data_length` per §6.8, body kept raw.
    Unknown {
        /// The raw 8-bit `update_type`.
        update_type: u8,
        /// The raw update body.
        data: Vec<u8>,
    },
}

/// One `updates_defined` entry of a [`DccSelectionCodeTable`] — the
/// typed update plus its descriptor loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccsctUpdateEntry {
    /// The typed update.
    pub update: DccsctUpdate,
    /// Raw bytes of the update's `dccsct_descriptors` loop — walk with
    /// [`Self::iter_descriptors`].
    pub descriptors: Vec<u8>,
}

impl DccsctUpdateEntry {
    /// Walk this update's descriptor loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.descriptors)
    }
}

/// Parsed DCC Selection Code Table section (A/65 §6.8 Table 6.23) —
/// carried on [`ATSC_BASE_PID`] with `table_id == 0xD4`, always a
/// single section; extends the genre / location code sets the DCCT
/// selection terms reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccSelectionCodeTable {
    /// 5-bit `version_number`.
    pub version_number: u8,
    /// The code-set updates.
    pub updates: Vec<DccsctUpdateEntry>,
    /// Raw bytes of the `dccsct_additional_descriptors` loop — walk
    /// with [`Self::iter_descriptors`].
    pub additional_descriptors: Vec<u8>,
}

impl DccSelectionCodeTable {
    /// Parse a single DCCSCT section (from `table_id` through the
    /// CRC).
    pub fn parse(section: &[u8]) -> Result<Self, TsError> {
        let (hdr, body) = parse_psip_section(section, DCCSCT_TABLE_ID)?;
        // The table_id_extension position carries the 16-bit
        // dccsct_type; only 0x0000 is defined, and §6.8 expects
        // receivers to discard sections with a non-zero value.
        if hdr.table_id_extension != 0 {
            return Err(TsError::Unsupported(
                "DCCSCT dccsct_type is not zero (A/65 defines only zero)",
            ));
        }
        let (&updates_defined, rest) = body.split_first().ok_or(TsError::Truncated {
            what: "DCCSCT updates_defined",
            have: 0,
            need: 1,
        })?;
        let mut i = 0usize;
        let mut updates = Vec::with_capacity((updates_defined as usize).min(64));
        for _ in 0..updates_defined {
            if i + 2 > rest.len() {
                return Err(TsError::Truncated {
                    what: "DCCSCT update entry",
                    have: rest.len() - i,
                    need: 2,
                });
            }
            let update_type = rest[i];
            let data_len = rest[i + 1] as usize;
            i += 2;
            if i + data_len > rest.len() {
                return Err(TsError::SectionLengthOverrun {
                    claimed: data_len,
                    have: rest.len() - i,
                });
            }
            let data = &rest[i..i + data_len];
            i += data_len;
            let update = Self::parse_update(update_type, data)?;
            let (descs, next) = dcc_descriptor_loop(rest, i, "DCCSCT dccsct_descriptors_length")?;
            updates.push(DccsctUpdateEntry {
                update,
                descriptors: descs.to_vec(),
            });
            i = next;
        }
        let (descs, next) =
            dcc_descriptor_loop(rest, i, "DCCSCT dccsct_additional_descriptors_length")?;
        if next != rest.len() {
            return Err(TsError::Unsupported(
                "DCCSCT loops do not fill the section exactly",
            ));
        }
        Ok(Self {
            version_number: hdr.version_number,
            updates,
            additional_descriptors: descs.to_vec(),
        })
    }

    /// Decode one Table 6.24-typed update body (`data` spans exactly
    /// `update_data_length` bytes).
    fn parse_update(update_type: u8, data: &[u8]) -> Result<DccsctUpdate, TsError> {
        /// Parse an MSS that must fill `bytes` exactly.
        fn full_mss(bytes: &[u8], what: &'static str) -> Result<MultipleStringStructure, TsError> {
            let (mss, used) = MultipleStringStructure::parse(bytes)?;
            if used != bytes.len() {
                return Err(TsError::Unsupported(what));
            }
            Ok(mss)
        }
        match update_type {
            0x01 => {
                // new_genre_category: genre_category_code (8) +
                // genre_category_name_text().
                let (&code, text) = data.split_first().ok_or(TsError::Truncated {
                    what: "DCCSCT genre_category_code",
                    have: 0,
                    need: 1,
                })?;
                Ok(DccsctUpdate::NewGenreCategory {
                    genre_category_code: code,
                    name: full_mss(
                        text,
                        "DCCSCT genre_category_name_text does not fill the update exactly",
                    )?,
                })
            }
            0x02 => {
                // new_state: dcc_state_location_code (8) +
                // dcc_state_location_code_text().
                let (&code, text) = data.split_first().ok_or(TsError::Truncated {
                    what: "DCCSCT dcc_state_location_code",
                    have: 0,
                    need: 1,
                })?;
                Ok(DccsctUpdate::NewState {
                    dcc_state_location_code: code,
                    name: full_mss(
                        text,
                        "DCCSCT dcc_state_location_code_text does not fill the update exactly",
                    )?,
                })
            }
            0x03 => {
                // new_county: state_code (8), reserved (6) |
                // dcc_county_location_code (10), then
                // dcc_county_location_code_text().
                if data.len() < 3 {
                    return Err(TsError::Truncated {
                        what: "DCCSCT new_county header",
                        have: data.len(),
                        need: 3,
                    });
                }
                let county = (((data[1] & 0x03) as u16) << 8) | data[2] as u16;
                Ok(DccsctUpdate::NewCounty {
                    state_code: data[0],
                    dcc_county_location_code: county,
                    name: full_mss(
                        &data[3..],
                        "DCCSCT dcc_county_location_code_text does not fill the update exactly",
                    )?,
                })
            }
            _ => Ok(DccsctUpdate::Unknown {
                update_type,
                data: data.to_vec(),
            }),
        }
    }

    /// Walk the `dccsct_additional_descriptors` loop.
    pub fn iter_descriptors(&self) -> AtscDescriptorIter<'_> {
        iter_atsc_descriptors(&self.additional_descriptors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psi::mpeg2_crc32;

    /// Assemble an A/65 §4.1 PSIP long-form section: header,
    /// `protocol_version 0`, `body`, CRC-32. `private_indicator` is
    /// `'1'` per Table 4.1.
    fn psip_section(table_id: u8, table_id_extension: u16, version: u8, body: &[u8]) -> Vec<u8> {
        let section_length = 5 + 1 + body.len() + 4;
        let mut s = Vec::with_capacity(3 + section_length);
        s.push(table_id);
        s.push(0b1111_0000 | ((section_length >> 8) & 0x0F) as u8);
        s.push((section_length & 0xFF) as u8);
        s.extend_from_slice(&table_id_extension.to_be_bytes());
        s.push(0b1100_0001 | ((version & 0x1F) << 1));
        s.push(0); // section_number
        s.push(0); // last_section_number
        s.push(0); // protocol_version
        s.extend_from_slice(body);
        let crc = mpeg2_crc32(&s);
        s.extend_from_slice(&crc.to_be_bytes());
        s
    }

    /// Encode a single-language, single-segment uncompressed MSS.
    fn mss(lang: [u8; 3], mode: u8, bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![
            1,
            lang[0],
            lang[1],
            lang[2],
            1,
            0x00,
            mode,
            bytes.len() as u8,
        ];
        v.extend_from_slice(bytes);
        v
    }

    #[test]
    fn mss_range_select_and_utf16_decode() {
        let (m, used) = MultipleStringStructure::parse(&mss(*b"eng", 0x00, b"Movie!")).unwrap();
        assert_eq!(used, 8 + 6);
        assert_eq!(m.strings.len(), 1);
        assert_eq!(m.strings[0].language_code, *b"eng");
        assert_eq!(m.first_text().unwrap(), "Movie!");

        // Mode 0x0E selects the 0x0E00–0x0EFF range: byte 0x50 is
        // U+0E50 (the spec's own worked example bytes).
        let (m, _) = MultipleStringStructure::parse(&mss(*b"tha", 0x0E, &[0x50, 0x51])).unwrap();
        assert_eq!(
            m.first_text().unwrap(),
            "\u{0E50}\u{0E51}",
            "mode byte supplies the high 8 bits of each code point"
        );

        // Mode 0x3F is UTF-16 (big-endian code units).
        let (m, _) =
            MultipleStringStructure::parse(&mss(*b"jpn", 0x3F, &[0x30, 0x42, 0x30, 0x44])).unwrap();
        assert_eq!(m.first_text().unwrap(), "\u{3042}\u{3044}");

        // Huffman-compressed segments now decode via the annex-C
        // tables (pinned separately); a reserved compression type
        // stays raw.
        let mut h = mss(*b"eng", 0x00, &[0x12, 0x34]);
        h[5] = 0x03; // reserved compression_type
        let (m, _) = MultipleStringStructure::parse(&h).unwrap();
        assert!(m.first_text().is_none());
        assert_eq!(m.strings[0].segments[0].bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn mss_multi_string_multi_segment() {
        // Two strings; the first has two segments that concatenate.
        let mut v = vec![2];
        v.extend_from_slice(b"eng");
        v.push(2); // segments
        v.extend_from_slice(&[0x00, 0x00, 3]);
        v.extend_from_slice(b"Foo");
        v.extend_from_slice(&[0x00, 0x00, 3]);
        v.extend_from_slice(b"Bar");
        v.extend_from_slice(b"spa");
        v.push(1);
        v.extend_from_slice(&[0x00, 0x00, 4]);
        v.extend_from_slice(b"Cine");
        let (m, used) = MultipleStringStructure::parse(&v).unwrap();
        assert_eq!(used, v.len());
        assert_eq!(m.strings[0].decode().unwrap(), "FooBar");
        assert_eq!(m.strings[1].decode().unwrap(), "Cine");
    }

    #[test]
    fn mss_truncated_errors() {
        assert!(MultipleStringStructure::parse(&[]).is_err());
        assert!(MultipleStringStructure::parse(&[1, b'e', b'n']).is_err());
        // Segment claims more bytes than remain.
        let v = vec![1, b'e', b'n', b'g', 1, 0x00, 0x00, 10, b'x'];
        assert!(MultipleStringStructure::parse(&v).is_err());
    }

    #[test]
    fn stt_parses_time_and_daylight_saving() {
        // system_time = 1 000 000 000 GPS seconds, offset 18,
        // daylight_saving: DS_status=1, day 27, hour 2 →
        // 0b1_11_11011 0x02 (reserved bits '11').
        let mut body = Vec::new();
        body.extend_from_slice(&1_000_000_000u32.to_be_bytes());
        body.push(18);
        body.push(0b1111_1011);
        body.push(2);
        let s = psip_section(STT_TABLE_ID, 0x0000, 0, &body);
        let stt = SystemTimeTable::parse(&s).unwrap();
        assert_eq!(stt.system_time, 1_000_000_000);
        assert_eq!(stt.gps_utc_offset, 18);
        assert_eq!(stt.unix_time(), GPS_EPOCH_UNIX + 1_000_000_000 - 18);
        assert!(stt.ds_status());
        assert_eq!(stt.ds_day_of_month(), 27);
        assert_eq!(stt.ds_hour(), 2);
        assert!(stt.descriptors.is_empty());
    }

    #[test]
    fn stt_nonzero_protocol_version_is_unsupported() {
        let mut body = vec![0u8; 7];
        body.resize(7, 0);
        let mut s = psip_section(STT_TABLE_ID, 0x0000, 0, &body);
        // Patch protocol_version to 1 and re-CRC.
        s[8] = 1;
        let crc_pos = s.len() - 4;
        let crc = mpeg2_crc32(&s[..crc_pos]);
        s[crc_pos..].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            SystemTimeTable::parse(&s),
            Err(TsError::Unsupported(_))
        ));
    }

    #[test]
    fn mgt_parses_table_directory() {
        // Two entries: current TVCT on 0x1FFB and EIT-0 on 0x1D00.
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_be_bytes());
        // Entry 1: table_type 0x0000 (TVCT current), PID 0x1FFB,
        // version 3, 812 bytes, no descriptors.
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&[0xE0 | 0x1F, 0xFB]);
        body.push(0xE0 | 3);
        body.extend_from_slice(&812u32.to_be_bytes());
        body.extend_from_slice(&[0xF0, 0x00]);
        // Entry 2: table_type 0x0100 (EIT-0), PID 0x1D00, version 12,
        // 4096 bytes, one stuffing descriptor.
        body.extend_from_slice(&0x0100u16.to_be_bytes());
        body.extend_from_slice(&[0xE0 | 0x1D, 0x00]);
        body.push(0xE0 | 12);
        body.extend_from_slice(&4096u32.to_be_bytes());
        body.extend_from_slice(&[0xF0, 0x04, 0x80, 0x02, 0xFF, 0xFF]);
        // MGT-level loop: empty.
        body.extend_from_slice(&[0xF0, 0x00]);
        let s = psip_section(MGT_TABLE_ID, 0x0000, 7, &body);
        let mgt = MasterGuideTable::parse(&s).unwrap();
        assert_eq!(mgt.version_number, 7);
        assert_eq!(mgt.tables.len(), 2);
        assert_eq!(mgt.tables[0].table_type, 0x0000);
        assert_eq!(mgt.tables[0].pid, 0x1FFB);
        assert_eq!(mgt.tables[0].version_number, 3);
        assert_eq!(mgt.tables[0].number_bytes, 812);
        assert_eq!(mgt.tables[0].eit_index(), None);
        assert_eq!(mgt.tables[1].eit_index(), Some(0));
        assert_eq!(mgt.tables[1].pid, 0x1D00);
        let d = mgt.tables[1].iter_descriptors().next().unwrap().unwrap();
        assert!(matches!(d.body, AtscDescriptorBody::Stuffing(_)));
        assert!(mgt.descriptors.is_empty());
    }

    #[test]
    fn mgt_entry_classifiers() {
        let mut e = MgtTableEntry {
            table_type: 0x0205,
            pid: 0x1D05,
            version_number: 0,
            number_bytes: 0,
            descriptors: Vec::new(),
        };
        assert_eq!(e.event_ett_index(), Some(5));
        e.table_type = 0x0301;
        assert_eq!(e.rrt_rating_region(), Some(1));
        e.table_type = 0x017F;
        assert_eq!(e.eit_index(), Some(127));
        e.table_type = 0x1442;
        assert_eq!(e.dcct_dcc_id(), Some(0x42));
        assert!(!e.is_dccsct());
        e.table_type = 0x0005;
        assert!(e.is_dccsct());
        assert_eq!(e.dcct_dcc_id(), None);
    }

    /// Build one 32-byte VCT channel prefix + descriptor loop.
    #[allow(clippy::too_many_arguments)]
    fn vct_channel(
        name: &str,
        major: u16,
        minor: u16,
        program_number: u16,
        source_id: u16,
        flags0: u8,
        service_type: u8,
        descriptors: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        let mut units: Vec<u16> = name.encode_utf16().collect();
        units.resize(7, 0);
        for u in units {
            v.extend_from_slice(&u.to_be_bytes());
        }
        // reserved (4) | major (10) | minor (10).
        v.push(0xF0 | ((major >> 6) & 0x0F) as u8);
        v.push((((major & 0x3F) << 2) as u8) | ((minor >> 8) & 0x03) as u8);
        v.push((minor & 0xFF) as u8);
        v.push(0x04); // modulation_mode: 8-VSB
        v.extend_from_slice(&0u32.to_be_bytes()); // carrier_frequency
        v.extend_from_slice(&0x0F01u16.to_be_bytes()); // channel_TSID
        v.extend_from_slice(&program_number.to_be_bytes());
        v.push(flags0);
        v.push(0xC0 | (service_type & 0x3F));
        v.extend_from_slice(&source_id.to_be_bytes());
        v.push(0xFC | ((descriptors.len() >> 8) & 0x03) as u8);
        v.push((descriptors.len() & 0xFF) as u8);
        v.extend_from_slice(descriptors);
        v
    }

    #[test]
    fn tvct_round_trips_channels_and_service_location() {
        let sl_desc: &[u8] = &[
            0xA1,
            0x0F, // tag + len
            0xE0 | 0x10,
            0x11, // PCR_PID 0x1011
            0x02, // number_elements
            0x02,
            0xE0 | 0x10,
            0x11,
            0x00,
            0x00,
            0x00, // MPEG-2 video
            0x81,
            0xE0 | 0x11,
            0x00,
            b'e',
            b'n',
            b'g', // AC-3 audio
        ];
        let mut body = vec![2u8];
        // ETM_location 01, access_controlled 0, hidden 0, hide_guide 0:
        // f0 = 01 0 0 0 0 0 1 (trailing reserved '1').
        body.extend_from_slice(&vct_channel(
            "WOXA",
            12,
            1,
            3,
            0x1001,
            0b0100_0001,
            0x02,
            sl_desc,
        ));
        body.extend_from_slice(&vct_channel(
            "WOXA-SD",
            12,
            2,
            4,
            0x1002,
            0b0001_0011,
            0x03,
            &[],
        ));
        body.extend_from_slice(&[0xFC, 0x00]); // additional_descriptors_length 0
        let s = psip_section(TVCT_TABLE_ID, 0x0F01, 9, &body);
        let vct = VirtualChannelTable::parse(&s).unwrap();
        assert!(!vct.cable);
        assert_eq!(vct.transport_stream_id, 0x0F01);
        assert_eq!(vct.version_number, 9);
        assert_eq!(vct.channels.len(), 2);
        let c0 = &vct.channels[0];
        assert_eq!(c0.short_name_text(), "WOXA");
        assert_eq!((c0.major_channel_number, c0.minor_channel_number), (12, 1));
        assert_eq!(c0.modulation_mode, 0x04);
        assert_eq!(c0.channel_tsid, 0x0F01);
        assert_eq!(c0.program_number, 3);
        assert_eq!(c0.etm_location, 0b01);
        assert!(!c0.access_controlled);
        assert!(!c0.hidden);
        assert!(!c0.path_select, "TVCT reserved bit never reads as cable");
        assert_eq!(c0.service_type, 0x02);
        assert_eq!(c0.source_id, 0x1001);
        assert_eq!(c0.one_part_number(), None);
        match &c0.iter_descriptors().next().unwrap().unwrap().body {
            AtscDescriptorBody::ServiceLocation { pcr_pid, elements } => {
                assert_eq!(*pcr_pid, 0x1011);
                assert_eq!(elements.len(), 2);
                assert_eq!(elements[0].stream_type, 0x02);
                assert_eq!(elements[0].elementary_pid, 0x1011);
                assert_eq!(elements[1].stream_type, 0x81);
                assert_eq!(elements[1].language_code, *b"eng");
            }
            other => panic!("{other:?}"),
        }
        let c1 = &vct.channels[1];
        assert_eq!(c1.short_name_text(), "WOXA-SD");
        assert!(c1.hidden);
        assert!(c1.hide_guide);
        assert_eq!(c1.service_type, 0x03);
    }

    #[test]
    fn cvct_reads_cable_bits_and_one_part_number() {
        // One-part number: major's 6 msbs '111111', low nibble 0x3 →
        // one_part = (0x3 << 10) + 500.
        let major = 0b11_1111_0011u16; // 10-bit field
        let mut body = vec![1u8];
        // f0: ETM 00, AC 0, hidden 0, path_select 1, out_of_band 1,
        // hide_guide 0, reserved 1.
        body.extend_from_slice(&vct_channel(
            "CBL",
            major,
            500,
            7,
            0x2001,
            0b0000_1101,
            0x02,
            &[],
        ));
        body.extend_from_slice(&[0xFC, 0x00]);
        let s = psip_section(CVCT_TABLE_ID, 0x0F02, 1, &body);
        let vct = VirtualChannelTable::parse(&s).unwrap();
        assert!(vct.cable);
        let c = &vct.channels[0];
        assert!(c.path_select);
        assert!(c.out_of_band);
        assert_eq!(c.one_part_number(), Some((0x3 << 10) + 500));
    }

    #[test]
    fn rrt_round_trips_dimensions_and_values() {
        let region_name = mss(*b"eng", 0x00, b"US (50 states + possessions)");
        let dim_name = mss(*b"eng", 0x00, b"MPAA");
        let abbrev = mss(*b"eng", 0x00, b"PG");
        let full = mss(*b"eng", 0x00, b"Parental Guidance Suggested");
        let mut body = Vec::new();
        body.push(region_name.len() as u8);
        body.extend_from_slice(&region_name);
        body.push(1); // dimensions_defined
        body.push(dim_name.len() as u8);
        body.extend_from_slice(&dim_name);
        // reserved '111' | graduated_scale 1 | values_defined 1.
        body.push(0b1111_0001);
        body.push(abbrev.len() as u8);
        body.extend_from_slice(&abbrev);
        body.push(full.len() as u8);
        body.extend_from_slice(&full);
        body.extend_from_slice(&[0xFC, 0x00]); // descriptors_length 0
        let s = psip_section(RRT_TABLE_ID, 0xFF01, 2, &body);
        let rrt = RatingRegionTable::parse(&s).unwrap();
        assert_eq!(rrt.rating_region, 0x01);
        assert_eq!(
            rrt.rating_region_name.first_text().unwrap(),
            "US (50 states + possessions)"
        );
        assert_eq!(rrt.dimensions.len(), 1);
        let d = &rrt.dimensions[0];
        assert_eq!(d.dimension_name.first_text().unwrap(), "MPAA");
        assert!(d.graduated_scale);
        assert_eq!(d.values.len(), 1);
        assert_eq!(d.values[0].abbrev_rating_value.first_text().unwrap(), "PG");
        assert_eq!(
            d.values[0].rating_value.first_text().unwrap(),
            "Parental Guidance Suggested"
        );
    }

    #[test]
    fn atsc_eit_round_trips_events() {
        let title = mss(*b"eng", 0x00, b"Evening News");
        // content_advisory: one region, one dimension, empty MSS text.
        let ca: &[u8] = &[
            0x87,
            0x07,        // tag + len
            0xC0 | 0x01, // rating_region_count 1
            0x01,        // rating_region
            0x01,        // rated_dimensions
            0x00,
            0xF0 | 0x03, // dimension 0 → value 3
            0x01,        // rating_description_length
            0x00,        // MSS: number_strings 0
        ];
        let mut body = vec![1u8];
        // event_id 0x155 with '11' reserved bits.
        body.push(0xC0 | 0x01);
        body.push(0x55);
        body.extend_from_slice(&987_654_321u32.to_be_bytes());
        // reserved '11' | ETM_location 01 | length 1800 s (20 bits).
        let secs = 1800u32;
        body.push(0b1101_0000 | ((secs >> 16) & 0x0F) as u8);
        body.push(((secs >> 8) & 0xFF) as u8);
        body.push((secs & 0xFF) as u8);
        body.push(title.len() as u8);
        body.extend_from_slice(&title);
        body.push(0xF0 | ((ca.len() >> 8) & 0x0F) as u8);
        body.push((ca.len() & 0xFF) as u8);
        body.extend_from_slice(ca);
        let s = psip_section(ATSC_EIT_TABLE_ID, 0x1001, 4, &body);
        let eit = AtscEventInformationTable::parse(&s).unwrap();
        assert_eq!(eit.source_id, 0x1001);
        assert_eq!(eit.version_number, 4);
        assert_eq!(eit.events.len(), 1);
        let e = &eit.events[0];
        assert_eq!(e.event_id, 0x155);
        assert_eq!(e.start_time, 987_654_321);
        assert_eq!(e.etm_location, 0b01);
        assert_eq!(e.length_in_seconds, 1800);
        assert_eq!(e.title.first_text().unwrap(), "Evening News");
        match &e.iter_descriptors().next().unwrap().unwrap().body {
            AtscDescriptorBody::ContentAdvisory(regions) => {
                assert_eq!(regions.len(), 1);
                assert_eq!(regions[0].rating_region, 0x01);
                assert_eq!(regions[0].dimensions.len(), 1);
                assert_eq!(regions[0].dimensions[0].rating_dimension, 0);
                assert_eq!(regions[0].dimensions[0].rating_value, 3);
                assert!(regions[0].rating_description.strings.is_empty());
            }
            other => panic!("{other:?}"),
        }
        // Zero events is legal (§6.5: an instance with no events in
        // the slot carries num_events_in_section = 0).
        let s = psip_section(ATSC_EIT_TABLE_ID, 0x1002, 0, &[0]);
        assert!(AtscEventInformationTable::parse(&s)
            .unwrap()
            .events
            .is_empty());
    }

    #[test]
    fn ett_round_trips_channel_and_event_ids() {
        // Event ETM: source_id 0x1001, event_id 0x155, LSBs '10'.
        let etm_id: u32 = (0x1001u32 << 16) | (0x155u32 << 2) | 0b10;
        let msg = mss(*b"eng", 0x00, b"A long synopsis of the event.");
        let mut body = Vec::new();
        body.extend_from_slice(&etm_id.to_be_bytes());
        body.extend_from_slice(&msg);
        let s = psip_section(ETT_TABLE_ID, 0x0001, 1, &body);
        let ett = ExtendedTextTable::parse(&s).unwrap();
        assert_eq!(ett.source_id(), 0x1001);
        assert!(ett.is_event_etm());
        assert_eq!(ett.event_id(), Some(0x155));
        assert_eq!(
            ett.message.first_text().unwrap(),
            "A long synopsis of the event."
        );

        // Channel ETM: LSBs '00'.
        let etm_id: u32 = 0x1001u32 << 16;
        let mut body = Vec::new();
        body.extend_from_slice(&etm_id.to_be_bytes());
        body.extend_from_slice(&mss(*b"eng", 0x00, b"About this channel."));
        let s = psip_section(ETT_TABLE_ID, 0x0002, 1, &body);
        let ett = ExtendedTextTable::parse(&s).unwrap();
        assert!(!ett.is_event_etm());
        assert_eq!(ett.event_id(), None);
    }

    #[test]
    fn caption_service_descriptor_decodes_both_forms() {
        // Two services: a 708 digital service and a 608 stream.
        let d: &[u8] = &[
            0xE0 | 2, // reserved '111' | number_of_services — wait, 3+5 bits
            b'e',
            b'n',
            b'g',
            0b1100_0000 | 0x05, // digital_cc 1, reserved 1, service number 5
            0b1100_0000,
            0xFF, // easy_reader 1, wide_aspect_ratio 1, reserved
            b's',
            b'p',
            b'a',
            0b0111_1111, // digital_cc 0 → line21_field 1
            0x3F,
            0xFF,
        ];
        match decode_atsc_descriptor(0x86, d) {
            AtscDescriptorBody::CaptionService(entries) => {
                assert_eq!(entries.len(), 2);
                assert!(entries[0].digital_cc);
                assert_eq!(entries[0].caption_service_number, 5);
                assert!(entries[0].easy_reader);
                assert!(entries[0].wide_aspect_ratio);
                assert!(!entries[1].digital_cc);
                assert!(entries[1].line21_field);
                assert_eq!(entries[1].language, *b"spa");
            }
            other => panic!("{other:?}"),
        }
        // Truncated body falls back to Raw.
        assert_eq!(
            decode_atsc_descriptor(0x86, &d[..5]),
            AtscDescriptorBody::Raw
        );
    }

    #[test]
    fn time_shifted_service_descriptor_decodes() {
        let d: &[u8] = &[
            0xE0 | 1, // number_of_services 1
            0xFC | 0x01,
            0x2C, // time_shift 300 minutes (0x12C)
            0xF0,
            12 << 2,
            0x02, // major 12, minor 2
        ];
        match decode_atsc_descriptor(0xA2, d) {
            AtscDescriptorBody::TimeShiftedService(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].time_shift_minutes, 300);
                assert_eq!(v[0].major_channel_number, 12);
                assert_eq!(v[0].minor_channel_number, 2);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn name_and_dcc_and_misc_descriptors_decode() {
        let name = mss(*b"eng", 0x00, b"The Oxide Channel");
        match decode_atsc_descriptor(0xA0, &name) {
            AtscDescriptorBody::ExtendedChannelName(m) => {
                assert_eq!(m.first_text().unwrap(), "The Oxide Channel");
            }
            other => panic!("{other:?}"),
        }
        match decode_atsc_descriptor(0xA3, &name) {
            AtscDescriptorBody::ComponentName(m) => {
                assert_eq!(m.first_text().unwrap(), "The Oxide Channel");
            }
            other => panic!("{other:?}"),
        }
        let text = mss(*b"eng", 0x00, b"Channel change ahead");
        let mut d = vec![0x02, text.len() as u8];
        d.extend_from_slice(&text);
        match decode_atsc_descriptor(0xA8, &d) {
            AtscDescriptorBody::DccDepartingRequest { request_type, text } => {
                assert_eq!(request_type, 0x02);
                assert_eq!(text.first_text().unwrap(), "Channel change ahead");
            }
            other => panic!("{other:?}"),
        }
        match decode_atsc_descriptor(0xA9, &d) {
            AtscDescriptorBody::DccArrivingRequest { request_type, .. } => {
                assert_eq!(request_type, 0x02);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            decode_atsc_descriptor(0xAA, &[]),
            AtscDescriptorBody::RedistributionControl(Vec::new())
        );
        match decode_atsc_descriptor(0xAB, &[0xE0 | 2, 0x20, 0x35]) {
            AtscDescriptorBody::Genre(attrs) => assert_eq!(attrs, vec![0x20, 0x35]),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            decode_atsc_descriptor(0x81, &[0x10, 0x20]),
            AtscDescriptorBody::Ac3AudioStream(vec![0x10, 0x20])
        );
        assert_eq!(
            decode_atsc_descriptor(0x42, &[1, 2]),
            AtscDescriptorBody::Raw
        );
    }

    /// Test-local annex-C encoder — the inverse of
    /// `huffman_decode_text`, used to pin decode round-trips. Emits
    /// the order-1 code for each character (Terminate appended), the
    /// §C.2.1 escape + 8-bit literal when the pair has no code, and a
    /// raw 8-bit character after any prior ≥ 128.
    fn huffman_encode_text(text: &[u8], table: &'static [(u8, u8, u8, u16)]) -> Vec<u8> {
        let mut bits: Vec<u16> = Vec::new();
        let push_code = |bits: &mut Vec<u16>, len: u8, code: u16| {
            for k in (0..len).rev() {
                bits.push((code >> k) & 1);
            }
        };
        let mut prior = 0u8;
        for &ch in text.iter().chain(std::iter::once(&0u8)) {
            if prior >= 128 {
                push_code(&mut bits, 8, ch as u16);
            } else {
                let ctx = huffman_context(table, prior);
                if let Some(e) = ctx.iter().find(|e| e.1 == ch) {
                    push_code(&mut bits, e.2, e.3);
                } else {
                    let esc = ctx
                        .iter()
                        .find(|e| e.1 == 27)
                        .expect("every context escapes");
                    push_code(&mut bits, esc.2, esc.3);
                    push_code(&mut bits, 8, ch as u16);
                }
            }
            prior = ch;
        }
        let mut out = Vec::with_capacity(bits.len().div_ceil(8));
        for chunk in bits.chunks(8) {
            let mut b = 0u8;
            for (k, &bit) in chunk.iter().enumerate() {
                b |= (bit as u8) << (7 - k);
            }
            out.push(b);
        }
        out
    }

    #[test]
    fn annex_c_tables_are_complete_prefix_free_trees() {
        for table in [
            crate::atsc_huffman::TITLE_CODES,
            crate::atsc_huffman::DESCRIPTION_CODES,
        ] {
            // Sorted by (prior, symbol), one context per possible
            // prior character.
            assert!(table
                .windows(2)
                .all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1)));
            for prior in 0u8..128 {
                let ctx = huffman_context(table, prior);
                assert!(!ctx.is_empty(), "context {prior} missing");
                // The order-1 escape is reachable from every context.
                assert!(
                    ctx.iter().any(|e| e.1 == 27),
                    "context {prior} cannot escape"
                );
                // Prefix-free: no code is a prefix of another.
                for (i, a) in ctx.iter().enumerate() {
                    assert!(a.2 >= 1 && a.2 <= 11);
                    for b in &ctx[i + 1..] {
                        let (short, long) = if a.2 <= b.2 { (a, b) } else { (b, a) };
                        assert_ne!(
                            long.3 >> (long.2 - short.2),
                            short.3,
                            "context {prior}: prefix clash {a:?} vs {b:?}"
                        );
                    }
                }
                // Multi-entry contexts are COMPLETE binary trees: the
                // Kraft sum equals one exactly (single-entry contexts
                // are printed in the spec as the lone escape at code
                // '1', giving 1/2).
                let kraft: u32 = ctx.iter().map(|e| 1u32 << (11 - e.2)).sum();
                if ctx.len() > 1 {
                    assert_eq!(kraft, 1 << 11, "context {prior} tree incomplete");
                } else {
                    assert_eq!((ctx[0].1, ctx[0].2, ctx[0].3), (27, 1, 1));
                }
            }
        }
    }

    #[test]
    fn annex_c_spot_codes_match_the_printed_table() {
        use crate::atsc_huffman::TITLE_CODES;
        // A handful of literals read straight off Table C4: the
        // Terminate context codes 'S' as 000 and 'T' as 010; a space
        // codes 'T' as 1000; '1' codes '9' as 00; an apostrophe codes
        // 's' as 1.
        for want in [
            (0u8, b'S', 3u8, 0b000u16),
            (0, b'T', 3, 0b010),
            (b' ', b'T', 4, 0b1000),
            (b'1', b'9', 2, 0b00),
            (b'\'', b's', 1, 0b1),
        ] {
            assert!(
                TITLE_CODES.contains(&want),
                "missing spot-check entry {want:?}"
            );
        }
    }

    #[test]
    fn annex_c_decode_round_trips_typical_text() {
        for table in [
            crate::atsc_huffman::TITLE_CODES,
            crate::atsc_huffman::DESCRIPTION_CODES,
        ] {
            for text in [
                &b"The Evening News"[..],
                b"Movie: The Great Escape (1963)",
                b"SPORTS Tonight at 10:30",
                b"A",
                b"",
                // Pairs with no order-1 code force the escape path.
                b"qp qq zx",
                // A Latin-1 character (>= 128) forces the raw-follow
                // rule.
                b"Caf\xE9 au lait",
            ] {
                let coded = huffman_encode_text(text, table);
                let decoded = huffman_decode_text(&coded, table).expect("clean stream decodes");
                let want: String = text.iter().map(|&b| char::from(b)).collect();
                assert_eq!(decoded, want);
            }
        }
    }

    #[test]
    fn annex_c_decode_flags_corrupt_streams_not_panics() {
        // First title-context code space: '11001011' is the Terminate
        // context's ESC... corrupting bits must either error (None) or
        // decode to some bounded string — never panic. Sweep all
        // single-byte streams plus a few longer patterns.
        for b in 0u8..=255 {
            let _ = huffman_decode_text(&[b], crate::atsc_huffman::TITLE_CODES);
            let _ = huffman_decode_text(&[b, !b, b], crate::atsc_huffman::DESCRIPTION_CODES);
        }
    }

    #[test]
    fn mss_huffman_segment_decodes_through_the_structure() {
        let coded = huffman_encode_text(b"Evening News", crate::atsc_huffman::TITLE_CODES);
        let mut v = vec![1u8, b'e', b'n', b'g', 1, 0x01, 0xFF, coded.len() as u8];
        v.extend_from_slice(&coded);
        let (m, used) = MultipleStringStructure::parse(&v).unwrap();
        assert_eq!(used, v.len());
        assert_eq!(m.first_text().unwrap(), "Evening News");

        // compression_type 0x02 with text mode 0x00 (the §6.10
        // spelling).
        let coded = huffman_encode_text(
            b"A long description of the program.",
            crate::atsc_huffman::DESCRIPTION_CODES,
        );
        let mut v = vec![1u8, b'e', b'n', b'g', 1, 0x02, 0x00, coded.len() as u8];
        v.extend_from_slice(&coded);
        let (m, _) = MultipleStringStructure::parse(&v).unwrap();
        assert_eq!(
            m.first_text().unwrap(),
            "A long description of the program."
        );

        // A Huffman segment with a non-text mode stays undecoded.
        let seg = MssSegment {
            compression_type: 0x01,
            mode: 0x3F,
            bytes: vec![0x12],
        };
        assert!(seg.decode().is_none());
    }

    #[test]
    fn descriptor_iter_reports_truncated_tlv() {
        let mut it = iter_atsc_descriptors(&[0x80, 0x05, 0xFF]);
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    #[test]
    fn corrupt_crc_is_rejected() {
        let mut s = psip_section(STT_TABLE_ID, 0x0000, 0, &[0, 0, 0, 0, 0, 0, 0]);
        let last = s.len() - 1;
        s[last] ^= 0xFF;
        assert!(SystemTimeTable::parse(&s).is_err());
    }

    /// Append a §6.7/§6.8 `reserved (6) | length (10)` descriptor-loop
    /// header + bytes.
    fn push_dcc_loop(v: &mut Vec<u8>, descs: &[u8]) {
        v.push(0xFC | ((descs.len() >> 8) as u8 & 0x03));
        v.push(descs.len() as u8);
        v.extend_from_slice(descs);
    }

    /// Append the Table 6.15 fixed test-entry head (channel numbers +
    /// GPS window + term count).
    #[allow(clippy::too_many_arguments)]
    fn push_dcc_test_head(
        v: &mut Vec<u8>,
        redirect: bool,
        from: (u16, u16),
        to: (u16, u16),
        start: u32,
        end: u32,
        term_count: u8,
    ) {
        let ctx = if redirect { 0x80 } else { 0x00 };
        v.push(ctx | 0x70 | (from.0 >> 6) as u8);
        v.push(((from.0 & 0x3F) as u8) << 2 | (from.1 >> 8) as u8);
        v.push(from.1 as u8);
        v.push(0xF0 | (to.0 >> 6) as u8);
        v.push(((to.0 & 0x3F) as u8) << 2 | (to.1 >> 8) as u8);
        v.push(to.1 as u8);
        v.extend_from_slice(&start.to_be_bytes());
        v.extend_from_slice(&end.to_be_bytes());
        v.push(term_count);
    }

    #[test]
    fn dcct_round_trips_tests_terms_and_descriptors() {
        let mut body = vec![2u8]; // dcc_test_count

        // Test 1: Temporary Retune 12.1 → 12.2, two ANDed terms.
        push_dcc_test_head(
            &mut body,
            false,
            (12, 1),
            (12, 2),
            1_000_000_000,
            1_000_000_600,
            2,
        );
        // Term A: numeric postal inclusion on "00055?98", with a
        // stuffing descriptor in the term loop.
        body.push(0x01);
        body.extend_from_slice(b"00055?98");
        push_dcc_loop(&mut body, &[0x80, 2, 0xAA, 0xBB]);
        // Term B: demographic one-or-more (males or 18-34), bare.
        body.push(0x05);
        let demo = dcc_demographic::MALES | dcc_demographic::AGES_18_34;
        body.extend_from_slice(&demo.to_be_bytes());
        push_dcc_loop(&mut body, &[]);
        // Empty test descriptor loop.
        push_dcc_loop(&mut body, &[]);

        // Test 2: Channel Redirect at the 10-bit extremes, no terms,
        // a DCC departing request descriptor in the test loop.
        push_dcc_test_head(&mut body, true, (999, 999), (1, 1), 5, 6, 0);
        let text = mss(*b"eng", 0x00, b"Back soon");
        let mut dep = vec![0xA8, (2 + text.len()) as u8, 0x01, text.len() as u8];
        dep.extend_from_slice(&text);
        push_dcc_loop(&mut body, &dep);

        // dcc_additional_descriptors: one stuffing descriptor.
        push_dcc_loop(&mut body, &[0x80, 1, 0xFF]);

        let s = psip_section(DCCT_TABLE_ID, 0x0007, 9, &body);
        let dcct = DirectedChannelChangeTable::parse(&s).unwrap();
        assert_eq!(dcct.dcc_id, 7);
        assert_eq!(dcct.version_number, 9);
        assert_eq!(dcct.tests.len(), 2);

        let t = &dcct.tests[0];
        assert_eq!(t.context, DccContext::TemporaryRetune);
        assert_eq!(
            (t.from_major_channel_number, t.from_minor_channel_number),
            (12, 1)
        );
        assert_eq!(
            (t.to_major_channel_number, t.to_minor_channel_number),
            (12, 2)
        );
        assert_eq!((t.start_time, t.end_time), (1_000_000_000, 1_000_000_600));
        assert_eq!(t.terms.len(), 2);
        assert_eq!(
            t.terms[0].category(),
            DccSelectionCategory::NumericPostalCode { exclusion: false }
        );
        assert_eq!(t.terms[0].postal_code_text().unwrap(), "00055?98");
        assert!(t.terms[0].genre_codes().is_none());
        let d = t.terms[0].iter_descriptors().next().unwrap().unwrap();
        assert_eq!(d.tag, 0x80);
        assert_eq!(
            t.terms[1].category(),
            DccSelectionCategory::DemographicOneOrMore { negated: false }
        );
        assert_eq!(t.terms[1].selection_id, demo);
        assert!(t.terms[1].postal_code_text().is_none());

        let t = &dcct.tests[1];
        assert_eq!(t.context, DccContext::ChannelRedirect);
        assert_eq!(
            (t.from_major_channel_number, t.from_minor_channel_number),
            (999, 999),
            "10-bit channel numbers survive the 4/6 + 2/8 bit split"
        );
        assert_eq!(
            (t.to_major_channel_number, t.to_minor_channel_number),
            (1, 1)
        );
        assert!(t.terms.is_empty());
        match t.iter_descriptors().next().unwrap().unwrap().body {
            AtscDescriptorBody::DccDepartingRequest { request_type, text } => {
                assert_eq!(request_type, 0x01);
                assert_eq!(text.first_text().unwrap(), "Back soon");
            }
            other => panic!("expected DCC departing request, got {other:?}"),
        }

        let d = dcct.iter_descriptors().next().unwrap().unwrap();
        assert_eq!(d.tag, 0x80);
        assert_eq!(d.body, AtscDescriptorBody::Stuffing(vec![0xFF]));
    }

    #[test]
    fn dcc_selection_categories_classify_per_table_6_17() {
        for (code, want) in [
            (0x00, DccSelectionCategory::Unconditional),
            (0x09, DccSelectionCategory::CannotBeAuthorized),
            (0x0D, DccSelectionCategory::RatingBlocked),
            (0x0F, DccSelectionCategory::ReturnToOriginalChannel),
            (
                0x11,
                DccSelectionCategory::NumericPostalCode { exclusion: true },
            ),
            (
                0x12,
                DccSelectionCategory::AlphanumericPostalCode { exclusion: true },
            ),
            (0x16, DccSelectionCategory::DemographicAll { negated: true }),
            (
                0x0C,
                DccSelectionCategory::GeographicLocation { exclusion: false },
            ),
            (
                0x1C,
                DccSelectionCategory::GeographicLocation { exclusion: true },
            ),
            (0x22, DccSelectionCategory::ViewerDirectSelect { button: 2 }),
            (0x03, DccSelectionCategory::Reserved),
            (0x24, DccSelectionCategory::Reserved),
            (0xFF, DccSelectionCategory::Reserved),
        ] {
            assert_eq!(DccSelectionCategory::classify(code), want, "0x{code:02X}");
        }

        // Table 6.19 packing example: three codes in the least
        // significant 24 bits, zero bytes are unused slots.
        let term = DccTerm {
            selection_type: 0x07,
            selection_id: 0x0000_0000_0022_2120,
            descriptors: Vec::new(),
        };
        assert_eq!(term.genre_codes().unwrap(), vec![0x22, 0x21, 0x20]);
        let all = DccTerm {
            selection_type: 0x18,
            selection_id: 0x3031_3233_3435_3620,
            descriptors: Vec::new(),
        };
        assert_eq!(all.genre_codes().unwrap().len(), 8);
    }

    #[test]
    fn dcct_rejects_bad_subtype_truncation_and_slack() {
        // Non-zero dcc_subtype (high byte of the extension position).
        let mut body = vec![0u8];
        push_dcc_loop(&mut body, &[]);
        let s = psip_section(DCCT_TABLE_ID, 0x0100, 0, &body);
        assert!(matches!(
            DirectedChannelChangeTable::parse(&s),
            Err(TsError::Unsupported(_))
        ));

        // dcc_test_count promises a test the body cannot hold.
        let s = psip_section(DCCT_TABLE_ID, 0x0000, 0, &[1, 0xF0, 0x04]);
        assert!(matches!(
            DirectedChannelChangeTable::parse(&s),
            Err(TsError::Truncated { .. })
        ));

        // Term descriptor loop overruns the section body.
        let mut body = vec![1u8];
        push_dcc_test_head(&mut body, false, (2, 1), (2, 2), 0, 1, 1);
        body.push(0x00);
        body.extend_from_slice(&[0u8; 8]);
        body.push(0xFC | 0x01); // claims 256+ bytes of descriptors
        body.push(0x00);
        let s = psip_section(DCCT_TABLE_ID, 0x0000, 0, &body);
        assert!(matches!(
            DirectedChannelChangeTable::parse(&s),
            Err(TsError::SectionLengthOverrun { .. })
        ));

        // Trailing slack after the additional-descriptor loop.
        let mut body = vec![0u8];
        push_dcc_loop(&mut body, &[]);
        body.push(0xEE);
        let s = psip_section(DCCT_TABLE_ID, 0x0000, 0, &body);
        assert!(matches!(
            DirectedChannelChangeTable::parse(&s),
            Err(TsError::Unsupported(_))
        ));
    }

    #[test]
    fn dccsct_round_trips_all_update_types() {
        let mut body = vec![4u8]; // updates_defined

        // 0x01 new_genre_category.
        let name = mss(*b"eng", 0x00, b"Rugby");
        body.push(0x01);
        body.push((1 + name.len()) as u8);
        body.push(0x1A);
        body.extend_from_slice(&name);
        push_dcc_loop(&mut body, &[]);

        // 0x02 new_state, with a stuffing descriptor on the entry.
        let name = mss(*b"eng", 0x00, b"Newland");
        body.push(0x02);
        body.push((1 + name.len()) as u8);
        body.push(81);
        body.extend_from_slice(&name);
        push_dcc_loop(&mut body, &[0x80, 0]);

        // 0x03 new_county (10-bit county code).
        let name = mss(*b"eng", 0x00, b"Wayne");
        body.push(0x03);
        body.push((3 + name.len()) as u8);
        body.push(26);
        body.push(0xFC | ((163 >> 8) as u8));
        body.push(163u16 as u8);
        body.extend_from_slice(&name);
        push_dcc_loop(&mut body, &[]);

        // Reserved update type — must be skipped via
        // update_data_length and kept raw.
        body.push(0xB7);
        body.push(3);
        body.extend_from_slice(&[1, 2, 3]);
        push_dcc_loop(&mut body, &[]);

        push_dcc_loop(&mut body, &[0x80, 1, 0x00]);

        let s = psip_section(DCCSCT_TABLE_ID, 0x0000, 3, &body);
        let t = DccSelectionCodeTable::parse(&s).unwrap();
        assert_eq!(t.version_number, 3);
        assert_eq!(t.updates.len(), 4);
        match &t.updates[0].update {
            DccsctUpdate::NewGenreCategory {
                genre_category_code,
                name,
            } => {
                assert_eq!(*genre_category_code, 0x1A);
                assert_eq!(name.first_text().unwrap(), "Rugby");
            }
            other => panic!("expected genre update, got {other:?}"),
        }
        match &t.updates[1].update {
            DccsctUpdate::NewState {
                dcc_state_location_code,
                name,
            } => {
                assert_eq!(*dcc_state_location_code, 81);
                assert_eq!(name.first_text().unwrap(), "Newland");
            }
            other => panic!("expected state update, got {other:?}"),
        }
        assert_eq!(
            t.updates[1].iter_descriptors().next().unwrap().unwrap().tag,
            0x80
        );
        match &t.updates[2].update {
            DccsctUpdate::NewCounty {
                state_code,
                dcc_county_location_code,
                name,
            } => {
                assert_eq!(*state_code, 26);
                assert_eq!(*dcc_county_location_code, 163);
                assert_eq!(name.first_text().unwrap(), "Wayne");
            }
            other => panic!("expected county update, got {other:?}"),
        }
        assert_eq!(
            t.updates[3].update,
            DccsctUpdate::Unknown {
                update_type: 0xB7,
                data: vec![1, 2, 3],
            }
        );
        assert_eq!(t.additional_descriptors, vec![0x80, 1, 0x00]);
    }

    #[test]
    fn dccsct_rejects_bad_type_overrun_and_slack_mss() {
        // Non-zero dccsct_type is discarded per §6.8.
        let mut body = vec![0u8];
        push_dcc_loop(&mut body, &[]);
        let s = psip_section(DCCSCT_TABLE_ID, 0x0001, 0, &body);
        assert!(matches!(
            DccSelectionCodeTable::parse(&s),
            Err(TsError::Unsupported(_))
        ));

        // update_data_length overruns the body.
        let s = psip_section(DCCSCT_TABLE_ID, 0x0000, 0, &[1, 0x01, 200, 0x1A]);
        assert!(matches!(
            DccSelectionCodeTable::parse(&s),
            Err(TsError::SectionLengthOverrun { .. })
        ));

        // A known update whose MSS does not fill update_data_length
        // exactly.
        let name = mss(*b"eng", 0x00, b"X");
        let mut body = vec![1u8, 0x01, (1 + name.len() + 1) as u8, 0x1A];
        body.extend_from_slice(&name);
        body.push(0x00); // slack inside the update body
        push_dcc_loop(&mut body, &[]);
        push_dcc_loop(&mut body, &[]);
        let s = psip_section(DCCSCT_TABLE_ID, 0x0000, 0, &body);
        assert!(matches!(
            DccSelectionCodeTable::parse(&s),
            Err(TsError::Unsupported(_))
        ));
    }
}
