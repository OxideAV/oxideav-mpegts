//! Program / elementary-stream descriptor parser per ISO/IEC 13818-1
//! §2.6 ("Program and program element descriptors").
//!
//! Every descriptor on the wire is a TLV record:
//!
//! ```text
//! descriptor_tag    (8)
//! descriptor_length (8) — count of bytes after this field
//! descriptor data   (descriptor_length × 8)
//! ```
//!
//! `descriptor_length == 0` is legal (header-only descriptor). A
//! descriptor list lives either inside a PMT's `program_info` block
//! (program-wide) or inside one PMT entry's `ES_info` block
//! (per-elementary-stream). The list ends when the enclosing block's
//! length budget is exhausted.
//!
//! ## Scope
//!
//! The parser walks the TLV envelope generically — every descriptor
//! surfaces as a [`Descriptor`] borrowing its data slice from the
//! source — and additionally decodes a small set of tags that the
//! crate's downstream pipeline routinely needs to identify a stream:
//!
//! | Tag    | Name                              | Decoded variant                                |
//! |--------|-----------------------------------|-----------------------------------------------|
//! | `0x02` | video_stream_descriptor (§2.6.2)  | [`DescriptorBody::VideoStream`]              |
//! | `0x03` | audio_stream_descriptor (§2.6.4)  | [`DescriptorBody::AudioStream`]              |
//! | `0x04` | hierarchy_descriptor (§2.6.6)     | [`DescriptorBody::Hierarchy`]                |
//! | `0x05` | registration_descriptor (§2.6.8)  | [`DescriptorBody::Registration`]             |
//! | `0x06` | data_stream_alignment_descriptor (§2.6.10) | [`DescriptorBody::DataStreamAlignment`] |
//! | `0x07` | target_background_grid_descriptor (§2.6.12) | [`DescriptorBody::TargetBackgroundGrid`] |
//! | `0x08` | video_window_descriptor (§2.6.14) | [`DescriptorBody::VideoWindow`]              |
//! | `0x09` | CA_descriptor (§2.6.16)           | [`DescriptorBody::Ca`]                       |
//! | `0x0A` | ISO_639_language_descriptor (§2.6.18) | [`DescriptorBody::Iso639Language`]       |
//! | `0x0B` | system_clock_descriptor (§2.6.20) | [`DescriptorBody::SystemClock`]              |
//! | `0x0C` | multiplex_buffer_utilization_descriptor (§2.6.22) | [`DescriptorBody::MultiplexBufferUtilization`] |
//! | `0x0D` | copyright_descriptor (§2.6.24)    | [`DescriptorBody::Copyright`]                |
//! | `0x0E` | maximum_bitrate_descriptor (§2.6.26) | [`DescriptorBody::MaximumBitrate`]        |
//! | `0x10` | smoothing_buffer_descriptor (§2.6.30) | [`DescriptorBody::SmoothingBuffer`]      |
//! | `0x11` | STD_descriptor (§2.6.32)          | [`DescriptorBody::Std`]                      |
//! | `0x12` | IBP_descriptor (§2.6.34)          | [`DescriptorBody::Ibp`]                      |
//! | `0x28` | AVC_video_descriptor (§2.6.64)    | [`DescriptorBody::AvcVideo`]                 |
//! | `0x38` | HEVC_video_descriptor (Amd. 3 §2.6.95) | [`DescriptorBody::HevcVideo`]           |
//! | `0x40` | network_name_descriptor (EN 300 468 §6.2.27) | [`DescriptorBody::NetworkName`]  |
//! | `0x48` | service_descriptor (EN 300 468 §6.2.33) | [`DescriptorBody::Service`]            |
//! | `0x4D` | short_event_descriptor (EN 300 468 §6.2.37) | [`DescriptorBody::ShortEvent`]     |
//!
//! Every other tag is preserved as [`DescriptorBody::Raw`] so callers
//! still see the payload bytes without losing information.

use crate::TsError;

/// One descriptor decoded from a descriptor list.
#[derive(Debug, Clone)]
pub struct Descriptor<'a> {
    /// 8-bit descriptor tag (Table 2-45).
    pub tag: u8,
    /// Raw descriptor payload — exactly `descriptor_length` bytes.
    pub data: &'a [u8],
    /// Decoded body for the tags this module knows how to interpret,
    /// or [`DescriptorBody::Raw`] for unrecognised tags.
    pub body: DescriptorBody<'a>,
}

/// Typed body for descriptors this module decodes.
#[derive(Debug, Clone)]
pub enum DescriptorBody<'a> {
    /// `0x02` video_stream_descriptor (§2.6.2).
    VideoStream(VideoStreamDescriptor),
    /// `0x03` audio_stream_descriptor (§2.6.4).
    AudioStream(AudioStreamDescriptor),
    /// `0x04` hierarchy_descriptor (§2.6.6) — links one program element
    /// to its embedded base layer for hierarchically-coded video / audio
    /// / private streams (Table 2-43).
    Hierarchy(HierarchyDescriptor),
    /// `0x05` registration_descriptor (§2.6.8). `format_identifier` is
    /// a 4-byte ASCII code (e.g. `b"HDMV"` on Blu-ray) plus optional
    /// additional bytes whose semantics are scoped to the FOURCC.
    Registration {
        format_identifier: [u8; 4],
        additional_identification_info: &'a [u8],
    },
    /// `0x06` data_stream_alignment_descriptor (§2.6.10).
    DataStreamAlignment(DataStreamAlignmentDescriptor),
    /// `0x07` target_background_grid_descriptor (§2.6.12) — describes a
    /// grid of unit pixels projected onto the display area, against which
    /// a paired video_window_descriptor places the stream's window
    /// (Table 2-49).
    TargetBackgroundGrid(TargetBackgroundGridDescriptor),
    /// `0x08` video_window_descriptor (§2.6.14) — places the stream's
    /// display window on the grid defined by its paired
    /// target_background_grid_descriptor (Table 2-50).
    VideoWindow(VideoWindowDescriptor),
    /// `0x09` CA_descriptor (§2.6.16) — Conditional Access PID + system.
    Ca(CaDescriptor<'a>),
    /// `0x0A` ISO_639_language_descriptor (§2.6.18).
    Iso639Language(Vec<Iso639Language>),
    /// `0x0B` system_clock_descriptor (§2.6.20).
    SystemClock(SystemClockDescriptor),
    /// `0x0C` multiplex_buffer_utilization_descriptor (§2.6.22).
    MultiplexBufferUtilization(MultiplexBufferUtilizationDescriptor),
    /// `0x0D` copyright_descriptor (§2.6.24).
    Copyright(CopyrightDescriptor<'a>),
    /// `0x0E` maximum_bitrate_descriptor (§2.6.26).
    MaximumBitrate(MaximumBitrateDescriptor),
    /// `0x10` smoothing_buffer_descriptor (§2.6.30).
    SmoothingBuffer(SmoothingBufferDescriptor),
    /// `0x11` STD_descriptor (§2.6.32).
    Std(StdDescriptor),
    /// `0x12` IBP_descriptor (§2.6.34) — GOP-structure hints for the
    /// associated video elementary stream (Table 2-61).
    Ibp(IbpDescriptor),
    /// `0x28` AVC_video_descriptor (§2.6.64).
    AvcVideo(AvcVideoDescriptor),
    /// `0x38` HEVC_video_descriptor (Amd. 3 §2.6.95).
    HevcVideo(HevcVideoDescriptor),
    /// `0x48` service_descriptor — DVB SI extension (ETSI EN 300 468
    /// §6.2.33 Table 88). Carried in the SDT service loop; names the
    /// service plus its provider in text form.
    Service(ServiceDescriptor<'a>),
    /// `0x4D` short_event_descriptor — DVB SI extension (ETSI EN 300 468
    /// §6.2.37 Table 93). Carried in the EIT event loop; names the event
    /// plus a short text description, both tagged with a language code.
    ShortEvent(ShortEventDescriptor<'a>),
    /// `0x40` network_name_descriptor — DVB SI extension (ETSI EN 300 468
    /// §6.2.27 Table 81). Carried in the NIT network-level descriptor
    /// loop; names the delivery system the NIT informs about.
    NetworkName(NetworkNameDescriptor<'a>),
    /// Unrecognised tag — payload bytes preserved verbatim.
    Raw,
}

/// service_descriptor body (ETSI EN 300 468 §6.2.33 Table 88).
///
/// This is a DVB Service Information extension to the ISO/IEC 13818-1
/// descriptor space, carried inside the per-service descriptor loop of
/// a [`crate::psi::ServiceDescriptionTable`] section. It pairs the
/// service's textual provider name and service name with an 8-bit
/// `service_type` (Table 89).
///
/// The two name fields are exposed as **raw byte slices** rather than
/// decoded strings: DVB text strings (EN 300 468 annex A) carry an
/// optional leading character-table selector byte and may use any of
/// several code tables, so charset interpretation is deliberately left
/// to the caller. The bytes are exactly the `service_provider_name`
/// and `service_name` runs as they appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceDescriptor<'a> {
    /// 8-bit `service_type` (Table 89). Common values: `0x01` digital
    /// television, `0x02` digital radio, `0x11` HD digital television,
    /// `0x19` H.264/AVC HD, `0x1F` HEVC digital television.
    pub service_type: u8,
    /// Raw `service_provider_name` bytes (DVB text string, annex A).
    pub service_provider_name: &'a [u8],
    /// Raw `service_name` bytes (DVB text string, annex A).
    pub service_name: &'a [u8],
}

/// short_event_descriptor body (ETSI EN 300 468 §6.2.37 Table 93).
///
/// A DVB Service Information extension to the ISO/IEC 13818-1 descriptor
/// space, carried inside the per-event descriptor loop of an
/// [`crate::psi::EventInformationTable`] section. It pairs the event's
/// name with a short free-text description, both tagged by the same
/// 3-character ISO 639-2 language code.
///
/// Like the `service_descriptor`, the `event_name` and `text` fields
/// are exposed as **raw byte slices** rather than decoded strings: DVB
/// text strings (EN 300 468 annex A) carry an optional leading
/// character-table selector byte and may use any of several code
/// tables, so charset interpretation is deliberately left to the
/// caller. The bytes are exactly the `event_name` and `text` runs as
/// they appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortEventDescriptor<'a> {
    /// 24-bit `ISO_639_language_code` — three ISO 639-2 characters, each
    /// coded as one ISO/IEC 8859-1 byte (e.g. `b"eng"`, `b"fre"`).
    pub language_code: [u8; 3],
    /// Raw `event_name` bytes (DVB text string, annex A).
    pub event_name: &'a [u8],
    /// Raw `text` bytes — the short event description (DVB text string,
    /// annex A).
    pub text: &'a [u8],
}

/// network_name_descriptor body (ETSI EN 300 468 §6.2.27 Table 81).
///
/// A DVB Service Information extension to the ISO/IEC 13818-1 descriptor
/// space, carried inside the network-level descriptor loop of a
/// [`crate::psi::NetworkInformationTable`] section. It carries the
/// human-readable name of the delivery system the NIT informs about.
///
/// The whole descriptor payload is the name run — there is no
/// length-prefix or terminator inside it; the `descriptor_length` of
/// the TLV envelope bounds the field. As with the other DVB name
/// descriptors, the bytes are exposed **raw** (DVB text string, annex A)
/// so the caller chooses the character-table interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkNameDescriptor<'a> {
    /// Raw `network_name` bytes (DVB text string, annex A) — the entire
    /// descriptor payload.
    pub network_name: &'a [u8],
}

/// video_stream_descriptor body (§2.6.2 Table 2-46).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoStreamDescriptor {
    /// `multiple_frame_rate_flag`.
    pub multiple_frame_rate_flag: bool,
    /// 4-bit `frame_rate_code` (Table 6-4 of ISO/IEC 13818-2).
    pub frame_rate_code: u8,
    /// `MPEG_1_only_flag` — when set, no MPEG-2 extension byte follows.
    pub mpeg_1_only_flag: bool,
    /// `constrained_parameter_flag`.
    pub constrained_parameter_flag: bool,
    /// `still_picture_flag`.
    pub still_picture_flag: bool,
    /// `profile_and_level_indication`, when `mpeg_1_only_flag = 0`.
    pub profile_and_level_indication: Option<u8>,
    /// 2-bit `chroma_format` (00=reserved, 01=4:2:0, 10=4:2:2, 11=4:4:4).
    pub chroma_format: Option<u8>,
    /// `frame_rate_extension_flag`.
    pub frame_rate_extension_flag: Option<bool>,
}

/// audio_stream_descriptor body (§2.6.4 Table 2-47).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioStreamDescriptor {
    /// `free_format_flag` — `1` when the bitrate is "free format".
    pub free_format_flag: bool,
    /// `ID` — `1` indicates ISO/IEC 11172-3 (MPEG-1) audio, `0`
    /// indicates ISO/IEC 13818-3 (MPEG-2) audio extension.
    pub id: bool,
    /// 2-bit `layer` (00=reserved, 01=III, 10=II, 11=I).
    pub layer: u8,
    /// `variable_rate_audio_indicator`.
    pub variable_rate_audio_indicator: bool,
}

/// hierarchy_descriptor body (§2.6.6 Table 2-43).
///
/// The descriptor labels one PMT entry as a layer in a hierarchically
/// coded program — most commonly a video stream split into a base layer
/// plus one or more enhancement layers (spatial / SNR / temporal /
/// data-partitioning scalability per ITU-T H.262 | ISO/IEC 13818-2),
/// but the framing also covers ISO/IEC 13818-3 audio extensions and
/// 13818-1 private streams.
///
/// Wire payload (Table 2-43): exactly four bytes, two reserved bits
/// then six payload bits in each. `hierarchy_layer_index` is a unique
/// 6-bit index for this layer within the program;
/// `hierarchy_embedded_layer_index` points at the layer this one
/// depends on (undefined when `hierarchy_type == HierarchyType::BaseLayer`
/// per §2.6.7); `hierarchy_channel` is the intended transmission
/// channel rank — lower values are the more robust channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HierarchyDescriptor {
    /// Typed `hierarchy_type` (Table 2-44). The wire value is preserved
    /// in the [`HierarchyType::Reserved`] / [`HierarchyType::Unknown`]
    /// variants for callers that need the raw nibble.
    pub hierarchy_type: HierarchyType,
    /// 6-bit `hierarchy_layer_index` — unique index of this layer in
    /// the program's hierarchy table.
    pub hierarchy_layer_index: u8,
    /// 6-bit `hierarchy_embedded_layer_index` — index of the layer this
    /// one is built on top of. Per §2.6.7 the value is **undefined**
    /// when `hierarchy_type == HierarchyType::BaseLayer`; callers should
    /// ignore it in that case rather than relying on the raw bits.
    pub hierarchy_embedded_layer_index: u8,
    /// 6-bit `hierarchy_channel` — the transmission channel number this
    /// layer is intended to be carried on. The most robust channel is
    /// the lowest value (§2.6.7).
    pub hierarchy_channel: u8,
}

/// `hierarchy_type` values per Table 2-44.
///
/// The wire field is 4 bits; values 0 and 8..14 are reserved by the
/// spec and surface as [`HierarchyType::Reserved`] preserving the raw
/// nibble. Values outside the 0..=15 range cannot appear on the wire
/// (the field is only four bits) but the parser still surfaces them as
/// [`HierarchyType::Unknown`] for defensive coding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyType {
    /// `1` — ITU-T Rec. H.262 | ISO/IEC 13818-2 spatial scalability.
    Mpeg2SpatialScalability,
    /// `2` — ITU-T Rec. H.262 | ISO/IEC 13818-2 SNR scalability.
    Mpeg2SnrScalability,
    /// `3` — ITU-T Rec. H.262 | ISO/IEC 13818-2 temporal scalability.
    Mpeg2TemporalScalability,
    /// `4` — ITU-T Rec. H.262 | ISO/IEC 13818-2 data partitioning.
    Mpeg2DataPartitioning,
    /// `5` — ISO/IEC 13818-3 extension bitstream.
    Mpeg2AudioExtension,
    /// `6` — ITU-T Rec. H.222.0 | ISO/IEC 13818-1 private stream.
    PrivateStream,
    /// `7` — ITU-T Rec. H.262 | ISO/IEC 13818-2 multi-view profile.
    Mpeg2MultiviewProfile,
    /// `15` — Base layer; per §2.6.7 the embedded-layer-index field is
    /// undefined when this variant is set.
    BaseLayer,
    /// `0` and `8..=14` — reserved by Table 2-44. The raw 4-bit nibble
    /// is preserved verbatim.
    Reserved(u8),
    /// Out-of-range value (cannot occur on a conformant 4-bit wire
    /// field; surfaces here only if a future caller constructs the
    /// struct directly).
    Unknown(u8),
}

impl HierarchyType {
    /// Decode a 4-bit `hierarchy_type` nibble (only the low four bits
    /// are examined; the high four bits, if any, are ignored).
    pub fn from_nibble(value: u8) -> Self {
        match value & 0x0F {
            1 => HierarchyType::Mpeg2SpatialScalability,
            2 => HierarchyType::Mpeg2SnrScalability,
            3 => HierarchyType::Mpeg2TemporalScalability,
            4 => HierarchyType::Mpeg2DataPartitioning,
            5 => HierarchyType::Mpeg2AudioExtension,
            6 => HierarchyType::PrivateStream,
            7 => HierarchyType::Mpeg2MultiviewProfile,
            15 => HierarchyType::BaseLayer,
            other => HierarchyType::Reserved(other),
        }
    }

    /// Raw 4-bit value as it would appear on the wire. For
    /// [`HierarchyType::Unknown`] the stored value is returned verbatim
    /// (and may exceed 0xF, indicating an internally-constructed
    /// non-wire value).
    pub fn as_nibble(self) -> u8 {
        match self {
            HierarchyType::Mpeg2SpatialScalability => 1,
            HierarchyType::Mpeg2SnrScalability => 2,
            HierarchyType::Mpeg2TemporalScalability => 3,
            HierarchyType::Mpeg2DataPartitioning => 4,
            HierarchyType::Mpeg2AudioExtension => 5,
            HierarchyType::PrivateStream => 6,
            HierarchyType::Mpeg2MultiviewProfile => 7,
            HierarchyType::BaseLayer => 15,
            HierarchyType::Reserved(v) => v & 0x0F,
            HierarchyType::Unknown(v) => v,
        }
    }

    /// `true` when this variant is the §2.6.7 base layer; the
    /// `hierarchy_embedded_layer_index` field is undefined in that case.
    pub fn is_base_layer(self) -> bool {
        matches!(self, HierarchyType::BaseLayer)
    }
}

/// CA_descriptor body (§2.6.16 Table 2-50).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaDescriptor<'a> {
    /// `CA_system_ID`.
    pub ca_system_id: u16,
    /// 13-bit `CA_PID` carrying the ECM/EMM stream.
    pub ca_pid: u16,
    /// `private_data_bytes` — payload bytes after the PID.
    pub private_data: &'a [u8],
}

/// One language entry from an ISO_639_language_descriptor (§2.6.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iso639Language {
    /// 3-byte ISO 639-2 language code (typically lowercase ASCII).
    pub language: [u8; 3],
    /// `audio_type` — `0x00` undefined, `0x01` clean effects,
    /// `0x02` hearing impaired, `0x03` visual impaired commentary.
    pub audio_type: u8,
}

/// AVC_video_descriptor body (§2.6.64 Table 2-71).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvcVideoDescriptor {
    /// `profile_idc`.
    pub profile_idc: u8,
    /// Compound flags byte (`constraint_set0..2_flag` + 5 bits of
    /// `AVC_compatible_flags`).
    pub constraint_set_and_compat: u8,
    /// `level_idc`.
    pub level_idc: u8,
    /// `AVC_still_present`.
    pub avc_still_present: bool,
    /// `AVC_24_hour_picture_flag`.
    pub avc_24_hour_picture_flag: bool,
    /// `frame_packing_SEI_not_present_flag` (introduced in
    /// Amendment 1).
    pub frame_packing_sei_not_present_flag: bool,
}

/// data_stream_alignment_descriptor body (§2.6.10 Table 2-46).
///
/// `alignment_type` semantics depend on whether the referenced ES is
/// video (Table 2-47) or audio (Table 2-48):
///
/// | Value | Video                       | Audio       |
/// |-------|-----------------------------|-------------|
/// | 0x00  | Reserved                    | Reserved    |
/// | 0x01  | Slice, or video access unit | Sync word   |
/// | 0x02  | Video access unit           | (Reserved)  |
/// | 0x03  | GOP, or SEQ                 | (Reserved)  |
/// | 0x04  | SEQ                         | (Reserved)  |
/// | 0x05..0xFF | Reserved               | Reserved    |
///
/// The descriptor itself doesn't carry the video/audio distinction; the
/// caller selects the table based on the enclosing PMT entry's
/// `stream_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataStreamAlignmentDescriptor {
    /// Raw 8-bit `alignment_type` byte (Tables 2-47 / 2-48).
    pub alignment_type: u8,
}

/// target_background_grid_descriptor body (§2.6.12 Table 2-49).
///
/// Describes a grid of unit pixels projected onto the display area
/// (e.g. a monitor) for a video stream that is not intended to occupy
/// the full display. A paired video_window_descriptor (§2.6.14) then
/// places the stream's window on this grid. Per §2.6.13:
///
/// * `horizontal_size` — horizontal size of the target background grid
///   in pixels.
/// * `vertical_size` — vertical size of the target background grid in
///   pixels.
/// * `aspect_ratio_information` — sample or display aspect ratio of the
///   grid, encoded per the `aspect_ratio_information` field of
///   ITU-T Rec. H.262 | ISO/IEC 13818-2 (Table 2-49 cross-reference).
///   Surfaced as the raw 4-bit code; this crate does not decode the
///   H.262 table.
///
/// On the wire the body is exactly 4 bytes (Table 2-49):
///
/// ```text
/// byte 0: horizontal_size bits 13..6                      (8)
/// byte 1: horizontal_size bits 5..0 (6) | vertical_size bits 13..12 (2)
/// byte 2: vertical_size bits 11..4                        (8)
/// byte 3: vertical_size bits 3..0 (4) | aspect_ratio_information (4)
/// ```
///
/// Both size fields are big-endian 14-bit unsigned values; the table
/// carries no reserved bits, so all 32 bits are payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetBackgroundGridDescriptor {
    /// `horizontal_size` (14 bits) — grid width in pixels.
    pub horizontal_size: u16,
    /// `vertical_size` (14 bits) — grid height in pixels.
    pub vertical_size: u16,
    /// `aspect_ratio_information` (4 bits) — raw H.262 aspect-ratio code.
    pub aspect_ratio_information: u8,
}

/// video_window_descriptor body (§2.6.14 Table 2-50).
///
/// Describes the window characteristics of the associated video
/// elementary stream; its offsets reference the grid established by the
/// stream's paired target_background_grid_descriptor (§2.6.12). Per
/// §2.6.15:
///
/// * `horizontal_offset` — horizontal position of the top-left pixel of
///   the video display window (or display rectangle) on the target
///   background grid. The top-left pixel shall coincide with a grid
///   pixel.
/// * `vertical_offset` — vertical position of the same top-left pixel on
///   the grid.
/// * `window_priority` — overlap order, `0` lowest through `15` highest;
///   windows at priority `15` are always visible.
///
/// On the wire the body is exactly 4 bytes (Table 2-50), laid out
/// identically to the target_background_grid_descriptor's first three
/// fields:
///
/// ```text
/// byte 0: horizontal_offset bits 13..6                     (8)
/// byte 1: horizontal_offset bits 5..0 (6) | vertical_offset bits 13..12 (2)
/// byte 2: vertical_offset bits 11..4                       (8)
/// byte 3: vertical_offset bits 3..0 (4) | window_priority  (4)
/// ```
///
/// Both offset fields are big-endian 14-bit unsigned values; the table
/// carries no reserved bits, so all 32 bits are payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoWindowDescriptor {
    /// `horizontal_offset` (14 bits) — top-left X on the grid, in pixels.
    pub horizontal_offset: u16,
    /// `vertical_offset` (14 bits) — top-left Y on the grid, in pixels.
    pub vertical_offset: u16,
    /// `window_priority` (4 bits) — overlap order, `0` lowest, `15`
    /// highest (always visible).
    pub window_priority: u8,
}

/// system_clock_descriptor body (§2.6.20 Table 2-54).
///
/// `clock_accuracy_integer × 10^(-clock_accuracy_exponent)` gives the
/// fractional frequency accuracy of the program clock in parts per
/// million (§2.6.21). When `clock_accuracy_integer == 0` the spec
/// defines the accuracy as 30 ppm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemClockDescriptor {
    /// `external_clock_reference_indicator` — when `true`, the clock
    /// is derived from an external frequency reference at the decoder.
    pub external_clock_reference: bool,
    /// 6-bit `clock_accuracy_integer`.
    pub clock_accuracy_integer: u8,
    /// 3-bit `clock_accuracy_exponent`.
    pub clock_accuracy_exponent: u8,
}

/// copyright_descriptor body (§2.6.24 Table 2-56).
///
/// Surfaces the 32-bit `copyright_identifier` issued by the §2.9
/// Registration Authority plus the trailing `additional_copyright_info`
/// bytes. Per §2.6.25 the meaning of those trailing bytes is scoped to
/// the assignee of the `copyright_identifier` and stays opaque to this
/// crate. A descriptor body shorter than 4 bytes (the fixed
/// `copyright_identifier` field) falls back to
/// [`DescriptorBody::Raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyrightDescriptor<'a> {
    /// 32-bit `copyright_identifier` value obtained from the §2.9
    /// Registration Authority.
    pub copyright_identifier: u32,
    /// `additional_copyright_info` — descriptor bytes after the
    /// fixed-size identifier. May be empty.
    pub additional_copyright_info: &'a [u8],
}

/// maximum_bitrate_descriptor body (§2.6.26 Table 2-57).
///
/// `maximum_bitrate` is a 22-bit field in units of 50 bytes/s (§2.6.27).
/// Multiply by 50 to get bytes/s, or by 400 to get bits/s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaximumBitrateDescriptor {
    /// Raw 22-bit `maximum_bitrate` value (units of 50 bytes/s).
    pub maximum_bitrate: u32,
}

impl MaximumBitrateDescriptor {
    /// Convert to bits/s. `maximum_bitrate` units are 50 bytes/s, i.e.
    /// 400 bits/s, so the conversion is a multiply by 400 (which fits
    /// in `u64` for the full 22-bit range).
    pub fn bits_per_second(self) -> u64 {
        (self.maximum_bitrate as u64) * 400
    }
}

/// smoothing_buffer_descriptor body (§2.6.30 Table 2-59).
///
/// Optional PMT descriptor that declares the size of a smoothing
/// buffer SBn and the rate at which bytes leak out of it for the
/// program element(s) the descriptor refers to. Per §2.6.31:
///
/// * `sb_leak_rate` is a 22-bit value in units of 400 bits/s — i.e.
///   multiply by 400 to recover bits/s (multiply by 50 to recover
///   bytes/s).
/// * `sb_size` is a 22-bit value in units of 1 byte and gives the
///   capacity of SBn directly.
///
/// On the wire (§2.6.30 Table 2-59) the body is exactly 6 bytes:
/// two reserved bits then the 22-bit leak rate, then two reserved
/// bits then the 22-bit buffer size, both big-endian. The descriptor
/// is only defined inside a PMT or Program Stream Map; an SBn that
/// would overflow is a spec violation, not something this typed view
/// enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmoothingBufferDescriptor {
    /// Raw 22-bit `sb_leak_rate` value (units of 400 bits/s — i.e.
    /// the same 50 bytes/s units as `maximum_bitrate_descriptor`).
    pub sb_leak_rate: u32,
    /// Raw 22-bit `sb_size` value (units of 1 byte; this is the
    /// buffer capacity in bytes already).
    pub sb_size: u32,
}

impl SmoothingBufferDescriptor {
    /// Convert `sb_leak_rate` to bits per second. The wire field is in
    /// units of 400 bits/s, so the conversion is a multiply by 400
    /// (fits in `u64` for the full 22-bit range).
    pub fn leak_rate_bits_per_second(self) -> u64 {
        (self.sb_leak_rate as u64) * 400
    }

    /// Convert `sb_leak_rate` to bytes per second (the same 50 bytes/s
    /// quanta `maximum_bitrate_descriptor` uses).
    pub fn leak_rate_bytes_per_second(self) -> u64 {
        (self.sb_leak_rate as u64) * 50
    }

    /// `sb_size` in bytes — the field's wire units are already 1 byte
    /// per count, so this is just a widened copy for symmetry with the
    /// leak-rate helpers.
    pub fn buffer_size_bytes(self) -> u64 {
        self.sb_size as u64
    }
}

/// STD_descriptor body (§2.6.32 Table 2-60).
///
/// When `leak_valid_flag == true`, the transfer of data from buffer
/// MBn to EBn in the T-STD uses the leak method defined in §2.4.2.3;
/// when `false`, the transfer uses the `vbv_delay` method (provided
/// the per-frame `vbv_delay` is not `0xFFFF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdDescriptor {
    /// `leak_valid_flag` — 1 bit.
    pub leak_valid_flag: bool,
}

/// multiplex_buffer_utilization_descriptor body (§2.6.22 Table 2-55).
///
/// An optional PMT descriptor that bounds the LTW (legal time window)
/// offset values a re-multiplexer can expect to see for the program
/// element(s) the descriptor refers to. Per §2.6.23:
///
/// * `bound_valid_flag = 0` marks the two bound fields as undefined —
///   callers must ignore them in that case.
/// * `bound_valid_flag = 1` makes both bounds valid. Each bound is in
///   units of `(27 MHz / 300) = 90 kHz` clock periods (the LTW_offset
///   unit defined in §2.4.3.4) and bounds the value any future
///   `ltw_offset` field would carry on this stream until the next
///   occurrence of this descriptor.
///
/// On the wire the body is exactly 4 bytes:
///
/// ```text
/// byte 0: bound_valid_flag (1) | LTW_offset_lower_bound bits 14..8  (7)
/// byte 1: LTW_offset_lower_bound bits 7..0                          (8)
/// byte 2: reserved          (1) | LTW_offset_upper_bound bits 14..8 (7)
/// byte 3: LTW_offset_upper_bound bits 7..0                          (8)
/// ```
///
/// **Spec note.** The §2.6.22 Table 2-55 syntax row labels
/// `LTW_offset_upper_bound` as a 14-bit field, but the surrounding
/// semantic text (§2.6.23) describes it as a 15-bit field — the same
/// width as the adaptation-field `ltw_offset` in §2.4.3.4 / Table 2-7.
/// Together with the fixed reserved bit before the upper bound, the
/// 15-bit width is the only width that lets the body sum to a clean
/// four-byte boundary (`1 + 15 + 1 + 15 = 32`). This parser follows the
/// 15-bit reading because it matches both the semantic text and the
/// adaptation-field source field; a future spec corrigendum is the
/// expected path to close the typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiplexBufferUtilizationDescriptor {
    /// `bound_valid_flag` — when `false`, the two bound fields are
    /// undefined and callers should ignore them.
    pub bound_valid_flag: bool,
    /// Raw 15-bit `LTW_offset_lower_bound` value (units of 90 kHz clock
    /// periods). Meaningful only when `bound_valid_flag == true`.
    pub ltw_offset_lower_bound: u16,
    /// Raw 15-bit `LTW_offset_upper_bound` value (units of 90 kHz clock
    /// periods). Meaningful only when `bound_valid_flag == true`.
    pub ltw_offset_upper_bound: u16,
}

/// IBP_descriptor body (§2.6.34 Table 2-61).
///
/// Optional PMT-resident descriptor that summarises the GOP structure
/// of the associated video elementary stream. Two boolean hints plus a
/// 14-bit GOP-length cap let a downstream consumer pre-allocate
/// reorder buffers and seek-index slots without first scanning the
/// elementary stream.
///
/// On the wire the body is exactly 2 bytes:
///
/// ```text
/// byte 0: closed_gop_flag    (1)
///       | identical_gop_flag (1)
///       | max_gop_length bits 13..8 (6)
/// byte 1: max_gop_length bits 7..0   (8)
/// ```
///
/// Per §2.6.35:
///
/// * `closed_gop_flag = 1` — a GOP header is encoded before every
///   I-frame and every such GOP carries `closed_gop = 1`.
/// * `identical_gop_flag = 1` — the picture-type sequence between any
///   two I-pictures is identical throughout the stream (except possibly
///   for pictures up to the second I-picture).
/// * `max_gop_length` — maximum number of coded pictures between any
///   two consecutive I-pictures in the sequence. The value `0` is
///   forbidden by the spec; [`Self::is_well_formed`] flags that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IbpDescriptor {
    /// `closed_gop_flag` (1 bit).
    pub closed_gop_flag: bool,
    /// `identical_gop_flag` (1 bit).
    pub identical_gop_flag: bool,
    /// `max_gop_length` (14 bits). Spec forbids `0`; see
    /// [`Self::is_well_formed`].
    pub max_gop_length: u16,
}

impl IbpDescriptor {
    /// `true` when `max_gop_length` carries a spec-legal non-zero value.
    /// `false` flags the §2.6.35 "value of 0 is forbidden" condition,
    /// which the parser still surfaces so callers can detect malformed
    /// streams rather than silently substituting a sentinel.
    pub fn is_well_formed(self) -> bool {
        self.max_gop_length != 0
    }
}

/// HEVC_video_descriptor body (Amd. 3 §2.6.95 Table 2-96).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HevcVideoDescriptor {
    /// `profile_space`, 2 bits.
    pub profile_space: u8,
    /// `tier_flag`.
    pub tier_flag: bool,
    /// `profile_idc`, 5 bits.
    pub profile_idc: u8,
    /// `profile_compatibility_indication` (32 bits).
    pub profile_compatibility_indication: u32,
    /// `progressive_source_flag`.
    pub progressive_source_flag: bool,
    /// `interlaced_source_flag`.
    pub interlaced_source_flag: bool,
    /// `non_packed_constraint_flag`.
    pub non_packed_constraint_flag: bool,
    /// `frame_only_constraint_flag`.
    pub frame_only_constraint_flag: bool,
    /// `level_idc`.
    pub level_idc: u8,
    /// `temporal_layer_subset_flag`.
    pub temporal_layer_subset_flag: bool,
    /// `HEVC_still_present_flag`.
    pub hevc_still_present_flag: bool,
    /// `HEVC_24hr_picture_present_flag`.
    pub hevc_24hr_picture_present_flag: bool,
    /// `temporal_id_min` (3 bits), populated only when
    /// `temporal_layer_subset_flag = 1`.
    pub temporal_id_min: Option<u8>,
    /// `temporal_id_max` (3 bits), populated only when
    /// `temporal_layer_subset_flag = 1`.
    pub temporal_id_max: Option<u8>,
}

/// Iterate the descriptor TLV records carried inside `block`.
///
/// `block` is the exact slice that follows a `_info_length` field —
/// typically `pmt.program_info` or `pmt_stream.descriptors`. The
/// iterator stops cleanly once the slice is exhausted; a truncated
/// trailer (a descriptor header that claims more bytes than remain)
/// surfaces as [`TsError::Truncated`] on the next `next()` call.
pub fn iter_descriptors(block: &[u8]) -> DescriptorIter<'_> {
    DescriptorIter { rest: block }
}

/// Iterator returned by [`iter_descriptors`].
#[derive(Debug)]
pub struct DescriptorIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for DescriptorIter<'a> {
    type Item = Result<Descriptor<'a>, TsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 2 {
            let have = self.rest.len();
            self.rest = &[][..];
            return Some(Err(TsError::Truncated {
                what: "descriptor header",
                have,
                need: 2,
            }));
        }
        let tag = self.rest[0];
        let len = self.rest[1] as usize;
        if self.rest.len() < 2 + len {
            let have = self.rest.len() - 2;
            self.rest = &[][..];
            return Some(Err(TsError::Truncated {
                what: "descriptor body",
                have,
                need: len,
            }));
        }
        let data = &self.rest[2..2 + len];
        self.rest = &self.rest[2 + len..];
        Some(Ok(Descriptor {
            tag,
            data,
            body: decode_body(tag, data),
        }))
    }
}

/// Collect every descriptor in `block` into a `Vec`, returning the
/// first parse error if any.
pub fn parse_descriptors(block: &[u8]) -> Result<Vec<Descriptor<'_>>, TsError> {
    iter_descriptors(block).collect()
}

fn decode_body<'a>(tag: u8, data: &'a [u8]) -> DescriptorBody<'a> {
    match tag {
        0x02 => decode_video_stream(data).unwrap_or(DescriptorBody::Raw),
        0x03 => decode_audio_stream(data).unwrap_or(DescriptorBody::Raw),
        0x04 => decode_hierarchy(data).unwrap_or(DescriptorBody::Raw),
        0x05 => decode_registration(data).unwrap_or(DescriptorBody::Raw),
        0x06 => decode_data_stream_alignment(data).unwrap_or(DescriptorBody::Raw),
        0x07 => decode_target_background_grid(data).unwrap_or(DescriptorBody::Raw),
        0x08 => decode_video_window(data).unwrap_or(DescriptorBody::Raw),
        0x09 => decode_ca(data).unwrap_or(DescriptorBody::Raw),
        0x0A => decode_iso639_language(data).unwrap_or(DescriptorBody::Raw),
        0x0B => decode_system_clock(data).unwrap_or(DescriptorBody::Raw),
        0x0C => decode_multiplex_buffer_utilization(data).unwrap_or(DescriptorBody::Raw),
        0x0D => decode_copyright(data).unwrap_or(DescriptorBody::Raw),
        0x0E => decode_maximum_bitrate(data).unwrap_or(DescriptorBody::Raw),
        0x10 => decode_smoothing_buffer(data).unwrap_or(DescriptorBody::Raw),
        0x11 => decode_std(data).unwrap_or(DescriptorBody::Raw),
        0x12 => decode_ibp(data).unwrap_or(DescriptorBody::Raw),
        0x28 => decode_avc_video(data).unwrap_or(DescriptorBody::Raw),
        0x38 => decode_hevc_video(data).unwrap_or(DescriptorBody::Raw),
        0x40 => DescriptorBody::NetworkName(NetworkNameDescriptor { network_name: data }),
        0x48 => decode_service(data).unwrap_or(DescriptorBody::Raw),
        0x4D => decode_short_event(data).unwrap_or(DescriptorBody::Raw),
        _ => DescriptorBody::Raw,
    }
}

fn decode_service(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // ETSI EN 300 468 §6.2.33 Table 88:
    //   service_type                 (8)
    //   service_provider_name_length (8)
    //   service_provider_name        (provider_len bytes)
    //   service_name_length          (8)
    //   service_name                 (name_len bytes)
    if data.len() < 2 {
        return None;
    }
    let service_type = data[0];
    let provider_len = data[1] as usize;
    let provider_start = 2usize;
    let provider_end = provider_start.checked_add(provider_len)?;
    // The name_length byte must still fit after the provider run.
    if provider_end >= data.len() {
        return None;
    }
    let service_provider_name = &data[provider_start..provider_end];
    let name_len = data[provider_end] as usize;
    let name_start = provider_end + 1;
    let name_end = name_start.checked_add(name_len)?;
    if name_end > data.len() {
        return None;
    }
    let service_name = &data[name_start..name_end];
    Some(DescriptorBody::Service(ServiceDescriptor {
        service_type,
        service_provider_name,
        service_name,
    }))
}

fn decode_short_event(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // ETSI EN 300 468 §6.2.37 Table 93:
    //   ISO_639_language_code (24)
    //   event_name_length     (8)
    //   event_name            (name_len bytes)
    //   text_length           (8)
    //   text                  (text_len bytes)
    if data.len() < 4 {
        return None;
    }
    let language_code = [data[0], data[1], data[2]];
    let name_len = data[3] as usize;
    let name_start = 4usize;
    let name_end = name_start.checked_add(name_len)?;
    // The text_length byte must still fit after the event_name run.
    if name_end >= data.len() {
        return None;
    }
    let event_name = &data[name_start..name_end];
    let text_len = data[name_end] as usize;
    let text_start = name_end + 1;
    let text_end = text_start.checked_add(text_len)?;
    if text_end > data.len() {
        return None;
    }
    let text = &data[text_start..text_end];
    Some(DescriptorBody::ShortEvent(ShortEventDescriptor {
        language_code,
        event_name,
        text,
    }))
}

fn decode_video_stream(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.is_empty() {
        return None;
    }
    let b0 = data[0];
    let multiple_frame_rate_flag = (b0 & 0b1000_0000) != 0;
    let frame_rate_code = (b0 >> 3) & 0b0000_1111;
    let mpeg_1_only_flag = (b0 & 0b0000_0100) != 0;
    let constrained_parameter_flag = (b0 & 0b0000_0010) != 0;
    let still_picture_flag = (b0 & 0b0000_0001) != 0;
    let (profile_and_level_indication, chroma_format, frame_rate_extension_flag) =
        if !mpeg_1_only_flag && data.len() >= 3 {
            let pli = data[1];
            let b2 = data[2];
            let chroma = (b2 >> 6) & 0b11;
            let fre = (b2 & 0b0010_0000) != 0;
            (Some(pli), Some(chroma), Some(fre))
        } else {
            (None, None, None)
        };
    Some(DescriptorBody::VideoStream(VideoStreamDescriptor {
        multiple_frame_rate_flag,
        frame_rate_code,
        mpeg_1_only_flag,
        constrained_parameter_flag,
        still_picture_flag,
        profile_and_level_indication,
        chroma_format,
        frame_rate_extension_flag,
    }))
}

fn decode_audio_stream(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.is_empty() {
        return None;
    }
    let b0 = data[0];
    let free_format_flag = (b0 & 0b1000_0000) != 0;
    let id = (b0 & 0b0100_0000) != 0;
    let layer = (b0 >> 4) & 0b0000_0011;
    let variable_rate_audio_indicator = (b0 & 0b0000_1000) != 0;
    Some(DescriptorBody::AudioStream(AudioStreamDescriptor {
        free_format_flag,
        id,
        layer,
        variable_rate_audio_indicator,
    }))
}

fn decode_hierarchy(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Table 2-43: four bytes total. Each carries two reserved high bits
    // then a six-bit payload field. Byte 0 differs — the high nibble is
    // reserved and the low nibble is the hierarchy_type. All four
    // reserved chunks are ignored on the read path per §2.6 generic
    // forwards-compatibility rules.
    if data.len() < 4 {
        return None;
    }
    let hierarchy_type = HierarchyType::from_nibble(data[0]);
    let hierarchy_layer_index = data[1] & 0b0011_1111;
    let hierarchy_embedded_layer_index = data[2] & 0b0011_1111;
    let hierarchy_channel = data[3] & 0b0011_1111;
    Some(DescriptorBody::Hierarchy(HierarchyDescriptor {
        hierarchy_type,
        hierarchy_layer_index,
        hierarchy_embedded_layer_index,
        hierarchy_channel,
    }))
}

fn decode_registration(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.len() < 4 {
        return None;
    }
    let mut format_identifier = [0u8; 4];
    format_identifier.copy_from_slice(&data[..4]);
    Some(DescriptorBody::Registration {
        format_identifier,
        additional_identification_info: &data[4..],
    })
}

fn decode_ca(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.len() < 4 {
        return None;
    }
    let ca_system_id = u16::from_be_bytes([data[0], data[1]]);
    let ca_pid = (((data[2] & 0b0001_1111) as u16) << 8) | (data[3] as u16);
    Some(DescriptorBody::Ca(CaDescriptor {
        ca_system_id,
        ca_pid,
        private_data: &data[4..],
    }))
}

fn decode_iso639_language(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.len() % 4 != 0 {
        return None;
    }
    let mut langs = Vec::with_capacity(data.len() / 4);
    for chunk in data.chunks_exact(4) {
        let mut language = [0u8; 3];
        language.copy_from_slice(&chunk[..3]);
        langs.push(Iso639Language {
            language,
            audio_type: chunk[3],
        });
    }
    Some(DescriptorBody::Iso639Language(langs))
}

fn decode_data_stream_alignment(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.is_empty() {
        return None;
    }
    Some(DescriptorBody::DataStreamAlignment(
        DataStreamAlignmentDescriptor {
            alignment_type: data[0],
        },
    ))
}

fn decode_target_background_grid(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Four-byte payload (Table 2-49):
    //   byte 0: horizontal_size bits 13..6                       (8)
    //   byte 1: horizontal_size bits 5..0 (6) | vertical_size 13..12 (2)
    //   byte 2: vertical_size bits 11..4                         (8)
    //   byte 3: vertical_size bits 3..0 (4) | aspect_ratio_information (4)
    // Both size fields are big-endian 14-bit unsigneds; the table carries
    // no reserved bits, so all 32 bits are payload.
    if data.len() < 4 {
        return None;
    }
    let horizontal_size = ((data[0] as u16) << 6) | ((data[1] >> 2) as u16);
    let vertical_size = (((data[1] & 0b0000_0011) as u16) << 12)
        | ((data[2] as u16) << 4)
        | ((data[3] >> 4) as u16);
    let aspect_ratio_information = data[3] & 0b0000_1111;
    Some(DescriptorBody::TargetBackgroundGrid(
        TargetBackgroundGridDescriptor {
            horizontal_size,
            vertical_size,
            aspect_ratio_information,
        },
    ))
}

fn decode_video_window(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Four-byte payload (Table 2-50):
    //   byte 0: horizontal_offset bits 13..6                     (8)
    //   byte 1: horizontal_offset bits 5..0 (6) | vertical_offset 13..12 (2)
    //   byte 2: vertical_offset bits 11..4                       (8)
    //   byte 3: vertical_offset bits 3..0 (4) | window_priority  (4)
    // Both offset fields are big-endian 14-bit unsigneds; the table carries
    // no reserved bits, so all 32 bits are payload (same layout as the
    // target_background_grid_descriptor's size + aspect-ratio fields).
    if data.len() < 4 {
        return None;
    }
    let horizontal_offset = ((data[0] as u16) << 6) | ((data[1] >> 2) as u16);
    let vertical_offset = (((data[1] & 0b0000_0011) as u16) << 12)
        | ((data[2] as u16) << 4)
        | ((data[3] >> 4) as u16);
    let window_priority = data[3] & 0b0000_1111;
    Some(DescriptorBody::VideoWindow(VideoWindowDescriptor {
        horizontal_offset,
        vertical_offset,
        window_priority,
    }))
}

fn decode_system_clock(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Two-byte payload: byte 0 = external_clock_reference_indicator (1)
    //                            | reserved (1) | clock_accuracy_integer (6);
    //                  byte 1 = clock_accuracy_exponent (3) | reserved (5).
    if data.len() < 2 {
        return None;
    }
    let b0 = data[0];
    let b1 = data[1];
    let external_clock_reference = (b0 & 0b1000_0000) != 0;
    let clock_accuracy_integer = b0 & 0b0011_1111;
    let clock_accuracy_exponent = (b1 >> 5) & 0b0000_0111;
    Some(DescriptorBody::SystemClock(SystemClockDescriptor {
        external_clock_reference,
        clock_accuracy_integer,
        clock_accuracy_exponent,
    }))
}

fn decode_multiplex_buffer_utilization(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Four-byte payload (Table 2-55, with the §2.6.23 15-bit-upper-bound
    // reading documented on the struct):
    //   byte 0: bound_valid_flag (1) | LTW_offset_lower_bound bits 14..8 (7)
    //   byte 1: LTW_offset_lower_bound bits 7..0                         (8)
    //   byte 2: reserved          (1) | LTW_offset_upper_bound bits 14..8 (7)
    //   byte 3: LTW_offset_upper_bound bits 7..0                         (8)
    // Both bounds are big-endian 15-bit unsigneds packed against the LSB
    // of their leading byte. Reserved bits in byte 2 are ignored on the
    // read path per §2.6 forwards-compatibility.
    if data.len() < 4 {
        return None;
    }
    let bound_valid_flag = (data[0] & 0b1000_0000) != 0;
    let ltw_offset_lower_bound = (((data[0] & 0b0111_1111) as u16) << 8) | (data[1] as u16);
    let ltw_offset_upper_bound = (((data[2] & 0b0111_1111) as u16) << 8) | (data[3] as u16);
    Some(DescriptorBody::MultiplexBufferUtilization(
        MultiplexBufferUtilizationDescriptor {
            bound_valid_flag,
            ltw_offset_lower_bound,
            ltw_offset_upper_bound,
        },
    ))
}

fn decode_copyright(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Table 2-56: 32-bit copyright_identifier (big-endian) followed by
    // zero or more additional_copyright_info bytes.
    if data.len() < 4 {
        return None;
    }
    let copyright_identifier = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    Some(DescriptorBody::Copyright(CopyrightDescriptor {
        copyright_identifier,
        additional_copyright_info: &data[4..],
    }))
}

fn decode_maximum_bitrate(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Three-byte payload: 2 reserved bits then 22-bit maximum_bitrate
    // (big-endian, MSBs in byte 0 after the reserved nibble).
    if data.len() < 3 {
        return None;
    }
    let maximum_bitrate =
        (((data[0] & 0b0011_1111) as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    Some(DescriptorBody::MaximumBitrate(MaximumBitrateDescriptor {
        maximum_bitrate,
    }))
}

fn decode_smoothing_buffer(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Six-byte payload (Table 2-59):
    //   byte 0: 2 reserved bits | top 6 bits of sb_leak_rate
    //   byte 1: middle 8 bits of sb_leak_rate
    //   byte 2: low 8 bits of sb_leak_rate
    //   byte 3: 2 reserved bits | top 6 bits of sb_size
    //   byte 4: middle 8 bits of sb_size
    //   byte 5: low 8 bits of sb_size
    // Both fields are big-endian; both are 22-bit unsigned.
    if data.len() < 6 {
        return None;
    }
    let sb_leak_rate =
        (((data[0] & 0b0011_1111) as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    let sb_size =
        (((data[3] & 0b0011_1111) as u32) << 16) | ((data[4] as u32) << 8) | (data[5] as u32);
    Some(DescriptorBody::SmoothingBuffer(SmoothingBufferDescriptor {
        sb_leak_rate,
        sb_size,
    }))
}

fn decode_std(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // One-byte payload: 7 reserved bits then 1-bit leak_valid_flag.
    if data.is_empty() {
        return None;
    }
    Some(DescriptorBody::Std(StdDescriptor {
        leak_valid_flag: (data[0] & 0b0000_0001) != 0,
    }))
}

fn decode_ibp(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // Two-byte payload (Table 2-61):
    //   byte 0: closed_gop_flag    (1)
    //         | identical_gop_flag (1)
    //         | max_gop_length bits 13..8 (6)
    //   byte 1: max_gop_length bits 7..0 (8)
    // max_gop_length is a big-endian 14-bit unsigned; spec §2.6.35
    // forbids the value 0 but the parser still surfaces it so callers
    // can detect malformed streams via IbpDescriptor::is_well_formed.
    if data.len() < 2 {
        return None;
    }
    let closed_gop_flag = (data[0] & 0b1000_0000) != 0;
    let identical_gop_flag = (data[0] & 0b0100_0000) != 0;
    let max_gop_length = (((data[0] & 0b0011_1111) as u16) << 8) | (data[1] as u16);
    Some(DescriptorBody::Ibp(IbpDescriptor {
        closed_gop_flag,
        identical_gop_flag,
        max_gop_length,
    }))
}

fn decode_avc_video(data: &[u8]) -> Option<DescriptorBody<'_>> {
    if data.len() < 4 {
        return None;
    }
    let profile_idc = data[0];
    let constraint_set_and_compat = data[1];
    let level_idc = data[2];
    let flags = data[3];
    let avc_still_present = (flags & 0b1000_0000) != 0;
    let avc_24_hour_picture_flag = (flags & 0b0100_0000) != 0;
    let frame_packing_sei_not_present_flag = (flags & 0b0010_0000) != 0;
    Some(DescriptorBody::AvcVideo(AvcVideoDescriptor {
        profile_idc,
        constraint_set_and_compat,
        level_idc,
        avc_still_present,
        avc_24_hour_picture_flag,
        frame_packing_sei_not_present_flag,
    }))
}

fn decode_hevc_video(data: &[u8]) -> Option<DescriptorBody<'_>> {
    // 13 fixed bytes; +1 byte when temporal_layer_subset_flag = 1.
    if data.len() < 13 {
        return None;
    }
    let b0 = data[0];
    let profile_space = (b0 >> 6) & 0b11;
    let tier_flag = (b0 & 0b0010_0000) != 0;
    let profile_idc = b0 & 0b0001_1111;
    let profile_compatibility_indication = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let b5 = data[5];
    let progressive_source_flag = (b5 & 0b1000_0000) != 0;
    let interlaced_source_flag = (b5 & 0b0100_0000) != 0;
    let non_packed_constraint_flag = (b5 & 0b0010_0000) != 0;
    let frame_only_constraint_flag = (b5 & 0b0001_0000) != 0;
    // bytes 6..=11 carry the 44-bit `reserved_zero_44bits` field, which
    // we don't surface; per spec it must be zero on conformant streams
    // but we don't enforce.
    let level_idc = data[12];
    let (temporal_layer_subset_flag, hevc_still_present_flag, hevc_24hr_picture_present_flag) =
        if data.len() >= 14 {
            let b13 = data[13];
            (
                (b13 & 0b1000_0000) != 0,
                (b13 & 0b0100_0000) != 0,
                (b13 & 0b0010_0000) != 0,
            )
        } else {
            (false, false, false)
        };
    let (temporal_id_min, temporal_id_max) = if temporal_layer_subset_flag && data.len() >= 16 {
        // Two bytes: `temporal_id_min (3) | reserved (5)` then
        // `temporal_id_max (3) | reserved (5)`.
        let lo = (data[14] >> 5) & 0b111;
        let hi = (data[15] >> 5) & 0b111;
        (Some(lo), Some(hi))
    } else {
        (None, None)
    };
    Some(DescriptorBody::HevcVideo(HevcVideoDescriptor {
        profile_space,
        tier_flag,
        profile_idc,
        profile_compatibility_indication,
        progressive_source_flag,
        interlaced_source_flag,
        non_packed_constraint_flag,
        frame_only_constraint_flag,
        level_idc,
        temporal_layer_subset_flag,
        hevc_still_present_flag,
        hevc_24hr_picture_present_flag,
        temporal_id_min,
        temporal_id_max,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn iter_empty_block_yields_none() {
        let mut it = iter_descriptors(&[]);
        assert!(it.next().is_none());
    }

    #[test]
    fn unknown_tag_passes_through_as_raw() {
        let block = tlv(0x42, &[0xAA, 0xBB, 0xCC]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x42);
        assert_eq!(d.data, &[0xAA, 0xBB, 0xCC]);
        assert!(matches!(d.body, DescriptorBody::Raw));
    }

    #[test]
    fn two_descriptors_back_to_back() {
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x05, b"HDMV"));
        block.extend_from_slice(&tlv(0x09, &[0x09, 0x00, 0xE5, 0x00, 0xAB, 0xCD]));
        let v: Vec<_> = iter_descriptors(&block).collect();
        assert_eq!(v.len(), 2);
        let d0 = v[0].as_ref().unwrap();
        assert_eq!(d0.tag, 0x05);
        match &d0.body {
            DescriptorBody::Registration {
                format_identifier,
                additional_identification_info,
            } => {
                assert_eq!(format_identifier, b"HDMV");
                assert!(additional_identification_info.is_empty());
            }
            other => panic!("expected Registration, got {other:?}"),
        }
        let d1 = v[1].as_ref().unwrap();
        assert_eq!(d1.tag, 0x09);
        match &d1.body {
            DescriptorBody::Ca(ca) => {
                assert_eq!(ca.ca_system_id, 0x0900);
                assert_eq!(ca.ca_pid, 0x0500);
                assert_eq!(ca.private_data, &[0xAB, 0xCD]);
            }
            other => panic!("expected Ca, got {other:?}"),
        }
    }

    #[test]
    fn truncated_header_surfaces_error_then_stops() {
        let block = [0x05u8]; // only 1 byte — no length follows
        let mut it = iter_descriptors(&block);
        let err = it.next().expect("one error").unwrap_err();
        assert!(matches!(err, TsError::Truncated { .. }));
        assert!(it.next().is_none());
    }

    #[test]
    fn truncated_body_surfaces_error_then_stops() {
        let mut block = vec![0x05u8, 0x08]; // claims 8 bytes
        block.extend_from_slice(&[0xAA, 0xBB]); // only 2 supplied
        let mut it = iter_descriptors(&block);
        let err = it.next().expect("one error").unwrap_err();
        assert!(matches!(err, TsError::Truncated { .. }));
        assert!(it.next().is_none());
    }

    #[test]
    fn registration_descriptor_decodes_hdmv_with_trailer() {
        let block = tlv(0x05, b"HDMV\x88\x99");
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Registration {
                format_identifier,
                additional_identification_info,
            } => {
                assert_eq!(format_identifier, b"HDMV");
                assert_eq!(additional_identification_info, &[0x88, 0x99]);
            }
            other => panic!("expected Registration, got {other:?}"),
        }
    }

    #[test]
    fn iso639_language_descriptor_two_entries() {
        // "eng" audio_type=0, "jpn" audio_type=2
        let body = [b'e', b'n', b'g', 0x00, b'j', b'p', b'n', 0x02];
        let block = tlv(0x0A, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Iso639Language(langs) => {
                assert_eq!(langs.len(), 2);
                assert_eq!(&langs[0].language, b"eng");
                assert_eq!(langs[0].audio_type, 0);
                assert_eq!(&langs[1].language, b"jpn");
                assert_eq!(langs[1].audio_type, 2);
            }
            other => panic!("expected Iso639Language, got {other:?}"),
        }
    }

    #[test]
    fn iso639_language_bad_length_falls_back_to_raw() {
        // 5 bytes — not a multiple of 4.
        let body = [b'e', b'n', b'g', 0x00, 0xFF];
        let block = tlv(0x0A, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &body);
    }

    #[test]
    fn video_stream_descriptor_mpeg2_three_bytes() {
        // multiple_frame_rate=0, frame_rate_code=4 (29.97), MPEG_1_only=0,
        // CPF=0, still=0, profile_and_level=0x44 (Main@Main),
        // chroma=01 (4:2:0), fre=0.
        let body = [4u8 << 3, 0x44u8, 0b01 << 6];
        let block = tlv(0x02, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::VideoStream(v) => {
                assert!(!v.multiple_frame_rate_flag);
                assert_eq!(v.frame_rate_code, 4);
                assert!(!v.mpeg_1_only_flag);
                assert_eq!(v.profile_and_level_indication, Some(0x44));
                assert_eq!(v.chroma_format, Some(0b01));
                assert_eq!(v.frame_rate_extension_flag, Some(false));
            }
            other => panic!("expected VideoStream, got {other:?}"),
        }
    }

    #[test]
    fn video_stream_descriptor_mpeg1_one_byte() {
        // mpeg_1_only_flag = 1, frame_rate_code = 3, still = 1.
        let body = [(3 << 3) | 0b0000_0101];
        let block = tlv(0x02, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::VideoStream(v) => {
                assert!(v.mpeg_1_only_flag);
                assert_eq!(v.frame_rate_code, 3);
                assert!(v.still_picture_flag);
                assert!(v.profile_and_level_indication.is_none());
                assert!(v.chroma_format.is_none());
                assert!(v.frame_rate_extension_flag.is_none());
            }
            other => panic!("expected VideoStream, got {other:?}"),
        }
    }

    #[test]
    fn audio_stream_descriptor_layer_ii() {
        // free_format=0, ID=1 (MPEG-1), layer=10 (Layer II), VRA=1.
        let body = [(1u8 << 6) | (0b10 << 4) | (1 << 3)];
        let block = tlv(0x03, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::AudioStream(a) => {
                assert!(!a.free_format_flag);
                assert!(a.id);
                assert_eq!(a.layer, 0b10);
                assert!(a.variable_rate_audio_indicator);
            }
            other => panic!("expected AudioStream, got {other:?}"),
        }
    }

    #[test]
    fn ca_descriptor_min_no_private_data() {
        // CA_system_ID=0x4AAA, CA_PID=0x123 (with reserved=111 in high byte).
        let body = [0x4A, 0xAA, 0xE1 /* 111_00001 */, 0x23];
        let block = tlv(0x09, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Ca(ca) => {
                assert_eq!(ca.ca_system_id, 0x4AAA);
                assert_eq!(ca.ca_pid, 0x0123);
                assert!(ca.private_data.is_empty());
            }
            other => panic!("expected Ca, got {other:?}"),
        }
    }

    #[test]
    fn avc_video_descriptor_typical_values() {
        // profile_idc=100 (High), constraint+compat=0, level_idc=41,
        // flags: still=0, 24h=0, fp_sei_npresent=0.
        let body = [100, 0x00, 41, 0x00];
        let block = tlv(0x28, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::AvcVideo(a) => {
                assert_eq!(a.profile_idc, 100);
                assert_eq!(a.level_idc, 41);
                assert!(!a.avc_still_present);
                assert!(!a.frame_packing_sei_not_present_flag);
            }
            other => panic!("expected AvcVideo, got {other:?}"),
        }
    }

    #[test]
    fn hevc_video_descriptor_min_13_bytes() {
        // profile_space=0, tier_flag=1, profile_idc=2 (Main 10):
        let b0 = (1u8 << 5) | 2;
        let compat: u32 = 0x6000_0000;
        // progressive=1, interlaced=0, non_packed=1, frame_only=1, rest 0.
        let b5: u8 = 0b1011_0000;
        let level_idc: u8 = 153;
        let body = vec![
            b0,
            (compat >> 24) as u8,
            (compat >> 16) as u8,
            (compat >> 8) as u8,
            compat as u8,
            b5,
            0,
            0,
            0,
            0,
            0,
            0,
            level_idc,
        ];
        // No temporal_layer_subset byte.
        let block = tlv(0x38, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::HevcVideo(h) => {
                assert_eq!(h.profile_space, 0);
                assert!(h.tier_flag);
                assert_eq!(h.profile_idc, 2);
                assert_eq!(h.profile_compatibility_indication, compat);
                assert!(h.progressive_source_flag);
                assert!(!h.interlaced_source_flag);
                assert!(h.non_packed_constraint_flag);
                assert!(h.frame_only_constraint_flag);
                assert_eq!(h.level_idc, level_idc);
                assert!(!h.temporal_layer_subset_flag);
                assert!(h.temporal_id_min.is_none());
                assert!(h.temporal_id_max.is_none());
            }
            other => panic!("expected HevcVideo, got {other:?}"),
        }
    }

    #[test]
    fn hevc_video_descriptor_with_temporal_layer_subset() {
        let mut body = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 120];
        // temporal_layer_subset_flag=1, still=0, 24h=1, rest 0.
        body.push(0b1010_0000);
        // temporal_id_min = 1, temporal_id_max = 4.
        body.push(1 << 5);
        body.push(4 << 5);
        let block = tlv(0x38, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::HevcVideo(h) => {
                assert!(h.temporal_layer_subset_flag);
                assert!(h.hevc_24hr_picture_present_flag);
                assert_eq!(h.temporal_id_min, Some(1));
                assert_eq!(h.temporal_id_max, Some(4));
            }
            other => panic!("expected HevcVideo, got {other:?}"),
        }
    }

    #[test]
    fn data_stream_alignment_video_access_unit() {
        // alignment_type = 0x02 = "video access unit" per Table 2-47.
        let block = tlv(0x06, &[0x02]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::DataStreamAlignment(a) => {
                assert_eq!(a.alignment_type, 0x02);
            }
            other => panic!("expected DataStreamAlignment, got {other:?}"),
        }
    }

    #[test]
    fn data_stream_alignment_empty_body_falls_back_to_raw() {
        let block = tlv(0x06, &[]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
    }

    #[test]
    fn system_clock_descriptor_external_ref_off() {
        // external=0, reserved=1, clock_accuracy_integer=0b00_1010 (=10);
        // clock_accuracy_exponent=0b011 (=3), reserved=0b00000.
        let b0 = 0b0100_1010u8;
        let b1 = 0b0110_0000u8;
        let block = tlv(0x0B, &[b0, b1]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::SystemClock(s) => {
                assert!(!s.external_clock_reference);
                assert_eq!(s.clock_accuracy_integer, 10);
                assert_eq!(s.clock_accuracy_exponent, 3);
            }
            other => panic!("expected SystemClock, got {other:?}"),
        }
    }

    #[test]
    fn system_clock_descriptor_external_ref_on() {
        // external=1, reserved=0, clock_accuracy_integer=0b00_0000;
        // clock_accuracy_exponent=0b000.
        let block = tlv(0x0B, &[0b1000_0000, 0b0000_0000]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::SystemClock(s) => {
                assert!(s.external_clock_reference);
                assert_eq!(s.clock_accuracy_integer, 0);
                assert_eq!(s.clock_accuracy_exponent, 0);
            }
            other => panic!("expected SystemClock, got {other:?}"),
        }
    }

    #[test]
    fn maximum_bitrate_descriptor_typical() {
        // maximum_bitrate = 0x12_3456 (1_193_046 × 50 B/s = 59_652_300 B/s).
        // Encode: 2 reserved bits then 22 bits big-endian.
        // 0x12_3456 = 0b00_010010_00110100_01010110.
        let b0 = 0b1100_0000 | 0b0001_0010; // 2 reserved (set to 1) | top 6 bits
        let block = tlv(0x0E, &[b0, 0x34, 0x56]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::MaximumBitrate(m) => {
                assert_eq!(m.maximum_bitrate, 0x12_3456);
                // 0x12_3456 × 400 = 477_218_400 bits/s
                assert_eq!(m.bits_per_second(), 0x12_3456u64 * 400);
            }
            other => panic!("expected MaximumBitrate, got {other:?}"),
        }
    }

    #[test]
    fn maximum_bitrate_descriptor_zero_bitrate() {
        // All-zero except the reserved high bits (set to 1 per spec).
        let block = tlv(0x0E, &[0b1100_0000, 0x00, 0x00]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::MaximumBitrate(m) => {
                assert_eq!(m.maximum_bitrate, 0);
                assert_eq!(m.bits_per_second(), 0);
            }
            other => panic!("expected MaximumBitrate, got {other:?}"),
        }
    }

    #[test]
    fn maximum_bitrate_descriptor_short_body_falls_back_to_raw() {
        let block = tlv(0x0E, &[0xC0, 0x00]); // only 2 bytes
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
    }

    #[test]
    fn std_descriptor_leak_valid_set() {
        // 7 reserved bits high, leak_valid_flag = 1.
        let block = tlv(0x11, &[0b1111_1111]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Std(s) => assert!(s.leak_valid_flag),
            other => panic!("expected Std, got {other:?}"),
        }
    }

    #[test]
    fn std_descriptor_leak_valid_unset() {
        let block = tlv(0x11, &[0b1111_1110]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Std(s) => assert!(!s.leak_valid_flag),
            other => panic!("expected Std, got {other:?}"),
        }
    }

    #[test]
    fn smoothing_buffer_descriptor_typical_values() {
        // sb_leak_rate = 0x09_C400 = 640_000 (units of 400 bits/s →
        //   256 Mbit/s, units of 50 bytes/s → 32 MB/s).
        // sb_size      = 0x00_C000 = 49_152 bytes (= 48 KiB).
        // Reserved bits set to 1 (per spec they are reserved-for-future-
        // use; our parser must ignore them on the read path).
        let leak: u32 = 0x09_C400;
        let size: u32 = 0x00_C000;
        let body = [
            0b1100_0000 | ((leak >> 16) as u8 & 0b0011_1111),
            (leak >> 8) as u8,
            leak as u8,
            0b1100_0000 | ((size >> 16) as u8 & 0b0011_1111),
            (size >> 8) as u8,
            size as u8,
        ];
        let block = tlv(0x10, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::SmoothingBuffer(sb) => {
                assert_eq!(sb.sb_leak_rate, leak);
                assert_eq!(sb.sb_size, size);
                // 640_000 × 400 = 256_000_000 bits/s
                assert_eq!(sb.leak_rate_bits_per_second(), 256_000_000);
                // 640_000 × 50 = 32_000_000 bytes/s
                assert_eq!(sb.leak_rate_bytes_per_second(), 32_000_000);
                assert_eq!(sb.buffer_size_bytes(), 49_152);
            }
            other => panic!("expected SmoothingBuffer, got {other:?}"),
        }
    }

    #[test]
    fn smoothing_buffer_descriptor_zero_fields() {
        // All-zero leak rate and size; reserved bits left at 0 too —
        // both should still parse, since the reserved bits are ignored.
        let block = tlv(0x10, &[0u8; 6]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::SmoothingBuffer(sb) => {
                assert_eq!(sb.sb_leak_rate, 0);
                assert_eq!(sb.sb_size, 0);
                assert_eq!(sb.leak_rate_bits_per_second(), 0);
                assert_eq!(sb.buffer_size_bytes(), 0);
            }
            other => panic!("expected SmoothingBuffer, got {other:?}"),
        }
    }

    #[test]
    fn smoothing_buffer_descriptor_max_22bit_fields() {
        // Both fields at their 22-bit ceilings (0x3F_FFFF). Confirms
        // that the parser masks off reserved bits correctly and that
        // the rate conversion stays inside `u64`.
        let max22: u32 = 0x003F_FFFF;
        let body = [0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8];
        let block = tlv(0x10, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::SmoothingBuffer(sb) => {
                assert_eq!(sb.sb_leak_rate, max22);
                assert_eq!(sb.sb_size, max22);
                assert_eq!(sb.leak_rate_bits_per_second(), (max22 as u64) * 400);
                assert_eq!(sb.buffer_size_bytes(), max22 as u64);
            }
            other => panic!("expected SmoothingBuffer, got {other:?}"),
        }
    }

    #[test]
    fn smoothing_buffer_descriptor_short_body_falls_back_to_raw() {
        // Five bytes is one short of the 6-byte payload.
        let block = tlv(0x10, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data.len(), 5);
    }

    #[test]
    fn smoothing_buffer_descriptor_lives_in_pmt_program_info() {
        // A PMT's program_info block may carry a smoothing buffer
        // descriptor alongside an ISO-639 language descriptor; check
        // that `iter_descriptors` walks both and surfaces the typed
        // smoothing-buffer body in mid-list.
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x0A, &[b'f', b'r', b'a', 0x00]));
        let leak: u32 = 0x0001_0000; // 65_536 × 400 = 26_214_400 bits/s
        let size: u32 = 0x0000_4000; // 16 KiB
        let sb_body = [
            ((leak >> 16) as u8) & 0b0011_1111,
            (leak >> 8) as u8,
            leak as u8,
            ((size >> 16) as u8) & 0b0011_1111,
            (size >> 8) as u8,
            size as u8,
        ];
        block.extend_from_slice(&tlv(0x10, &sb_body));
        block.extend_from_slice(&tlv(0x11, &[0b1111_1111]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x0A);
        assert_eq!(v[1].tag, 0x10);
        match &v[1].body {
            DescriptorBody::SmoothingBuffer(sb) => {
                assert_eq!(sb.sb_leak_rate, leak);
                assert_eq!(sb.sb_size, size);
            }
            other => panic!("expected SmoothingBuffer, got {other:?}"),
        }
        assert_eq!(v[2].tag, 0x11);
        match &v[2].body {
            DescriptorBody::Std(s) => assert!(s.leak_valid_flag),
            other => panic!("expected Std, got {other:?}"),
        }
    }

    #[test]
    fn copyright_descriptor_identifier_only_no_trailer() {
        // `copyright_identifier` = 0x4953'4243 ("ISBC" — illustrative
        // four-byte FOURCC). No trailing additional_copyright_info.
        let body = [0x49, 0x53, 0x42, 0x43];
        let block = tlv(0x0D, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Copyright(c) => {
                assert_eq!(c.copyright_identifier, 0x4953_4243);
                assert!(c.additional_copyright_info.is_empty());
            }
            other => panic!("expected Copyright, got {other:?}"),
        }
    }

    #[test]
    fn copyright_descriptor_with_trailing_info() {
        // 4-byte identifier + 5 trailing bytes that the assignee
        // defines per §2.6.25. The parser surfaces them verbatim.
        let body = [0x00, 0x00, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let block = tlv(0x0D, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Copyright(c) => {
                assert_eq!(c.copyright_identifier, 0x0000_0001);
                assert_eq!(c.additional_copyright_info, &[0xDE, 0xAD, 0xBE, 0xEF, 0x42]);
            }
            other => panic!("expected Copyright, got {other:?}"),
        }
    }

    #[test]
    fn copyright_descriptor_short_body_falls_back_to_raw() {
        // Three bytes — one short of the mandatory 32-bit identifier.
        let block = tlv(0x0D, &[0xAA, 0xBB, 0xCC]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn copyright_descriptor_zero_body_falls_back_to_raw() {
        // descriptor_length == 0 — still legal per §2.6 generic TLV
        // framing but doesn't satisfy the copyright_descriptor's
        // 4-byte minimum, so the typed body falls back to Raw.
        let block = tlv(0x0D, &[]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert!(d.data.is_empty());
    }

    #[test]
    fn copyright_descriptor_in_pmt_program_info_alongside_other_tags() {
        // A realistic PMT program_info block: ISO-639 language +
        // copyright + smoothing-buffer. Each is a TLV; iter_descriptors
        // walks them in order and surfaces the typed Copyright body
        // mid-list without disturbing the surrounding decoders.
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x0A, &[b'e', b'n', b'g', 0x00]));
        let cid: u32 = 0x4953_524E; // ISRN — another four-byte FOURCC
        let trailer = [0x12, 0x34];
        let mut copy_body = Vec::new();
        copy_body.extend_from_slice(&cid.to_be_bytes());
        copy_body.extend_from_slice(&trailer);
        block.extend_from_slice(&tlv(0x0D, &copy_body));
        let leak: u32 = 0x0001_0000;
        let size: u32 = 0x0000_4000;
        let sb_body = [
            ((leak >> 16) as u8) & 0b0011_1111,
            (leak >> 8) as u8,
            leak as u8,
            ((size >> 16) as u8) & 0b0011_1111,
            (size >> 8) as u8,
            size as u8,
        ];
        block.extend_from_slice(&tlv(0x10, &sb_body));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x0A);
        assert_eq!(v[1].tag, 0x0D);
        match &v[1].body {
            DescriptorBody::Copyright(c) => {
                assert_eq!(c.copyright_identifier, cid);
                assert_eq!(c.additional_copyright_info, &trailer);
            }
            other => panic!("expected Copyright, got {other:?}"),
        }
        assert_eq!(v[2].tag, 0x10);
        assert!(matches!(v[2].body, DescriptorBody::SmoothingBuffer(_)));
    }

    #[test]
    fn hierarchy_descriptor_spatial_scalability_layer() {
        // hierarchy_type = 1 (spatial scalability), layer_index = 5,
        // embedded_layer_index = 15, channel = 0 (most robust).
        // Reserved bits set to 1 so the parser must mask them off.
        let body = [
            0b1111_0001,      // reserved=1111 | hierarchy_type=0001
            0b1100_0000 | 5,  // reserved=11 | layer_index=000101
            0b1100_0000 | 15, // reserved=11 | embedded_layer_index=001111
            0b1100_0000,      // reserved=11 | hierarchy_channel=000000
        ];
        let block = tlv(0x04, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Hierarchy(h) => {
                assert_eq!(h.hierarchy_type, HierarchyType::Mpeg2SpatialScalability);
                assert_eq!(h.hierarchy_type.as_nibble(), 1);
                assert!(!h.hierarchy_type.is_base_layer());
                assert_eq!(h.hierarchy_layer_index, 5);
                assert_eq!(h.hierarchy_embedded_layer_index, 15);
                assert_eq!(h.hierarchy_channel, 0);
            }
            other => panic!("expected Hierarchy, got {other:?}"),
        }
    }

    #[test]
    fn hierarchy_descriptor_base_layer_marker() {
        // hierarchy_type = 15 (base layer). Per §2.6.7 the
        // embedded_layer_index is undefined; the parser still surfaces
        // whatever the wire bytes carry, and `is_base_layer` reports
        // `true` so the caller knows to disregard it.
        let body = [
            0b0000_1111, // reserved=0000 | hierarchy_type=1111
            0b0000_0001, // layer_index = 1
            0b0011_1111, // embedded_layer_index = 0x3F (undefined per §2.6.7)
            0b0000_0010, // hierarchy_channel = 2
        ];
        let block = tlv(0x04, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Hierarchy(h) => {
                assert_eq!(h.hierarchy_type, HierarchyType::BaseLayer);
                assert!(h.hierarchy_type.is_base_layer());
                assert_eq!(h.hierarchy_layer_index, 1);
                assert_eq!(h.hierarchy_embedded_layer_index, 0x3F);
                assert_eq!(h.hierarchy_channel, 2);
            }
            other => panic!("expected Hierarchy, got {other:?}"),
        }
    }

    #[test]
    fn hierarchy_descriptor_all_typed_variants_round_trip() {
        // Walk every Table 2-44 mapping that has a named variant: 1..7
        // and 15. Confirm `from_nibble` round-trips through `as_nibble`
        // for each.
        let mapped = [
            (1u8, HierarchyType::Mpeg2SpatialScalability),
            (2, HierarchyType::Mpeg2SnrScalability),
            (3, HierarchyType::Mpeg2TemporalScalability),
            (4, HierarchyType::Mpeg2DataPartitioning),
            (5, HierarchyType::Mpeg2AudioExtension),
            (6, HierarchyType::PrivateStream),
            (7, HierarchyType::Mpeg2MultiviewProfile),
            (15, HierarchyType::BaseLayer),
        ];
        for (raw, expected) in mapped {
            let decoded = HierarchyType::from_nibble(raw);
            assert_eq!(decoded, expected, "wire nibble {raw}");
            assert_eq!(decoded.as_nibble(), raw, "round-trip for {raw}");
        }
        assert!(HierarchyType::BaseLayer.is_base_layer());
        // None of the non-base mappings flip `is_base_layer`.
        for (_, t) in mapped[..7].iter().copied() {
            assert!(!t.is_base_layer());
        }
    }

    #[test]
    fn hierarchy_descriptor_reserved_values_preserve_raw_nibble() {
        // Values 0 and 8..=14 are reserved per Table 2-44. The parser
        // must keep them round-trippable so a caller can tell which
        // reserved nibble showed up on the wire.
        for raw in [0u8, 8, 9, 10, 11, 12, 13, 14] {
            let decoded = HierarchyType::from_nibble(raw);
            assert_eq!(decoded, HierarchyType::Reserved(raw));
            assert_eq!(decoded.as_nibble(), raw);
            assert!(!decoded.is_base_layer());
        }
        // The Unknown variant is only reachable when callers build a
        // value directly; `as_nibble` preserves whatever they stored.
        assert_eq!(HierarchyType::Unknown(0xAB).as_nibble(), 0xAB);
    }

    #[test]
    fn hierarchy_descriptor_high_nibble_ignored_in_type_byte() {
        // The high four bits of byte 0 are reserved. Whatever value they
        // carry, the parser must mask them off before consulting
        // Table 2-44.
        let body = [0b1010_0011, 0, 0, 0]; // high nibble = 1010 → ignore
        let block = tlv(0x04, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Hierarchy(h) => {
                assert_eq!(h.hierarchy_type, HierarchyType::Mpeg2TemporalScalability);
            }
            other => panic!("expected Hierarchy, got {other:?}"),
        }
    }

    #[test]
    fn hierarchy_descriptor_short_body_falls_back_to_raw() {
        // Three bytes — one short of the four-byte Table 2-43 payload.
        let block = tlv(0x04, &[0x0F, 0xC0, 0xC0]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0x0F, 0xC0, 0xC0]);
    }

    #[test]
    fn hierarchy_descriptor_max_6bit_index_fields() {
        // Layer / embedded-layer / channel each saturated at the 6-bit
        // ceiling (0x3F). Reserved high bits left at 1 to verify the
        // mask. hierarchy_type = 2 (SNR scalability).
        let body = [
            0b0000_0010, // reserved=0 | hierarchy_type=0010
            0xFF,        // reserved=11 | layer_index=111111 = 63
            0xFF,        // reserved=11 | embedded_layer_index=111111 = 63
            0xFF,        // reserved=11 | hierarchy_channel=111111 = 63
        ];
        let block = tlv(0x04, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Hierarchy(h) => {
                assert_eq!(h.hierarchy_type, HierarchyType::Mpeg2SnrScalability);
                assert_eq!(h.hierarchy_layer_index, 0x3F);
                assert_eq!(h.hierarchy_embedded_layer_index, 0x3F);
                assert_eq!(h.hierarchy_channel, 0x3F);
            }
            other => panic!("expected Hierarchy, got {other:?}"),
        }
    }

    #[test]
    fn hierarchy_descriptor_in_pmt_es_info_alongside_other_tags() {
        // Realistic ES_info block on an enhancement-layer PMT entry:
        // ISO-639 language + hierarchy + max-bitrate. The hierarchy
        // descriptor lands mid-list and surfaces its typed body without
        // disturbing neighbours.
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x0A, &[b'e', b'n', b'g', 0x00]));
        let h_body = [
            0b0000_0001, // hierarchy_type = spatial scalability
            0b0000_0010, // layer_index = 2
            0b0000_0000, // embedded_layer_index = 0 (base)
            0b0000_0001, // hierarchy_channel = 1
        ];
        block.extend_from_slice(&tlv(0x04, &h_body));
        block.extend_from_slice(&tlv(0x0E, &[0b1100_0000, 0x00, 0x64]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x0A);
        assert_eq!(v[1].tag, 0x04);
        match &v[1].body {
            DescriptorBody::Hierarchy(h) => {
                assert_eq!(h.hierarchy_type, HierarchyType::Mpeg2SpatialScalability);
                assert_eq!(h.hierarchy_layer_index, 2);
                assert_eq!(h.hierarchy_embedded_layer_index, 0);
                assert_eq!(h.hierarchy_channel, 1);
            }
            other => panic!("expected Hierarchy, got {other:?}"),
        }
        assert_eq!(v[2].tag, 0x0E);
        assert!(matches!(v[2].body, DescriptorBody::MaximumBitrate(_)));
    }

    #[test]
    fn multiplex_buffer_utilization_descriptor_bounds_valid() {
        // bound_valid=1; pick two distinct 15-bit values that exercise
        // both halves of each bound. The 7-bit-then-8-bit packing means
        // byte 0 carries bits 14..8 of the lower bound (high 7 bits)
        // and byte 1 carries bits 7..0 (low 8 bits); same for byte 2/3.
        let lower: u16 = 0x1234; // 15-bit clean (top bit 0)
        let upper: u16 = 0x5678; // 15-bit clean (top bit 0)
        let body = [
            0x80 | ((lower >> 8) as u8 & 0x7F),
            lower as u8,
            (upper >> 8) as u8 & 0x7F,
            upper as u8,
        ];
        let block = tlv(0x0C, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::MultiplexBufferUtilization(m) => {
                assert!(m.bound_valid_flag);
                assert_eq!(m.ltw_offset_lower_bound, lower);
                assert_eq!(m.ltw_offset_upper_bound, upper);
            }
            other => panic!("expected MultiplexBufferUtilization, got {other:?}"),
        }
    }

    #[test]
    fn multiplex_buffer_utilization_descriptor_bounds_invalid() {
        // bound_valid=0 -- bound fields are still surfaced verbatim per
        // §2.6.23 ("undefined when flag = 0"), but the caller is expected
        // to discard them. We still verify the parser doesn't crash on a
        // populated body.
        let body = [0x7F, 0xFF, 0x7F, 0xFF];
        let block = tlv(0x0C, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::MultiplexBufferUtilization(m) => {
                assert!(!m.bound_valid_flag);
                assert_eq!(m.ltw_offset_lower_bound, 0x7FFF);
                assert_eq!(m.ltw_offset_upper_bound, 0x7FFF);
            }
            other => panic!("expected MultiplexBufferUtilization, got {other:?}"),
        }
    }

    #[test]
    fn multiplex_buffer_utilization_descriptor_short_body_falls_back_to_raw() {
        // Three bytes — one short of the four-byte Table 2-55 payload.
        let block = tlv(0x0C, &[0xA0, 0x00, 0x00]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0xA0, 0x00, 0x00]);
    }

    #[test]
    fn multiplex_buffer_utilization_descriptor_reserved_bit_ignored_on_read() {
        // The reserved bit at byte 2 MSB is ignored. Set bound_valid=1 +
        // a clean lower bound, and flip the reserved bit both ways on
        // the upper-bound byte — the upper bound must read the same.
        let lower = 0x0000u16;
        let upper = 0x0001u16; // smallest non-zero value
        let with_reserved_zero = [0x80, 0x00, (upper >> 8) as u8, upper as u8];
        let with_reserved_one = [0x80, 0x00, ((upper >> 8) as u8) | 0x80, upper as u8];
        let block0 = tlv(0x0C, &with_reserved_zero);
        let block1 = tlv(0x0C, &with_reserved_one);
        let d0 = iter_descriptors(&block0).next().unwrap().unwrap();
        let d1 = iter_descriptors(&block1).next().unwrap().unwrap();
        let unwrap = |b: &DescriptorBody<'_>| match b {
            DescriptorBody::MultiplexBufferUtilization(m) => *m,
            other => panic!("expected MultiplexBufferUtilization, got {other:?}"),
        };
        let m0 = unwrap(&d0.body);
        let m1 = unwrap(&d1.body);
        assert_eq!(m0.ltw_offset_lower_bound, lower);
        assert_eq!(m0.ltw_offset_upper_bound, upper);
        assert_eq!(m0, m1);
    }

    #[test]
    fn multiplex_buffer_utilization_descriptor_max_15bit_bounds() {
        // Saturate both bounds at the 15-bit ceiling (0x7FFF), with
        // bound_valid=1.
        // byte 0: 1 | 0x7F            = 0xFF
        // byte 1: 0xFF                = 0xFF
        // byte 2: reserved=1 | 0x7F   = 0xFF
        // byte 3: 0xFF                = 0xFF
        let body = [0xFF, 0xFF, 0xFF, 0xFF];
        let block = tlv(0x0C, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::MultiplexBufferUtilization(m) => {
                assert!(m.bound_valid_flag);
                assert_eq!(m.ltw_offset_lower_bound, 0x7FFF);
                assert_eq!(m.ltw_offset_upper_bound, 0x7FFF);
            }
            other => panic!("expected MultiplexBufferUtilization, got {other:?}"),
        }
    }

    #[test]
    fn multiplex_buffer_utilization_descriptor_in_es_info_list() {
        // Realistic PMT ES_info block: language + smoothing-buffer +
        // multiplex-buffer-utilization. The 0x0C descriptor lands at the
        // end and decodes alongside neighbours without disturbing them.
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x0A, &[b'e', b'n', b'g', 0x00]));
        // smoothing_buffer: leak_rate = 0x010203, sb_size = 0x040506
        block.extend_from_slice(&tlv(0x10, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        // multiplex_buffer_utilization: bound_valid=1, lower=0x0100, upper=0x0200
        // byte 0 = 0x80 | (0x0100 >> 8) = 0x81 ; byte 1 = 0x00
        // byte 2 = (0x0200 >> 8) = 0x02 ; byte 3 = 0x00
        block.extend_from_slice(&tlv(0x0C, &[0x81, 0x00, 0x02, 0x00]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x0A);
        assert_eq!(v[1].tag, 0x10);
        assert_eq!(v[2].tag, 0x0C);
        match &v[2].body {
            DescriptorBody::MultiplexBufferUtilization(m) => {
                assert!(m.bound_valid_flag);
                assert_eq!(m.ltw_offset_lower_bound, 0x0100);
                assert_eq!(m.ltw_offset_upper_bound, 0x0200);
            }
            other => panic!("expected MultiplexBufferUtilization, got {other:?}"),
        }
    }

    #[test]
    fn parse_descriptors_helper_collects_all() {
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x05, b"HDMV"));
        block.extend_from_slice(&tlv(0x0A, &[b'e', b'n', b'g', 0x00]));
        block.extend_from_slice(&tlv(0xFF, &[]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x05);
        assert_eq!(v[1].tag, 0x0A);
        assert_eq!(v[2].tag, 0xFF);
        assert!(matches!(v[2].body, DescriptorBody::Raw));
        assert!(v[2].data.is_empty());
    }

    #[test]
    fn ibp_descriptor_all_flags_set_max_length() {
        // closed=1, identical=1, max_gop_length = 0x3FFF (largest 14-bit).
        // byte 0: 1 | 1 | 0x3F          = 0xFF
        // byte 1: 0xFF                  = 0xFF
        let block = tlv(0x12, &[0xFF, 0xFF]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x12);
        match &d.body {
            DescriptorBody::Ibp(ibp) => {
                assert!(ibp.closed_gop_flag);
                assert!(ibp.identical_gop_flag);
                assert_eq!(ibp.max_gop_length, 0x3FFF);
                assert!(ibp.is_well_formed());
            }
            other => panic!("expected Ibp, got {other:?}"),
        }
    }

    #[test]
    fn ibp_descriptor_flags_clear_typical_length() {
        // closed=0, identical=0, max_gop_length = 15 (typical IBP GOP of 15).
        // byte 0: 0 | 0 | 0x00          = 0x00
        // byte 1: 0x0F                  = 0x0F
        let block = tlv(0x12, &[0x00, 0x0F]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Ibp(ibp) => {
                assert!(!ibp.closed_gop_flag);
                assert!(!ibp.identical_gop_flag);
                assert_eq!(ibp.max_gop_length, 15);
                assert!(ibp.is_well_formed());
            }
            other => panic!("expected Ibp, got {other:?}"),
        }
    }

    #[test]
    fn ibp_descriptor_closed_only_mid_length() {
        // closed=1, identical=0, max_gop_length = 0x012C (300).
        // byte 0: 1 | 0 | (0x012C >> 8 = 0x01)  = 0x81
        // byte 1: 0x2C                           = 0x2C
        let block = tlv(0x12, &[0x81, 0x2C]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Ibp(ibp) => {
                assert!(ibp.closed_gop_flag);
                assert!(!ibp.identical_gop_flag);
                assert_eq!(ibp.max_gop_length, 0x012C);
            }
            other => panic!("expected Ibp, got {other:?}"),
        }
    }

    #[test]
    fn ibp_descriptor_identical_only_mid_length() {
        // closed=0, identical=1, max_gop_length = 0x002A (42).
        // byte 0: 0 | 1 | 0x00          = 0x40
        // byte 1: 0x2A                  = 0x2A
        let block = tlv(0x12, &[0x40, 0x2A]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Ibp(ibp) => {
                assert!(!ibp.closed_gop_flag);
                assert!(ibp.identical_gop_flag);
                assert_eq!(ibp.max_gop_length, 42);
            }
            other => panic!("expected Ibp, got {other:?}"),
        }
    }

    #[test]
    fn ibp_descriptor_forbidden_zero_max_gop_length_flagged() {
        // Spec §2.6.35 forbids max_gop_length = 0; parser still surfaces
        // the value so callers can detect malformed streams.
        let block = tlv(0x12, &[0x00, 0x00]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::Ibp(ibp) => {
                assert_eq!(ibp.max_gop_length, 0);
                assert!(!ibp.is_well_formed());
            }
            other => panic!("expected Ibp, got {other:?}"),
        }
    }

    #[test]
    fn ibp_descriptor_truncated_falls_back_to_raw() {
        // 1-byte body — short of the fixed 2-byte payload, so the
        // typed decoder declines and the generic TLV layer keeps the
        // raw bytes.
        let block = tlv(0x12, &[0xFF]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x12);
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0xFF]);
    }

    #[test]
    fn ibp_descriptor_in_es_info_list_with_neighbours() {
        // Realistic PMT ES_info block carrying language + STD + IBP.
        // The IBP record lands in the middle and decodes alongside
        // neighbours without disturbing them.
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x0A, &[b'e', b'n', b'g', 0x00]));
        // ibp: closed=1, identical=0, max_gop_length=18 (typical
        // broadcast-MPEG-2 closed-GOP cadence).
        block.extend_from_slice(&tlv(0x12, &[0x80, 0x12]));
        // STD: leak_valid_flag=1
        block.extend_from_slice(&tlv(0x11, &[0x01]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x0A);
        assert_eq!(v[1].tag, 0x12);
        assert_eq!(v[2].tag, 0x11);
        match &v[1].body {
            DescriptorBody::Ibp(ibp) => {
                assert!(ibp.closed_gop_flag);
                assert!(!ibp.identical_gop_flag);
                assert_eq!(ibp.max_gop_length, 18);
                assert!(ibp.is_well_formed());
            }
            other => panic!("expected Ibp, got {other:?}"),
        }
    }

    #[test]
    fn target_background_grid_descriptor_typical_sd() {
        // horizontal_size = 720, vertical_size = 576, aspect = 3 (4:3
        // per H.262 aspect_ratio_information). 720 = 0x2D0, 576 = 0x240.
        //   byte 0: horizontal[13..6] = 0x2D0 >> 6 = 0x0B          = 0x0B
        //   byte 1: horizontal[5..0]<<2 | vertical[13..12]
        //           = (0x2D0 & 0x3F) << 2 | (0x240 >> 12)
        //           = (0x10) << 2 | 0 = 0x40                       = 0x40
        //   byte 2: vertical[11..4] = (0x240 >> 4) & 0xFF = 0x24   = 0x24
        //   byte 3: vertical[3..0]<<4 | aspect = (0x240 & 0xF)<<4 | 3
        //           = 0x00 | 0x03                                  = 0x03
        let block = tlv(0x07, &[0x0B, 0x40, 0x24, 0x03]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x07);
        match &d.body {
            DescriptorBody::TargetBackgroundGrid(g) => {
                assert_eq!(g.horizontal_size, 720);
                assert_eq!(g.vertical_size, 576);
                assert_eq!(g.aspect_ratio_information, 3);
            }
            other => panic!("expected TargetBackgroundGrid, got {other:?}"),
        }
    }

    #[test]
    fn target_background_grid_descriptor_max_fields() {
        // horizontal_size = 0x3FFF, vertical_size = 0x3FFF, aspect = 0xF
        // — every payload bit set.
        //   byte 0: 0x3FFF >> 6 = 0xFF
        //   byte 1: (0x3FFF & 0x3F) << 2 | (0x3FFF >> 12)
        //           = (0x3F << 2) | 0x3 = 0xFC | 0x3 = 0xFF
        //   byte 2: (0x3FFF >> 4) & 0xFF = 0xFF
        //   byte 3: (0x3FFF & 0xF) << 4 | 0xF = 0xF0 | 0xF = 0xFF
        let block = tlv(0x07, &[0xFF, 0xFF, 0xFF, 0xFF]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::TargetBackgroundGrid(g) => {
                assert_eq!(g.horizontal_size, 0x3FFF);
                assert_eq!(g.vertical_size, 0x3FFF);
                assert_eq!(g.aspect_ratio_information, 0xF);
            }
            other => panic!("expected TargetBackgroundGrid, got {other:?}"),
        }
    }

    #[test]
    fn target_background_grid_descriptor_all_zero() {
        let block = tlv(0x07, &[0x00, 0x00, 0x00, 0x00]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::TargetBackgroundGrid(g) => {
                assert_eq!(g.horizontal_size, 0);
                assert_eq!(g.vertical_size, 0);
                assert_eq!(g.aspect_ratio_information, 0);
            }
            other => panic!("expected TargetBackgroundGrid, got {other:?}"),
        }
    }

    #[test]
    fn target_background_grid_descriptor_short_body_falls_back_to_raw() {
        // 3-byte body — short of the fixed 4-byte payload, so the typed
        // decoder declines and the generic TLV layer keeps the raw bytes.
        let block = tlv(0x07, &[0x0B, 0x40, 0x24]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x07);
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0x0B, 0x40, 0x24]);
    }

    #[test]
    fn target_background_grid_descriptor_in_es_info_list_with_neighbours() {
        // Realistic PMT ES_info block: language + target_background_grid
        // + STD. The grid record lands in the middle and decodes alongside
        // neighbours without disturbing them. 1920×1080, aspect = 1.
        // 1920 = 0x780, 1080 = 0x438.
        //   byte 0: 0x780 >> 6 = 0x1E
        //   byte 1: (0x780 & 0x3F) << 2 | (0x438 >> 12)
        //           = (0x00) << 2 | 0 = 0x00
        //   byte 2: (0x438 >> 4) & 0xFF = 0x43
        //   byte 3: (0x438 & 0xF) << 4 | 1 = 0x80 | 0x01 = 0x81
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x0A, &[b'e', b'n', b'g', 0x00]));
        block.extend_from_slice(&tlv(0x07, &[0x1E, 0x00, 0x43, 0x81]));
        block.extend_from_slice(&tlv(0x11, &[0x01]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].tag, 0x0A);
        assert_eq!(v[1].tag, 0x07);
        assert_eq!(v[2].tag, 0x11);
        match &v[1].body {
            DescriptorBody::TargetBackgroundGrid(g) => {
                assert_eq!(g.horizontal_size, 1920);
                assert_eq!(g.vertical_size, 1080);
                assert_eq!(g.aspect_ratio_information, 1);
            }
            other => panic!("expected TargetBackgroundGrid, got {other:?}"),
        }
    }

    #[test]
    fn video_window_descriptor_typical_offsets() {
        // horizontal_offset = 320, vertical_offset = 240, priority = 5.
        // 320 = 0x140, 240 = 0x0F0.
        //   byte 0: horizontal[13..6] = 0x140 >> 6 = 0x05         = 0x05
        //   byte 1: horizontal[5..0]<<2 | vertical[13..12]
        //           = (0x140 & 0x3F) << 2 | (0x0F0 >> 12)
        //           = (0x00) << 2 | 0 = 0x00                      = 0x00
        //   byte 2: vertical[11..4] = (0x0F0 >> 4) & 0xFF = 0x0F  = 0x0F
        //   byte 3: vertical[3..0]<<4 | priority = (0x0F0 & 0xF)<<4 | 5
        //           = 0x00 | 0x05                                 = 0x05
        let block = tlv(0x08, &[0x05, 0x00, 0x0F, 0x05]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x08);
        match &d.body {
            DescriptorBody::VideoWindow(w) => {
                assert_eq!(w.horizontal_offset, 320);
                assert_eq!(w.vertical_offset, 240);
                assert_eq!(w.window_priority, 5);
            }
            other => panic!("expected VideoWindow, got {other:?}"),
        }
    }

    #[test]
    fn video_window_descriptor_max_fields() {
        // horizontal_offset = 0x3FFF, vertical_offset = 0x3FFF,
        // priority = 0xF — every payload bit set.
        //   byte 0: 0x3FFF >> 6 = 0xFF
        //   byte 1: (0x3FFF & 0x3F) << 2 | (0x3FFF >> 12) = 0xFC | 0x3 = 0xFF
        //   byte 2: (0x3FFF >> 4) & 0xFF = 0xFF
        //   byte 3: (0x3FFF & 0xF) << 4 | 0xF = 0xF0 | 0xF = 0xFF
        let block = tlv(0x08, &[0xFF, 0xFF, 0xFF, 0xFF]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::VideoWindow(w) => {
                assert_eq!(w.horizontal_offset, 0x3FFF);
                assert_eq!(w.vertical_offset, 0x3FFF);
                assert_eq!(w.window_priority, 0xF);
            }
            other => panic!("expected VideoWindow, got {other:?}"),
        }
    }

    #[test]
    fn video_window_descriptor_all_zero() {
        let block = tlv(0x08, &[0x00, 0x00, 0x00, 0x00]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match &d.body {
            DescriptorBody::VideoWindow(w) => {
                assert_eq!(w.horizontal_offset, 0);
                assert_eq!(w.vertical_offset, 0);
                assert_eq!(w.window_priority, 0);
            }
            other => panic!("expected VideoWindow, got {other:?}"),
        }
    }

    #[test]
    fn video_window_descriptor_short_body_falls_back_to_raw() {
        // 3-byte body — short of the fixed 4-byte payload, so the typed
        // decoder declines and the generic TLV layer keeps the raw bytes.
        let block = tlv(0x08, &[0x05, 0x00, 0x0F]);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x08);
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0x05, 0x00, 0x0F]);
    }

    #[test]
    fn video_window_descriptor_pairs_with_grid_in_es_info_list() {
        // Realistic PMT ES_info block: a target_background_grid_descriptor
        // (the 1920×1080 grid) immediately followed by the
        // video_window_descriptor that places this stream's window on it.
        // Window at offset (100, 50), priority 7. 100 = 0x064, 50 = 0x032.
        //   byte 0: 0x064 >> 6 = 0x01
        //   byte 1: (0x064 & 0x3F) << 2 | (0x032 >> 12)
        //           = (0x24) << 2 | 0 = 0x90
        //   byte 2: (0x032 >> 4) & 0xFF = 0x03
        //   byte 3: (0x032 & 0xF) << 4 | 7 = 0x20 | 0x07 = 0x27
        let mut block = Vec::new();
        block.extend_from_slice(&tlv(0x07, &[0x1E, 0x00, 0x43, 0x81]));
        block.extend_from_slice(&tlv(0x08, &[0x01, 0x90, 0x03, 0x27]));
        let v = parse_descriptors(&block).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].tag, 0x07);
        assert_eq!(v[1].tag, 0x08);
        match &v[0].body {
            DescriptorBody::TargetBackgroundGrid(g) => {
                assert_eq!(g.horizontal_size, 1920);
                assert_eq!(g.vertical_size, 1080);
            }
            other => panic!("expected TargetBackgroundGrid, got {other:?}"),
        }
        match &v[1].body {
            DescriptorBody::VideoWindow(w) => {
                assert_eq!(w.horizontal_offset, 100);
                assert_eq!(w.vertical_offset, 50);
                assert_eq!(w.window_priority, 7);
            }
            other => panic!("expected VideoWindow, got {other:?}"),
        }
    }

    #[test]
    fn service_descriptor_decodes_names_and_type() {
        // service_type = 0x01 (digital television),
        // provider = "Prov", service = "Channel 1".
        let mut body = vec![0x01];
        body.push(4);
        body.extend_from_slice(b"Prov");
        body.push(9);
        body.extend_from_slice(b"Channel 1");
        let block = tlv(0x48, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x48);
        match d.body {
            DescriptorBody::Service(s) => {
                assert_eq!(s.service_type, 0x01);
                assert_eq!(s.service_provider_name, b"Prov");
                assert_eq!(s.service_name, b"Channel 1");
            }
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[test]
    fn service_descriptor_empty_provider_name() {
        // Zero-length provider, non-empty service name.
        let mut body = vec![0x11]; // HD digital television
        body.push(0);
        body.push(3);
        body.extend_from_slice(b"HD1");
        let block = tlv(0x48, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match d.body {
            DescriptorBody::Service(s) => {
                assert_eq!(s.service_type, 0x11);
                assert!(s.service_provider_name.is_empty());
                assert_eq!(s.service_name, b"HD1");
            }
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[test]
    fn service_descriptor_truncated_falls_back_to_raw() {
        // provider_name_length claims 9 bytes but only 2 follow.
        let block = tlv(0x48, &[0x01, 0x09, b'X', b'Y']);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x48);
        assert!(matches!(d.body, DescriptorBody::Raw));
        assert_eq!(d.data, &[0x01, 0x09, b'X', b'Y']);
    }

    #[test]
    fn short_event_descriptor_decodes_name_and_text() {
        // ISO_639 = "eng", name = "News", text = "Daily bulletin".
        let mut body = Vec::new();
        body.extend_from_slice(b"eng");
        body.push(4);
        body.extend_from_slice(b"News");
        body.push(14);
        body.extend_from_slice(b"Daily bulletin");
        let block = tlv(0x4D, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x4D);
        match d.body {
            DescriptorBody::ShortEvent(s) => {
                assert_eq!(&s.language_code, b"eng");
                assert_eq!(s.event_name, b"News");
                assert_eq!(s.text, b"Daily bulletin");
            }
            other => panic!("expected ShortEvent, got {other:?}"),
        }
    }

    #[test]
    fn short_event_descriptor_empty_text() {
        // Zero-length text run after a non-empty name.
        let mut body = Vec::new();
        body.extend_from_slice(b"fre");
        body.push(5);
        body.extend_from_slice(b"Match");
        body.push(0);
        let block = tlv(0x4D, &body);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match d.body {
            DescriptorBody::ShortEvent(s) => {
                assert_eq!(&s.language_code, b"fre");
                assert_eq!(s.event_name, b"Match");
                assert!(s.text.is_empty());
            }
            other => panic!("expected ShortEvent, got {other:?}"),
        }
    }

    #[test]
    fn short_event_descriptor_truncated_falls_back_to_raw() {
        // name_length claims 9 bytes but only 2 follow the language code.
        let block = tlv(0x4D, &[b'e', b'n', b'g', 0x09, b'X', b'Y']);
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x4D);
        assert!(matches!(d.body, DescriptorBody::Raw));
    }

    #[test]
    fn network_name_descriptor_decodes_whole_payload() {
        // The whole descriptor payload is the name run (no inner length).
        let block = tlv(0x40, b"Example Network");
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        assert_eq!(d.tag, 0x40);
        match d.body {
            DescriptorBody::NetworkName(n) => {
                assert_eq!(n.network_name, b"Example Network");
            }
            other => panic!("expected NetworkName, got {other:?}"),
        }
    }

    #[test]
    fn network_name_descriptor_empty_is_legal() {
        let block = tlv(0x40, b"");
        let d = iter_descriptors(&block).next().unwrap().unwrap();
        match d.body {
            DescriptorBody::NetworkName(n) => assert!(n.network_name.is_empty()),
            other => panic!("expected NetworkName, got {other:?}"),
        }
    }
}
