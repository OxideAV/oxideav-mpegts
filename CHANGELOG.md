# Changelog

All notable changes to this crate are documented in this file. The
format is loosely based on [Keep a Changelog] and the crate adheres to
[Semantic Versioning] from `0.1.0` onward.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- `SelectionInformationTable` — the DVB Selection Information Table
  (SIT, ETSI EN 300 468 §5.2.10 / §7.1.2 / Table 164) carried on the
  fixed PID `0x001F` (`SIT_PID`) with `table_id == 0x7F`
  (`SIT_TABLE_ID`). The SIT describes the services and events carried by
  a **partial** TS — the kind produced when a single service is
  extracted from a full multiplex (e.g. a personal-video recording).
  Unlike the DIT it is a **long-form** section: `parse` CRC-verifies the
  standard `version_number` / `section_number` / `last_section_number`
  header (the same way as PAT/PMT/SDT), reads the SIT-wide
  transmission-info descriptor loop (lifted by
  `SelectionInformationTable::iter_descriptors` — the SIT-only
  `partial_transport_stream_descriptor`, tag `0x63`, rides here), then a
  loop of `SitService` entries each pairing a `service_id` and the
  original present event's typed `running_status` with its own
  descriptor loop (`SitService::iter_descriptors`). A wrong `table_id`,
  a bad CRC, or a descriptor-length overrun is rejected with `TsError`.
- `StuffingTable` — the DVB Stuffing Table (ST, ETSI EN 300 468 §5.2.8
  / Table 11) with `table_id == 0x72` (`ST_TABLE_ID`). The ST is the
  mechanism that **invalidates** existing sections at a delivery-system
  boundary (e.g. a cable head-end): when one section of a sub_table is
  overwritten every section of that sub_table is stuffed out so the
  `section_number` integrity is retained. It is a **short-form** section
  whose `section_syntax_indicator` may be `0` or `1`, with no version /
  section header and **no CRC**, so `StuffingTable::parse` surfaces the
  `section_syntax_indicator` flag plus the raw `data_byte` run (which
  has no meaning per §5.2.8). The ST may appear on any SI PID; a wrong
  `table_id` or a `section_length` overrun is rejected with `TsError`.
- `DiscontinuityInformationTable` — the DVB Discontinuity Information
  Table (DIT, ETSI EN 300 468 §5.2.9 / §7.1.1 / Table 163) carried on
  the fixed PID `0x001E` (`DIT_PID`) with `table_id == 0x7E`
  (`DIT_TABLE_ID`). The DIT is inserted at transition points in a
  **partial** TS where SI information may be discontinuous. It is a
  **short-form** section (no version / section header, **no CRC**) with
  a `section_length` fixed at `0x001`; `parse` decodes the single body
  byte's top bit into `transition_flag` — `true` for a change of the
  originating source (originating TS / position change, e.g. a
  time-shift), `false` for a change of the selection only — and ignores
  the 7 `reserved_future_use` bits. A wrong `table_id` or an empty body
  is rejected with `TsError`. New public constants `DIT_TABLE_ID` /
  `DIT_PID` / `SIT_TABLE_ID` / `SIT_PID`.
- `RunningStatusTable` — the DVB Running Status Table (RST, ETSI
  EN 300 468 §5.2.7 / Table 10) carried on the fixed PID `0x0013`
  (`RST_PID`) with `table_id == 0x71` (`RST_TABLE_ID`). The RST is the
  fast event-status update channel — a dedicated table refreshes the
  running status of one or more events quicker than a full EIT cycle
  when an event starts early or late. Unlike the long-form tables it is
  a **short-form** section (`section_syntax_indicator == 0`, no version
  / section header and **no CRC**), so the whole body is a flat run of
  fixed 9-byte `RstEntry` records, each locating an event by the
  `(transport_stream_id, original_network_id, service_id, event_id)`
  tuple and carrying its updated `RunningStatus`. A wrong `table_id`, a
  body that isn't a whole number of entries, or a `section_length` that
  overruns the section are all rejected with `TsError`.
- `BouquetAssociationTable` — the DVB Bouquet Association Table (BAT,
  ETSI EN 300 468 §5.2.2 / Table 4) carried on the SDT's fixed PID
  `0x0011` (`BAT_PID`) with `table_id == 0x4A` (`BAT_TABLE_ID`). A
  *bouquet* groups services into a marketable package that may cross
  network boundaries, independent of the physical multiplex layout the
  NIT describes. `BouquetAssociationTable::parse` reads a section into
  the `bouquet_id` (from `table_id_extension`), the standard version /
  section bookkeeping, the bouquet-level descriptor loop, and a typed
  `transport_stream_loop` of `BatTransportStream` entries — each pairing
  `(transport_stream_id, original_network_id)` with its own descriptor
  loop (`BatTransportStream::iter_descriptors`). The body is byte-for-
  byte the same shape as the NIT, so sections may be reassembled with
  `PsiSectionAssembler` before parsing and a wrong `table_id` / bad CRC
  is rejected with `TsError`.
- `BouquetNameDescriptor` — typed view of the DVB
  `bouquet_name_descriptor` (tag `0x47`, ETSI EN 300 468 §6.2.4 /
  Table 21). The entire descriptor payload is the `bouquet_name` run
  (no inner length prefix), exposed as raw bytes — the annex-A
  character-table selection is left to the caller, consistent with the
  `network_name_descriptor`. This is the bouquet-level descriptor a BAT
  usually carries to name the bouquet, lifted through
  `BouquetAssociationTable::iter_descriptors`.
- Multi-program demux selection — `MpegTsDemuxer` now collects every
  non-network program the PAT advertises (§2.4.4.5) into a typed
  `TsProgram { program_number, pmt_pid }` list exposed via
  `programs()`. The default `open` path keeps first-program-wins;
  `MpegTsDemuxer::open_program(input, program_number)` selects any
  other program (with `selected_program()` reporting the active
  choice). Previously the parsed PAT was discarded and only the first
  program was ever reachable.
- Demux-path timing reconstruction — the selected program's `PCR_PID`
  (§2.4.4.9) now feeds a `PcrTracker` for 27 MHz clock recovery
  (`last_pcr()` / `pcr_pid()`), and each emitted packet's 33-bit
  PTS/DTS is unwrapped through a per-PID `PtsTracker` (§2.4.3.7) onto
  the monotonic 64-bit extended timeline so a `2^33` ring wrap no
  longer surfaces as a backward jump. The first observed PTS anchors
  `StreamInfo.start_time`.
- `PtsTracker` (clock module) — per-PID PTS / DTS unwrapper per
  ISO/IEC 13818-1 §2.4.3.7. PES timestamps are 33-bit 90 kHz values that
  wrap every ~26.5 h; the tracker turns the raw values seen on one PID
  into a monotonic 64-bit **extended** timeline (`extended()`), counting
  `2^33` wraps (`TIMESTAMP_MODULUS_90KHZ`) while distinguishing a genuine
  wrap from a backward splice / seek discontinuity via the new
  `TimestampEvent` (`First` / `Forward` / `Wrapped` / `Backward`).
- Full ISO/IEC 13818-1 Table 2-29 `stream_type` mapping — [`StreamType`]
  now names the complete base assignment range `0x01..=0x26` (MPEG-1/2/4
  video + audio, AAC-ADTS / AAC-LATM, private sections / PES, MHEG,
  DSM-CC carriers, the `0x15..=0x19` metadata carriers, IPMP, AVC / SVC /
  MVC / MVCD, JPEG 2000 video, stereoscopic MPEG-2 / AVC views, HEVC and
  its temporal subset) plus AVS video (`0x42`) — on top of the existing
  HDMV-extended Blu-ray range. New classification predicates
  `is_metadata()` and `is_private()` join `is_video` / `is_audio` /
  `is_subtitle`; `is_subtitle` now also covers MPEG-4 timed text. The
  demuxer's `stream_type` → `CodecParameters` routing gains MPEG-1 video,
  MPEG-1/2 audio, AAC, MPEG-4 visual, JPEG 2000, stereoscopic views and
  MPEG-4 text arms, with an explicit drop for non-A/V payloads.
- DVB PMT elementary-stream descriptors (EN 300 468) — the tags a
  demultiplexer needs to route a private-data PES to the right decoder:
  `stream_identifier_descriptor` (`0x52`, §6.2.39 → `component_tag`),
  `teletext_descriptor` (`0x56`, §6.2.43 → per-language EBU teletext
  pages with split `teletext_type` / `teletext_magazine_number`),
  `subtitling_descriptor` (`0x59`, §6.2.41 → per-language EN 300 743
  subtitle services with `composition_page_id` / `ancillary_page_id`),
  `AC-3_descriptor` (`0x6A`, annex D Table D.6 → flag-gated
  `component_type` / `bsid` / `mainid` / `asvc`),
  `enhanced_AC-3_descriptor` (`0x7A`, annex D Table D.7 → the AC-3 set
  plus `mixinfoexists` and three independent-substream fields), and
  `DTS_descriptor` (`0x7B`, annex G Table G.1 → the 40-bit
  `sample_rate_code` / `bit_rate_code` / `nblks` / `fsize` /
  `surround_mode` / `lfe_flag` / `extended_surround_flag` bitfield head).
  Each surfaces a new `DescriptorBody` variant; malformed bodies fall
  back to `Raw`.
- `content_descriptor` (tag `0x54`, EN 300 468 §6.2.9) decode — the DVB
  genre classifier carried in the EIT event loop alongside the short /
  extended event descriptors. `DescriptorBody::Content` exposes a flat
  array of `ContentNibble` records, each pairing the two 4-bit content
  nibbles (Table 29 genre index) with the broadcaster-defined
  `user_byte`. Genre strings are left to the caller; an empty or
  odd-length body falls back to `Raw`.
- `extended_event_descriptor` (tag `0x4E`, EN 300 468 §6.2.15) decode —
  the long-form companion to the `short_event_descriptor`, carried in
  the EIT event loop. `DescriptorBody::ExtendedEvent` exposes the
  `descriptor_number` / `last_descriptor_number` association pair, the
  language code, a `Vec` of two-column `(item_description, item)` pairs,
  and the non-itemized free text. Item/text runs stay raw (annex A).
- DVB Time and Date Table (TDT, EN 300 468 §5.2.5) and Time Offset
  Table (TOT, §5.2.6) parsers — both short-form sections on PID
  `0x0014`. `TimeDateTable` / `TimeOffsetTable` decode the 40-bit
  MJD/BCD `UTC_time` via a shared `decode_utc_time` helper; the TOT
  additionally verifies its CRC-32 and exposes a descriptor loop.
- `local_time_offset_descriptor` (tag `0x58`, EN 300 468 §6.2.20)
  decode — per-country offset entries
  (`DescriptorBody::LocalTimeOffset`).

## [0.0.2](https://github.com/OxideAV/oxideav-mpegts/compare/v0.0.1...v0.0.2) - 2026-06-15

### Other

- decode §2.6.14 video_window_descriptor (tag 0x08)
- add DVB Event Information Table (EIT, EN 300 468 §5.2.4)
- add DVB Service Description Table (SDT, EN 300 468 §5.2.3)
- add Transport Stream Description Table (TSDT, §2.4.4.12)
- decode the full PES_extension body (Table 2-17 concluded, §2.4.3.7)
- target_background_grid (tag 0x07, §2.6.12 Table 2-49)
- ibp_descriptor (tag 0x12, §2.6.34)
- drop release-plz.toml — use release-plz defaults across the workspace
- multiplex_buffer_utilization_descriptor (tag 0x0C, §2.6.22)
- hierarchy_descriptor (tag 0x04, §2.6.6)
- copyright_descriptor (tag 0x0D, §2.6.24)
- smoothing_buffer_descriptor (tag 0x10, §2.6.30)
- PsiSectionAssembler + ConditionalAccessTable for multi-TS-packet sections
- decode every optional PES-header field (Table 2-17)
- unpack every optional field in the adaptation field (§2.4.3.4)
- PCR jitter / time-base discontinuity tracker + per-PID CC classifier
- add four more §2.6 descriptor decoders (alignment, sysclk, max-bitrate, STD)
- parse §2.6 program / ES descriptors (registration, ISO-639, CA, AVC, HEVC)
- resync past short TS sync misalignments instead of erroring
- include input byte offset in sync-byte / short-read errors
- write MPEG-TS files from oxideav_core::Packet streams
- move oxideav_core::register! to crate root so meta can resolve it
- demuxer + registry: container-shape Demuxer for the registry

### Added

- `NetworkInformationTable` — the DVB Network Information Table (NIT,
  ETSI EN 300 468 §5.2.1 Table 3) carried on the fixed PID `0x0010`
  ([`NIT_PID`]). `NetworkInformationTable::parse` reads a section into
  the `network_id` (from `table_id_extension`), the standard version /
  section bookkeeping, the network-level descriptor loop, and a typed
  `transport_stream_loop` of `NitTransportStream` entries. Both NIT
  `table_id` classifications are accepted — actual network (`0x40`,
  `NIT_ACTUAL_TABLE_ID`) and other networks (`0x41`,
  `NIT_OTHER_TABLE_ID`), with `other_network` recording which —
  matching the predicate `NetworkInformationTable::is_nit_table_id`.
  Each `NitTransportStream` pairs `(transport_stream_id,
  original_network_id)` — the combination the spec notes uniquely
  identifies a TS throughout the application area — with its own
  descriptor loop, walkable via `NitTransportStream::iter_descriptors`;
  the network-level loop is walkable via
  `NetworkInformationTable::iter_descriptors`. The two-level descriptor
  layout (network-wide loop then per-TS loops) mirrors the PMT's
  program-info / ES-info split, and sections may be reassembled with
  `PsiSectionAssembler` before parsing like the other long-form tables.
- `NetworkNameDescriptor` — typed view of the DVB
  `network_name_descriptor` (tag `0x40`, ETSI EN 300 468 §6.2.27
  Table 81). The entire descriptor payload is the `network_name` run
  (no inner length prefix), exposed as raw bytes — the EN 300 468
  annex-A character-table selection is left to the caller, consistent
  with the `service_descriptor` / `short_event_descriptor` name fields.
  This is the network-level descriptor a NIT usually carries to name
  the delivery system, wired through the shared descriptor decoder so
  `NetworkInformationTable::iter_descriptors` lifts it.
- `VideoWindowDescriptor` — typed view of the §2.6.14
  video_window_descriptor (tag `0x08`, Table 2-50). Surfaces the
  four-byte body as the 14-bit `horizontal_offset`, the 14-bit
  `vertical_offset` (the top-left position of the stream's display
  window on the grid per §2.6.15), and the 4-bit `window_priority`
  (overlap order, `0` lowest through `15` always-visible). The body
  shares the target_background_grid_descriptor's wire layout (14 + 14 +
  4 bits across four bytes, both offsets big-endian and spanning a byte
  boundary), and the table carries no reserved bits, so all 32 payload
  bits are read. Bodies shorter than four bytes fall back to
  `DescriptorBody::Raw`. Wired through `PmtStream::iter_descriptors` and
  `ProgramMapTable::iter_program_descriptors` alongside the existing tag
  set. This completes the §2.6.12–§2.6.15 grid/window descriptor pair:
  a target_background_grid_descriptor (tag `0x07`) establishes the
  display grid and a video_window_descriptor places the associated
  stream's window onto it.
- `EventInformationTable` — the DVB Event Information Table (EIT,
  ETSI EN 300 468 §5.2.4 / Table 7), carrying chronological per-event
  metadata for the services in a multiplex. Carried on the fixed PID
  `EIT_PID` (`0x0012`); `parse` accepts all four `table_id`
  classifications — present/following on the actual TS
  (`EIT_ACTUAL_PF_TABLE_ID`, `0x4E`) and other TSs (`0x4F`), and the
  event-schedule ranges `0x50`–`0x5F` (actual) / `0x60`–`0x6F` (other)
  — recording `other_transport_stream` and `schedule`. It CRC-verifies
  the long-form section header the same way as PAT/PMT/SDT, reads
  `transport_stream_id` / `original_network_id` /
  `segment_last_section_number` / `last_table_id`, then a loop of
  `EitEvent` entries (`event_id`, decoded `start_time`, `duration`,
  `running_status`, `free_CA_mode`, and a per-event descriptor block).
  A truncated event, a wrong `table_id`, or a bad CRC are rejected with
  `TsError`.
- `EitDateTime` / `EitDuration` — the EIT `start_time` 40-bit field is
  decoded per EN 300 468 annex C: 16 bits of Modified Julian Date
  converted to a Gregorian `(year, month, day)` via the integer
  conversion formula, plus 24 bits of 4-bit BCD UTC time. The
  all-ones sentinel surfaces as `None`. `duration` is the 24-bit BCD
  hours/minutes/seconds, with `EitDuration::as_seconds`. The spec
  worked examples (`0xC0 7912 4500` → 1993-10-13 12:45:00 and
  `0x01 4530` → 01:45:30) are pinned as tests.
- `ShortEventDescriptor` (DVB descriptor tag `0x4D`, EN 300 468
  §6.2.37 / Table 93) decoded by the descriptor layer — the 24-bit
  `ISO_639_language_code` plus the raw `event_name` / `text` byte runs
  (DVB text strings, annex A character-table selection left to the
  caller). Carried in the EIT event loop, this is the source of an
  event's human-readable name for the `oxideav remux bluray://` path.
- `ServiceDescriptionTable` — the DVB Service Description Table (SDT,
  ETSI EN 300 468 §5.2.3 / Table 5), the first Service Information
  table beyond the ISO/IEC 13818-1 PSI set. Carried on the fixed PID
  `SDT_PID` (`0x0011`); sections describing the actual TS use
  `SDT_ACTUAL_TABLE_ID` (`0x42`) and those describing other TSs use
  `SDT_OTHER_TABLE_ID` (`0x46`). `parse` accepts both table_ids
  (recording which in `other_transport_stream`), CRC-verifies the
  long-form section header the same way as PAT/PMT, then reads
  `original_network_id` plus a loop of `SdtService` entries
  (`service_id`, `EIT_schedule_flag`, `EIT_present_following_flag`,
  `running_status` as the typed `RunningStatus` enum from Table 6,
  `free_CA_mode`, and a per-service descriptor block). A truncated
  service entry, a wrong `table_id`, or a bad CRC are rejected with
  `TsError`.
- `ServiceDescriptor` (DVB descriptor tag `0x48`, EN 300 468 §6.2.33 /
  Table 88) decoded by the descriptor layer — `service_type` plus the
  raw `service_provider_name` / `service_name` byte runs (DVB text
  strings left undecoded; charset selection is the caller's concern).
  Lifted through `SdtService::iter_descriptors`, this is the source of
  a service's human-readable name for the remux→MKV title-naming path.
- `TransportStreamDescriptionTable` — the Transport Stream Description
  Table (TSDT, §2.4.4.12 / Table 2-30-1). The TSDT is the fourth
  ISO/IEC 13818-1 PSI table after PAT / CAT / PMT: an optional table on
  the fixed PID `TSDT_PID` (`0x0002`) with `table_id == TSDT_TABLE_ID`
  (`0x03`) that carries a single `descriptor()` loop (§2.6) applying to
  the **entire** Transport Stream. Structurally it mirrors the CAT — a
  long-form section header (`table_id` … `last_section_number`) whose
  bytes 3–4 are reserved (no `table_id_extension` meaning), then the
  descriptor block, then CRC-32. `parse` rejects a wrong `table_id` as
  `TsError::Unsupported`; `iter_descriptors` lifts the body to typed
  `Descriptor` records, and a section that overflows one TS payload
  reassembles through the existing `PsiSectionAssembler` before
  parsing. New public constants `TSDT_TABLE_ID` and `TSDT_PID`.
- `PesExtension` — full decode of the `PES_extension` body (§2.4.3.7,
  Table 2-17 concluded), replacing the bare
  `pes_extension_present: bool` on `PesPacket` with
  `pes_extension: Option<PesExtension>`. All five flag-gated
  sub-fields are surfaced: the 16-byte `PES_private_data`, the raw
  `pack_header()` bytes (length-prefixed by `pack_field_length`,
  carried verbatim without interpretation), the
  `program_packet_sequence_counter` group
  (`ProgramPacketSequenceCounter` — 7-bit counter,
  `MPEG1_MPEG2_identifier`, 6-bit `original_stuff_length`), the
  P-STD buffer pair (`PStdBuffer` — `scale` + 13-bit `size`, with a
  `size_bytes()` helper applying the §2.4.3.7 128-vs-1024-byte units
  rule), and the `PES_extension_flag_2` reserved bytes
  (`PES_extension_field_length`-prefixed, surfaced verbatim since
  every body byte is `reserved` in this edition of the spec). Each
  absent sub-flag maps to `None`; truncation anywhere inside the
  extension is a `TsError::Truncated` naming the exact field; the
  three reserved bits in the sub-flag byte are ignored on read. This
  completes the Table 2-17 optional PES header — every syntax element
  from the `'10'` marker through the stuffing bytes now has a typed
  decode.
- `TargetBackgroundGridDescriptor` — typed view of the §2.6.12
  target_background_grid_descriptor (tag `0x07`, Table 2-49). Surfaces
  the four-byte body as the 14-bit `horizontal_size`, the 14-bit
  `vertical_size` (both grid dimensions in pixels per §2.6.13), and the
  4-bit `aspect_ratio_information` (the raw H.262 / ISO/IEC 13818-2
  aspect-ratio code, which this crate does not further decode). The
  table carries no reserved bits, so all 32 payload bits are read; both
  size fields are big-endian and span a byte boundary in the middle of
  the body. Bodies shorter than four bytes fall back to
  `DescriptorBody::Raw`. Wired through `PmtStream::iter_descriptors` and
  `ProgramMapTable::iter_program_descriptors` alongside the existing tag
  set. The paired §2.6.14 video_window_descriptor (tag `0x08`) that
  places a stream's window on this grid is now also decoded.
- `IbpDescriptor` — typed view of the §2.6.34 IBP_descriptor (tag
  `0x12`, Table 2-61). Surfaces the two-byte body as `closed_gop_flag`,
  `identical_gop_flag`, and the 14-bit `max_gop_length` (big-endian,
  packed against the LSB of the leading byte). Spec §2.6.35 forbids
  `max_gop_length == 0`; the parser still surfaces the value rather
  than dropping it, and exposes the well-formed predicate via
  `IbpDescriptor::is_well_formed` so callers can detect malformed
  streams. Bodies shorter than the two-byte fixed payload fall back
  to `DescriptorBody::Raw`. Wired through `PmtStream::iter_descriptors`
  and `ProgramMapTable::iter_program_descriptors` alongside the
  existing tag set.
- `MultiplexBufferUtilizationDescriptor` — typed view of the §2.6.22
  multiplex_buffer_utilization_descriptor (tag `0x0C`, Table 2-55).
  Surfaces the four-byte body as `bound_valid_flag`,
  `ltw_offset_lower_bound`, and `ltw_offset_upper_bound`. Both bounds
  are 15-bit values in units of 90 kHz clock periods (the LTW_offset
  unit defined in §2.4.3.4). Reserved bits on byte 2 are ignored on
  the read path so a non-zero reservation doesn't corrupt the parse;
  bodies shorter than four bytes fall back to `DescriptorBody::Raw`.
  Wired through `PmtStream::iter_descriptors` and
  `ProgramMapTable::iter_program_descriptors` alongside the existing
  tag set. The 15-bit upper-bound width follows the §2.6.23 semantic
  text (which describes the field as 15-bit) and the adaptation-field
  `ltw_offset` width in §2.4.3.4; the Table 2-55 syntax row's 14-bit
  label leaves the body summing to 31 bits, which can't terminate on
  a clean byte boundary, so the 15-bit reading is the consistent one.
- `HierarchyDescriptor` + `HierarchyType` — typed view of the §2.6.6
  hierarchy_descriptor (tag `0x04`, Table 2-43). Surfaces the
  four-byte body — `hierarchy_type` (Table 2-44, full 8-variant
  mapping for the 1..7 + 15 named values plus `Reserved(u8)` for the
  Table 2-44 `0` / `8..=14` reserved range), `hierarchy_layer_index`,
  `hierarchy_embedded_layer_index` (undefined per §2.6.7 when the
  type is `BaseLayer` — `HierarchyType::is_base_layer()` flags that
  case), and `hierarchy_channel`. Reserved bits on every byte are
  masked off on the read path so a non-zero reservation doesn't
  corrupt the parse; bodies shorter than four bytes fall back to
  `DescriptorBody::Raw`. Wired through `PmtStream::iter_descriptors`
  and `ProgramMapTable::iter_program_descriptors` alongside the
  existing tag set.
- `CopyrightDescriptor` — typed view of the §2.6.24
  copyright_descriptor (tag `0x0D`, Table 2-56). Surfaces the 32-bit
  `copyright_identifier` (issued by the §2.9 Registration Authority)
  plus the trailing `additional_copyright_info` byte slice (whose
  semantics are scoped to the assignee of the identifier per §2.6.25
  and stay opaque to this crate). Bodies shorter than the 4-byte
  fixed identifier fall back to `DescriptorBody::Raw`. Wired through
  `PmtStream::iter_descriptors` and
  `ProgramMapTable::iter_program_descriptors` alongside the existing
  tag set.
- `SmoothingBufferDescriptor` — typed view of the §2.6.30
  smoothing_buffer_descriptor (tag `0x10`, Table 2-59). Surfaces the
  raw 22-bit `sb_leak_rate` and `sb_size` fields plus convenience
  helpers `leak_rate_bits_per_second` (× 400 — same as
  `maximum_bitrate_descriptor`'s units), `leak_rate_bytes_per_second`
  (× 50), and `buffer_size_bytes` (identity, since `sb_size` is
  already in bytes per §2.6.31). Bodies shorter than the six-byte
  fixed payload fall back to `DescriptorBody::Raw`; reserved bits on
  the two header bytes are ignored on the read path so a non-zero
  reservation doesn't corrupt the parse. Wired through
  `PmtStream::iter_descriptors` and `ProgramMapTable::iter_program_descriptors`
  alongside the existing tag set.
- `PsiSectionAssembler` — per-PID stateful reassembler that joins a
  PSI section across multiple 188-byte TS packets per ISO/IEC 13818-1
  §2.4.4. Feeds on `(payload, pusi, continuity_counter)` tuples and
  yields complete `Vec<u8>` sections that run from `table_id` through
  the CRC trailer (the same shape every `Parse::parse` consumes).
  Enforces: §2.4.4.1 `pointer_field` semantics (PUSI=1 finishes the
  previous in-flight section, then starts new ones), §2.4.4 stuffing
  byte termination (`0xFF` table_id ends iteration within one
  payload), §2.4.4 1024-byte cap (`MAX_PSI_SECTION_LEN`), §2.4.3.3
  CC-skip detection (an unexpected continuity_counter discards the
  in-flight buffer rather than concatenating misordered bytes), and
  back-to-back sections in a single payload. The demuxer's PAT and
  PMT discovery loops now drive a `PsiSectionAssembler` each, so a
  PMT whose descriptor block exceeds the ~184-byte single-TS payload
  budget (common with multi-language PGS + multi-codec audio + a
  rich registration descriptor) is reassembled correctly across as
  many continuation packets as the section spans.
- `ConditionalAccessTable` — parser for §2.4.4.6 / Table 2-27 (CAT,
  `table_id == 0x01` on PID `0x0001`). Exposes
  `version_number` / `current_next_indicator` /
  `section_number` / `last_section_number` plus the carried
  descriptor() loop via `iter_descriptors`, which lifts CA_descriptor
  entries (tag 0x09) into the existing typed
  `DescriptorBody::Ca { ca_system_id, ca_pid, private_data }` shape.
- `CAT_TABLE_ID` (0x01), `PAT_PID` (0x0000), `CAT_PID` (0x0001) and
  `MAX_PSI_SECTION_LEN` constants — every fixed value §2.4.4 wires
  to a normative PID or upper bound is now a named export.
- `PesPacket` now surfaces every optional PES-header field defined in
  ISO/IEC 13818-1 §2.4.3.7 / Table 2-17 beyond PTS+DTS: the five
  flags1 bits (`pes_scrambling_control`, `pes_priority`,
  `data_alignment_indicator`, `copyright`, `original_or_copy`) plus
  the flag-gated bodies `escr_27mhz` (42-bit ESCR_base × 300 +
  ESCR_extension), `es_rate_50bps` (22-bit ES_rate), `dsm_trick_mode`
  (raw 8-bit byte), `additional_copy_info` (7-bit), and
  `previous_pes_packet_crc` (16-bit). The PES_extension_flag is
  preserved as a `pes_extension_present` bool; its sub-fields stay
  inside the `PES_header_data_length` budget and are skipped past
  with the rest of the optional area. A truncated optional body
  (e.g. `PTS_DTS_flags = 0b11` but `PES_header_data_length = 5`)
  surfaces as `TsError::Truncated`.
- `clock` module — per-PCR-PID PCR recovery, time-base discontinuity
  detection (signalled via `discontinuity_indicator` per §2.4.3.5 *or*
  detected by an unsignalled PCR jump beyond a configurable jitter
  window), and per-sample jitter / instantaneous-bitrate readings.
  Sibling `ContinuityTracker` classifies each TS packet on a PID
  against §2.4.3.3 (continuous / spec-permitted duplicate / no-payload
  carrier / dropped / signalled discontinuity), enforcing the
  one-duplicate-per-CC cap.
- `descriptor` module — generic ISO/IEC 13818-1 §2.6 TLV walker plus
  typed decoders for `registration` (0x05), `ISO_639_language` (0x0A),
  `CA` (0x09), `video_stream` (0x02), `audio_stream` (0x03),
  `AVC_video` (0x28), and `HEVC_video` (0x38).
- Four additional §2.6 descriptor decoders surfaced as typed bodies:
  `data_stream_alignment_descriptor` (0x06, §2.6.10),
  `system_clock_descriptor` (0x0B, §2.6.20),
  `maximum_bitrate_descriptor` (0x0E, §2.6.26 — with a
  `bits_per_second()` convenience), and
  `STD_descriptor` (0x11, §2.6.32).
- `ProgramMapTable::iter_program_descriptors` and
  `PmtStream::iter_descriptors` convenience accessors that walk the
  PMT's program-info / per-ES descriptor blocks.
- `AdaptationField` now decodes every optional field in §2.4.3.4 /
  Table 2-6 beyond PCR: `opcr_base` / `opcr_extension` (OPCR coded
  identically to PCR), signed `splice_countdown`, `transport_private_data`
  (length-prefixed byte slice), and an `adaptation_field_extension`
  body with `ltw_valid_flag` + `ltw_offset`, 22-bit `piecewise_rate`,
  and 33-bit `dts_next_au` with 4-bit `splice_type` from the
  seamless-splice sub-field. Reserved padding inside the extension is
  silently skipped; a truncated extension surfaces as
  `TsError::Truncated`.
