# Changelog

All notable changes to this crate are documented in this file. The
format is loosely based on [Keep a Changelog] and the crate adheres to
[Semantic Versioning] from `0.1.0` onward.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

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
