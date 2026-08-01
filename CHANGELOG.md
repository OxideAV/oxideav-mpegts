# Changelog

All notable changes to this crate are documented in this file. The
format is loosely based on [Keep a Changelog] and the crate adheres to
[Semantic Versioning] from `0.1.0` onward.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- **T-STD buffer model (§2.4.2).** New `tstd` module:
  `analyze_tstd(&[u8], &TStdConfig) -> TStdReport` replays a whole
  transport stream (any physical framing) through the Transport
  Stream system target decoder. The §2.4.2.2 arrival clock is
  reconstructed from the PCRs on the configured `PCR_PID` (equations
  2-1 to 2-5: piecewise-constant transport rate between PCR pairs,
  wrap-aware on the 33+9-bit field, and the discontinuity rule —
  the previous interval's rate carries across a signalled time-base
  change, with decode times re-anchored on the new base). Each
  configured elementary PID runs its §2.4.2.3 chain as a fluid
  (piecewise-linear) model: whole TS packets enter the fixed
  512-byte `TBn` and drain at `Rxn` FIFO; PES bytes continue into
  the main buffer `Bn` (audio — PES headers are held until the
  access-unit removal, per the audio rule) or into `MBn → EBn` via
  the leak method (`Rbxn`, PES headers discarded at transfer, EBn
  back-pressure stalling the leak); whole access units leave at
  their decode time (DTS when coded, else PTS; access units are
  PES-granular, timestamp-less continuation PES packets extend the
  open unit). `system_pids` share the `TBsys → Bsys` chain with the
  equation 2-7 `Rsys` drain. Violations follow §2.4.2.6: `TbOverflow`
  / `TbBusyOverOneSecond` (empty-once-a-second), `MainOverflow` /
  `MainUnderflow`, `MbOverflow` / `MbBusyOverOneSecond`,
  `EbUnderflow`, `DelayOverOneSecond` (`tdn(j) − t(i) ≤ 1 s`), and
  `BsysOverflow`, deduplicated per rule + PID with the worst figure
  kept and every occurrence counted. `TStdStreamModel::audio()`
  carries the spec-fixed non-ADTS numbers (`Rxn` 2 Mbit/s, `BSn`
  3584); `video_low_main_level` / `video_high_level` apply the
  §2.4.2.3 `Rxn = 1.2 × Rmax`, `Rbxn`, and `MBSn = BSmux + BSoh
  (+ VBVmax − vbv_buffer_size)` formulas over caller-supplied
  `Rmax` / VBV figures (the values live in ISO/IEC 13818-2 tables).
  Per-chain stats report peak `TBn` / main / `EBn` occupancy, access
  units, and worst delay. Pinned by hand-built rate-exact streams:
  a conformant audio stream and a conformant 25 fps video stream
  pass; a 40 Mbit/s audio burst trips `TbOverflow`, hoarded audio
  trips `MainOverflow`, late data `MainUnderflow`, a 2 s decode
  offset `DelayOverOneSecond`, an under-provisioned leak
  `EbUnderflow`; the clock survives a PCR wrap and a signalled
  discontinuity; PSI loads ride the system branch.

- **PES splitting on the mux path (§2.4.3.7).** A bounded-length
  (non-video) frame whose payload exceeds the 16-bit
  `PES_packet_length` budget — the field counts the 3 post-length
  header bytes, the optional PTS/DTS area, and the payload — now
  splits across several PES envelopes instead of erroring: the first
  carries the timestamps, continuations carry none (a PES packet need
  not hold a whole access unit; alignment is only promised by the
  `data_alignment_indicator`, which stays clear). Each envelope
  fragments into TS packets with its own PUSI, the frame's PCR /
  `random_access_indicator` ride the first envelope, and an armed
  splicing point annotates only the last — the splicing point sits
  after the frame's final byte. Video stream_ids keep the unbounded
  `PES_packet_length = 0` single-envelope form. Demux round-trip:
  the split envelopes surface as consecutive packets whose payloads
  concatenate to the original frame, the first with the PTS.

- **Splice-point mux API (§2.4.3.4 / §2.4.3.5 / Annex K).**
  `MpegTsMuxer::signal_splice_after(stream_index, SpliceSpec)` arms a
  splicing point immediately after the next written `Packet`'s PES
  envelope: its payload-carrying TS packets gain `splicing_point_flag`
  with a positive `splice_countdown` counting down to zero on the last
  one — whose last payload byte is the last byte of the coded frame by
  construction (one `Packet` = one PES + adaptation-field tail
  stuffing), and the next payload on the PID starts a PES packet, the
  two §2.4.3.5 alignment constraints. `SpliceSpec::seamless`
  (`SeamlessSpliceSpec { splice_type, dts_next_au }`) additionally
  rides the adaptation-field extension's `splice_type` / `DTS_next_AU`
  pair on every annotated packet, honouring the §2.4.3.5 rule that
  `seamless_splice_flag`, once set with a positive countdown, stays
  set through the countdown-zero packet (Annex K.1.2 seamless splicing
  point). `SpliceSpec::post_splice_packets` continues the annotation
  past the splicing point with the negative countdown (`-1`, `-2`, …)
  across following PES envelopes. A PES spanning more than 128
  payload packets starts the countdown at 127 (the field is a signed
  8-bit `tcimsbf`) on the 128th-from-last packet. Arming rejects a
  non-zero `splice_type` on a non-video stream (§2.4.3.5), over-width
  `splice_type` / `DTS_next_AU`, and unknown stream indices. Splice
  output is pinned §2.4.3.x-conformant via `validate_ts` and
  round-trips through the demuxer unchanged.

- **Keyframe-accurate, wrap-aware seeking.** `Demuxer::seek_to` now
  honours the core contract (nearest keyframe at or before the
  target) end to end: the PCR bisection compares every probed PCR on
  the extended 64-bit timeline (head-anchored zero-wrap modular
  delta), so a mid-stream `2^33` wrap no longer breaks the search
  invariant or the tail clamp; a windowed forward scan from the PCR
  landing then lands on the last access point at or before the
  target, with a doubling backoff for GOPs longer than the window and
  the cached full index as the definitive fallback / clamp-up path.
  Access points are tiered via the new `AccessPointKind`:
  §2.4.3.5 `random_access_indicator` announcements (landing anchored
  on the flagged packet so the emitted `Packet` re-derives its
  keyframe flag) over §2.4.3.7 data-aligned PES starts for
  indicator-less streams — a window-local aligned point never
  shadows an indicator keyframe further back — over the PCR-granular
  landing when neither is signalled. `RandomAccessPoint` gained the
  `kind` field and its `pts_90k` is now the **extended** PTS
  (B-frame-tolerant epoch-nearest unwrap), keeping the index ordered
  across a wrap; `seek_to_random_access` remains the strict
  §2.4.3.5-only surface. New `MpegTsDemuxer::seek_to_access_point`
  exposes the tiered search directly.
- **Post-seek timeline continuity.** `PtsTracker::seed(extended_hint)`
  re-enters a wrap epoch after a reposition: the first observation
  picks the epoch whose extended value lies nearest the hint, so
  packets demuxed after a seek past `2^33` continue the extended
  timeline instead of re-anchoring at small raw values. Every seek
  landing re-seeds the per-PID PTS/DTS trackers with the landed time
  and drops in-flight PES state (continuation bytes are discarded
  until the next PUSI, as after a §2.4.3.4 discontinuity). The
  stateless companion `clock::extend_near(raw, reference)` — extend a
  raw 33-bit timestamp to the wrap epoch nearest a reference — is
  public too; it is what the index scan unwraps B-frame-reordered PES
  times with.
- **Round-trip seek accuracy suite.** Self-muxed fixtures (the muxer
  writes PCR + indicator keyframes at known timestamps) pin the
  landing exactness: a 15-target CBR sweep and a 64 B–24 KiB VBR
  layout land exactly on the keyframe grid (worst delta under one
  GOP), a two-program mux proves the bisection follows the selected
  program's own `PCR_PID`, flag-less streams degrade to a PCR landing
  within one frame + T-STD offset of the target, seeking revives a
  demuxer that already streamed to EOF, and hand-rolled streams cover
  wrap-crossing seeks both directions, sparse-PCR exact landings,
  carrier-packet indicator anchoring, long-GOP backoff, clamp-up, and
  tier preference. Cross-checked black-box against a validator-muxed
  20 s H.264 transport stream: nine targets all landed exactly on the
  validator-reported keyframe grid.

- **Deterministic hostile-input sweeps.** A test-only module drives a
  seeded in-tree LCG through every parse surface — hundreds of
  mutated well-formed streams (built via the crate's own write path),
  pure-noise buffers, sync-aligned noise, truncations, an over-cap
  `section_length` claim, and mutated demuxer open/read/seek runs
  with hard iteration bounds — pinning the robustness contract: no
  panics, no unbounded work or allocation, errors instead of
  misbehaviour. Fixed seeds make any failure reproduce exactly.

- **Write-side PES header builder (§2.4.3.7 Table 2-17).**
  `PesHeaderSpec` encodes a complete PES packet with every optional
  header field the parser reads — scrambling control, priority,
  alignment, copyright, original_or_copy, PTS/DTS, ESCR (composed
  27 MHz tick, exact inverse of the decoder including the maximum
  42-bit value), ES_rate, typed DSM trick mode, additional_copy_info,
  previous_PES_packet_CRC, and the full `PES_extension` body (the
  parsed `PesExtension` doubles as the write spec) — plus both length
  forms: real 16-bit `PES_packet_length` and the unbounded `0` form
  (video stream_ids only, per §2.4.3.7) and the header-less
  stream_ids. Spec-violating requests are rejected with
  `TsError::InvalidField`: DTS without/equal-to PTS (§2.7.5), the
  forbidden zero `ES_rate`, field-width overflows, over-budget
  optional areas, and unbounded length on non-video IDs. The muxer's
  PES construction now goes through the shared builder (audio PES
  gain real lengths; video keeps the BD-style unbounded form).

- **Conformance validation report.** New `validate` module:
  `validate_ts(&[u8]) -> TsValidationReport` walks a stream (any of
  the three physical framings) in two passes — PSI discovery, then
  packet-level checks — and tallies normative-rule violations with
  bounded state: §2.4.3.3 continuity-counter errors (drops +
  over-cap duplicates, per PID and overall), Table 2-5 reserved
  `adaptation_field_control` packets, §2.4.3.5 adaptation-field length
  bounds (183 with AF-only control, ≤182 with AF+payload), §2.4.3.5
  field pairings (OPCR without PCR, `seamless_splice` without
  `splicing_point_flag`, RAI on a PCR PID without PCR fields), §2.7.2
  unsignalled inter-PCR gaps over 0,1 s (`MAX_PCR_INTERVAL_27MHZ`),
  `transport_error_indicator` packets, and PAT/PMT sections failing
  CRC / length checks. Per-PCR-PID reports carry sample counts, the
  max inter-PCR interval, signalled discontinuities, and a §2.4.2.2
  transport-rate estimate; the report also exposes per-PID stats,
  null-packet counts, PAT repetition gaps, and an `is_conformant()`
  verdict. The muxer's own output is pinned conformant in tests;
  hostile-input tests cover CC gaps, oversized PCR gaps (signalled vs
  not), pairing violations, corrupt PSI CRC, garbage, and truncation.

- **192/204-byte physical packet tolerance.** The demuxer now detects
  and strips the two common non-188 framings: 192-byte source packets
  (a 4-byte prefix word ahead of each packet — the `.m2ts` shape) and
  204-byte packets (a 16-byte error-correction trailer appended by
  transmission systems). `TsPacketLayout` names the three framings,
  `detect_packet_layout` classifies a probe buffer by its sync-byte
  grid (≥2 consistent packets required), and
  `MpegTsDemuxer::packet_layout()` reports the detection. The whole
  read layer — streaming reads, garbage resync (double-sync check one
  packet *stride* apart), the PCR duration probe, the PCR-anchored
  binary-search seek, and the random-access index — walks the physical
  grid while every consumer keeps seeing plain 188-byte packets. The
  container probe now scores all three framings.

- **Typed DSM trick-mode decode (§2.4.3.7).** `DsmTrickMode` decodes
  the raw `DSM_trick_mode` byte into the Table 2-20
  `trick_mode_control` variants — fast-forward / fast-reverse (with
  `FieldId` per Table 2-21, `intra_slice_refresh`, and the Table 2-22
  `CoefficientSelection` frequency truncation), slow-motion /
  slow-reverse (5-bit `rep_cntrl`), freeze-frame (`FieldId`), and the
  reserved control values with their raw tail bits. `to_byte()` is the
  write-side inverse (all 256 byte values are stable through a
  decode–encode–decode cycle), and `PesPacket::trick_mode()` lifts the
  already-parsed raw byte.

- **Random-access index + keyframe-accurate seek.**
  `MpegTsDemuxer::random_access_points()` builds (once, in a single
  forward pass with the demux cursor restored) a typed index of every
  §2.4.3.5 `random_access_indicator` packet on the selected program's
  elementary PIDs — byte offset, PID, stream index, and the PTS of the
  announced PES packet, resolved per the "next PES packet to start"
  rule so indicators riding payload-less carrier packets still get the
  following PES start's timestamp. `seek_to_random_access(stream_index,
  target_90k)` then lands the demuxer on the last access point at or
  before the target (optionally restricted to one stream — typically
  the video track), so the next demuxed PES is a keyframe; it is the
  keyframe-accurate companion to the PCR-granular `seek_to`, and
  reports `Unsupported` for indicator-less streams so callers can fall
  back.

- **Keyframe ↔ `random_access_indicator` round trip.** The muxer sets
  the §2.4.3.5 `random_access_indicator` on the first TS packet of a
  keyframe-flagged `Packet`'s PES envelope (on the PCR PID only when
  that packet also carries the PCR fields, per the §2.4.3.5
  constraint). `PesReassembler` folds the indicator into a new
  `PesPacket::random_access` field — honouring the "next PES packet to
  start" rule, so a flag on a payload-less carrier packet ahead of the
  PES start still tags it — and the demuxer surfaces it as the core
  `Packet` keyframe flag. The muxer's hand-rolled adaptation-field
  bytes (PES stuffing + PCR-only packets) now go through the
  `AdaptationFieldSpec` builder, and the PCR wire encoding is the
  shared `encode_clock_reference`.

- **Write-side adaptation-field builder.** `AdaptationFieldSpec` /
  `AdaptationFieldExtensionSpec` encode the complete §2.4.3.4 Table 2-6
  surface — discontinuity / random-access / ES-priority indicators, PCR,
  OPCR, signed `splice_countdown`, `transport_private_data`, and the
  adaptation-field extension (`ltw_valid_flag` + 15-bit `ltw_offset`,
  22-bit `piecewise_rate`, `seamless_splice` with 4-bit `splice_type` +
  33-bit `DTS_next_AU`) — including the `adaptation_field_length == 0`
  single-stuffing-byte form and `0xFF`-stuffed padding to a requested
  size (the §2.4.3.5 PES tail-alignment mechanism). §2.4.3.5-forbidden
  combinations are rejected with the new `TsError::InvalidField`: OPCR
  without PCR, `seamless_splice` without a `splice_countdown`
  (`seamless_splice_flag` requires `splicing_point_flag`), field-width
  overflows, and content or padding beyond the 184-byte AF ceiling
  (`MAX_ADAPTATION_FIELD_LEN`). Every spec round-trips bit-exactly
  through `TsPacket::parse`. The 6-byte PCR/OPCR wire shape is exposed
  as `encode_clock_reference`.

- **End-to-end mux → demux round-trip harness.** A single test builds a
  two-program transport stream carrying SDT + NIT + present/following EIT
  + per-stream `stream_identifier` descriptors and PES with distinct
  PTS/DTS, then demuxes it and asserts every program, service name,
  network name, event, component tag, and timestamp reads back
  identically.
- **Richer PMT ES_info descriptor emission.** Every muxed elementary
  stream now carries an auto `stream_identifier_descriptor` (tag 0x52)
  with a per-program 1-based `component_tag`, alongside the existing
  ISO-639 language descriptor. `ProgramSpec.es_descriptors` lets a caller
  attach arbitrary extra ES_info descriptor bytes per stream (built with
  the `build` module — teletext / subtitling / AC-3 / …), appended after
  the auto ones. Round-trips through the demuxer's
  `PmtStream::iter_descriptors`.
- **DVB NIT + EIT emission on the mux side.** `MpegTsMuxConfig.network`
  (a `NetworkSpec`) makes the muxer emit a Network Information Table on
  PID 0x0010 naming the network and listing this transport stream (with
  a `network_name_descriptor` plus caller-supplied delivery-system /
  service_list descriptors). Each `ProgramSpec.events` (a `Vec<EventSpec>`)
  makes the muxer emit a present/following Event Information Table on PID
  0x0012 keyed on the program's `program_number`, each event carrying a
  `short_event_descriptor`. Both round-trip through the demuxer's
  `NetworkInformationTable::parse` / `EventInformationTable::parse`.
- `build::short_event_descriptor` (tag `0x4D`) and
  `build::service_list_descriptor` (tag `0x41`) round-trip builders.
- **PSI repetition intervals.** The muxer now re-emits the PAT, every
  PMT, and the SDT mid-stream whenever the running PTS advances past a
  configurable interval (default ~200 ms / 18000 ticks of the 90 kHz
  clock), so a receiver tuning in mid-file re-acquires the program tables
  quickly (cf. DVB TR 101 290 §5). `MpegTsMuxer::set_psi_repetition_interval`
  widens or disables it; `None` restores the header/trailer-only
  behaviour.
- **Multi-program muxing.** `MpegTsMuxer::with_config` takes a
  `MpegTsMuxConfig` describing several `ProgramSpec`s — each with its own
  `program_number`, PMT PID, PCR PID, and set of input streams. The PAT
  now lists every program's `(program_number, pmt_pid)` pair, one PMT is
  emitted per program on its own PID, and PCR insertion / the §2.7.2
  inter-PCR interval bound is tracked independently per program. The
  single-program `open` factory is unchanged (one program, PMT PID
  0x0100). Round-trips through the demuxer's `programs()` enumeration and
  per-program `open_program` selection.
- **DVB SDT emission.** A `ProgramSpec` carrying a `ServiceSpec`
  (`service_type` + provider / service names) makes the muxer emit a
  Service Description Table on PID 0x0011 with a `service_descriptor`
  per service, at header and trailer. Reads back through
  `ServiceDescriptionTable::parse`.
- The muxer's PAT / PMT construction now goes through the shared `build`
  module (removing an inlined CRC-32 duplicate).
- New `build` module — the write-side mirror of the `psi` / `descriptor`
  parse surface. Pure `&[…] -> Vec<u8>` builders emit spec-conformant
  bytes that read back identically through the matching parser:
  - **Descriptor TLV builders**: `registration_descriptor` (§2.6.8),
    `iso639_language_descriptor` (§2.6.18),
    `stream_identifier_descriptor` (0x52), `service_descriptor` (0x48),
    `network_name_descriptor` (0x40), `bouquet_name_descriptor` (0x47),
    `teletext_descriptor` (0x56), `subtitling_descriptor` (0x59),
    `ac3_descriptor` (0x6A), `enhanced_ac3_descriptor` (0x7A),
    `dts_descriptor` (0x7B), `aac_descriptor` (0x7C).
  - **Long-form PSI section builders**: `build_pat` (multi-program),
    `build_pmt` (per-stream `ES_info` loops), `build_sdt`, `build_nit`,
    and `build_eit_pf` (present/following), each emitting `table_id`
    through the MPEG-2 CRC-32 trailer.
  - DVB 40-bit MJD + BCD `UTC_time` encoding (the inverse of
    `decode_utc_time`, ETSI EN 300 468 annex-C integer formula) drives
    the EIT `start_time` field.
  - `RunningStatus::to_bits` — the inverse of `from_bits` — so an SDT /
    EIT parse → build round-trip is bit-exact.
- The DVB `data_broadcast_descriptor` (tag `0x64`, ETSI EN 300 468
  §6.2.11 Table 31) — the long form of the data_broadcast_id_descriptor
  — now decodes to a typed `DescriptorBody::DataBroadcast` carrying the
  `data_broadcast_id`, `component_tag`, the length-prefixed selector
  field, and the language-tagged free-text description. Truncated
  length prefixes fall back to `Raw`.
- The DVB `extension_descriptor` (tag `0x7F`, ETSI EN 300 468 §6.2.16
  Table 54) now decodes its `descriptor_tag_extension` envelope (clause
  6.3 Table 109) into a typed `DescriptorBody::Extension`. The selector
  field is exposed both raw and, for `descriptor_tag_extension == 0x06`,
  decoded into a typed `supplementary_audio_descriptor` (§6.4.11
  Table 153 — `mix_type`, `editorial_classification`, and the optional
  overriding `ISO_639_language_code`). Unknown extension sub-tags keep
  their selector bytes verbatim.
- Every public descriptor body type is now re-exported from the crate
  root (previously a subset was reachable only via the `descriptor::`
  module path).
- Six more PMT / EIT DVB descriptors now decode to typed bodies (ETSI
  EN 300 468): `service_move_descriptor` (tag `0x60`, §6.2.36 — the
  post-move `(original_network_id, transport_stream_id, service_id)`
  triple), `short_smoothing_buffer_descriptor` (tag `0x61`, §6.2.38 —
  `sb_size` / `sb_leak_rate` event bit-rate signalling),
  `scrambling_descriptor` (tag `0x65`, §6.2.32 — the `scrambling_mode`),
  `data_broadcast_id_descriptor` (tag `0x66`, §6.2.12 —
  `data_broadcast_id` + selector bytes), `ancillary_data_descriptor`
  (tag `0x6B`, §6.2.2 — the Table-16 ancillary-data bit-flags with
  per-field accessors), and `AAC_descriptor` (tag `0x7C`, annex H —
  `profile_and_level` plus the optional flag byte / `AAC_type` /
  `additional_info`). Malformed bodies still fall back to `Raw`.
- The four DVB NIT delivery-system descriptors now decode to typed
  bodies (ETSI EN 300 468 §6.2.13 / §6.2.17):
  `satellite_delivery_system_descriptor` (tag `0x43`, §6.2.13.2 — the
  DVB-S/S2 carrier: packed-BCD frequency / orbital position / symbol
  rate, polarization, roll-off, modulation system + type, inner FEC),
  `cable_delivery_system_descriptor` (tag `0x44`, §6.2.13.1 — the DVB-C
  carrier: packed-BCD frequency / symbol rate, outer + inner FEC,
  modulation), `terrestrial_delivery_system_descriptor` (tag `0x5A`,
  §6.2.13.4 — the DVB-T carrier: 10-Hz-unit centre frequency, bandwidth,
  priority, time-slicing / MPE-FEC indicators, constellation, hierarchy,
  HP/LP code rates, guard interval, transmission mode, other-frequency
  flag), and `frequency_list_descriptor` (tag `0x62`, §6.2.17 — the
  multiplex's additional centre frequencies with their `coding_type`).
  Frequency / symbol-rate fields are surfaced as their raw packed-BCD
  integers; the spec's §6.2.13 worked examples (cable `0x03120000` →
  312 MHz, satellite `0x01175725` → 11.75725 GHz, symbol rate
  `0x0274500` → 27.4500 Msymbol/s) are pinned as tests.
- Seven more DVB SI descriptors now decode to typed bodies (ETSI
  EN 300 468): `service_list_descriptor` (tag `0x41`, §6.2.35 — the
  NIT/BAT `(service_id, service_type)` channel list),
  `country_availability_descriptor` (tag `0x49`, §6.2.10 — the
  intended/not-intended country list with its polarity flag),
  `linkage_descriptor` (tag `0x4A`, §6.2.19 — the
  `(transport_stream_id, original_network_id, service_id, linkage_type)`
  header plus the type-specific body + private-data run as raw
  `link_data`), `component_descriptor` (tag `0x50`, §6.2.8 — the
  `(stream_content, stream_content_ext, component_type)` editorial
  classification with `component_tag`, language, and free text),
  `CA_identifier_descriptor` (tag `0x53`, §6.2.5 — the associated
  `CA_system_id` list), `parental_rating_descriptor` (tag `0x55`,
  §6.2.28 — per-country `(country_code, rating)` entries with a
  `minimum_age_years()` Table-83 helper), and
  `private_data_specifier_descriptor` (tag `0x5F`, §6.2.31 — the 32-bit
  specifier that scopes following private descriptors). Each surfaces a
  new `DescriptorBody` variant; malformed bodies still fall back to
  `Raw`.
- `MpegTsDemuxer` now supports time-based seeking. `Demuxer::seek_to`
  performs a PCR-anchored binary search over the byte stream
  (ISO/IEC 13818-1 §2.4.2.2) — MPEG-TS carries no in-container index, so
  the demuxer brackets the requested PTS between the open-time head/tail
  PCR anchors and bisects the byte range, scanning forward to the next
  PCR on the `PCR_PID` at each step and steering by its `base_90khz`. It
  lands on the packet boundary of the last PCR at or before the target,
  resets every per-PID PES reassembler and the PTS/DTS/PCR trackers, and
  returns the landed PCR base. Targets outside the bracket clamp to the
  first / last PCR; a stream with fewer than two PCRs returns
  `Error::Unsupported`. PTS and PCR share the 90 kHz time base so no
  per-stream rescale is needed.
- `MpegTsDemuxer` now reports container duration. `Demuxer::duration_micros`
  is computed once at open from the head-to-tail PCR span on the selected
  program's `PCR_PID` (ISO/IEC 13818-1 §2.4.2.2): the first PCR is scanned
  forward from the start of the stream and the last from a growing trailing
  window, and the 27 MHz tick delta (`base × 300 + extension`, wrap-aware
  via the modular delta) converts to microseconds. The same figure is
  mirrored onto every `StreamInfo.duration` in 90 kHz units. Returns
  `None` when the program declares no PCR_PID, the stream carries fewer
  than two PCR samples, or the source is not seekable to its end.
- `partial_transport_stream_descriptor` (tag `0x63`, ETSI EN 300 468
  §7.2.1 / Table 165) decode — the SIT-only descriptor that conveys the
  rate / smoothing parameters for controlling play-out and copying of a
  partial TS. `DescriptorBody::PartialTransportStream` exposes the
  22-bit `peak_rate` (with a `peak_rate_bits_per_second` helper), the
  22-bit `minimum_overall_smoothing_rate`, and the 14-bit
  `maximum_overall_smoothing_buffer`, both with `*_undefined` predicates
  for the §7.2.1 all-ones sentinels (`0x3F_FFFF` / `0x3FFF`). Bodies
  shorter than the 8-byte fixed payload fall back to `Raw`.
- `stuffing_descriptor` (tag `0x42`, ETSI EN 300 468 §6.2.40 / Table 98)
  decode — the descriptor-loop padding / invalidation mechanism that may
  ride in any of the NIT / BAT / SDT / EIT / SIT loops.
  `DescriptorBody::Stuffing` surfaces the raw `stuffing_byte` run (no
  meaning per §6.2.40); a zero-length body is legal.
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
