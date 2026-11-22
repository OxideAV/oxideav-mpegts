# oxideav-mpegts

[![CI](https://github.com/OxideAV/oxideav-mpegts/actions/workflows/ci.yml/badge.svg)](https://github.com/OxideAV/oxideav-mpegts/actions/workflows/ci.yml) [![crates.io](https://img.shields.io/crates/v/oxideav-mpegts.svg)](https://crates.io/crates/oxideav-mpegts) [![docs.rs](https://docs.rs/oxideav-mpegts/badge.svg)](https://docs.rs/oxideav-mpegts) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Rust, clean-room **MPEG-TS** (Transport Stream) demuxer and
muxer, and MPEG-2 program-stream demuxer, per
[ISO/IEC 13818-1](https://www.iso.org/standard/74427.html). The crate
is scoped at the bytes Blu-ray Disc ships inside a `.m2ts` file once the
BDAV `TP_extra_header` has been stripped — i.e. the 188-byte MPEG-TS
packets [`oxideav_bluray::iter_source_packets`] yields.

The motivating downstream is the workspace's `oxideav remux bluray://`
path: a Blu-ray title comes out of `oxideav-bluray` as a decrypted
192-byte-source-packet stream, the BDAV envelope gets stripped, this
crate demuxes each elementary stream's PES payloads, and the MKV
writer in `oxideav-mkv` lays them down as one MKV per unique title with
language-tagged tracks and chapter marks.

## Phase 1 surface

| Module           | What it parses                                                              |
|------------------|-----------------------------------------------------------------------------|
| `packet`         | 188-byte TS packet — sync byte, flags, PID, adaptation field (PCR + OPCR + splice_countdown + transport_private_data + adaptation_field_extension with ltw / piecewise_rate / seamless_splice), payload. The same §2.4.3.4 Table 2-6 surface is writable: `AdaptationFieldSpec` / `AdaptationFieldExtensionSpec` encode every optional field (round-trip tested against the parser), reject the §2.4.3.5-forbidden pairings (OPCR without PCR, seamless_splice without splicing_point) and field-width overflows with `TsError::InvalidField`, and stuff with `0xFF` to a requested size — the PES tail-alignment mechanism. `encode_clock_reference` is the shared 6-byte PCR/OPCR encoder. `TsPacketLayout` / `detect_packet_layout` classify the three physical framings — plain 188, 192-byte (4-byte-prefixed) source packets, 204-byte (16-byte-trailer) packets — by their sync-byte grid; `locate_packet_layout` finds the grid (and the offset of the first whole packet) in a buffer that starts mid-packet. |
| `psi`            | PAT + PMT + CAT (Conditional Access Table, §2.4.4.6) + TSDT (Transport Stream Description Table, §2.4.4.12 — TS-wide descriptor loop on PID 0x0002 / table_id 0x03) + SDT (DVB Service Description Table, ETSI EN 300 468 §5.2.3 — service loop on PID 0x0011 / table_id 0x42 actual + 0x46 other, with typed `RunningStatus`) + EIT (DVB Event Information Table, EN 300 468 §5.2.4 — event loop on PID 0x0012 / table_id 0x4E/0x4F present-following + 0x50–0x6F schedule, with MJD/BCD `start_time` + BCD `duration` decoded per annex C) + NIT (DVB Network Information Table, EN 300 468 §5.2.1 — PID 0x0010 / table_id 0x40 actual + 0x41 other, with the `network_id` plus a network-level descriptor loop and a typed `transport_stream_loop` of `(transport_stream_id, original_network_id)` entries each carrying their own descriptor loop) + BAT (DVB Bouquet Association Table, EN 300 468 §5.2.2 — PID 0x0011 / table_id 0x4A, a `bouquet_id` plus a bouquet-level descriptor loop and a `transport_stream_loop` of `(transport_stream_id, original_network_id)` entries with per-TS descriptor loops, byte-identical to the NIT body shape) + TDT (DVB Time and Date Table, EN 300 468 §5.2.5 — short-form section on PID 0x0014 / table_id 0x70 carrying just the 40-bit MJD/BCD `UTC_time`) + TOT (DVB Time Offset Table, EN 300 468 §5.2.6 — short-form section on PID 0x0014 / table_id 0x73, the `UTC_time` plus a CRC-verified descriptor loop that usually carries the `local_time_offset_descriptor`) + RST (DVB Running Status Table, EN 300 468 §5.2.7 — short-form section on PID 0x0013 / table_id 0x71, a flat run of 9-byte `(transport_stream_id, original_network_id, service_id, event_id, running_status)` entries with no CRC, the fast event-status update channel) + ST (DVB Stuffing Table, EN 300 468 §5.2.8 — short-form section on any SI PID / table_id 0x72 carrying a raw `data_byte` run with no CRC, the section-invalidation channel at a delivery-system boundary) + DIT (DVB Discontinuity Information Table, EN 300 468 §5.2.9 / §7.1.1 — short-form section on PID 0x001E / table_id 0x7E carrying a single `transition_flag` bit, inserted at partial-TS transition points) + SIT (DVB Selection Information Table, EN 300 468 §5.2.10 / §7.1.2 — long-form CRC-verified section on PID 0x001F / table_id 0x7F carrying a TS-wide transmission-info descriptor loop plus a typed `SitService` loop of `(service_id, running_status)` entries with per-service descriptor loops, describing the services/events of a partial TS) section parsers, plus `PsiSectionAssembler` — per-PID reassembler that joins long sections across multiple 188-byte TS packets (§2.4.4 pointer_field + PUSI continuation). Handles sections up to 1024 bytes for the four fixed PSI tables and up to 4096 bytes for private sections (§2.4.4.11, e.g. long DVB EIT sections), a section header split across two packets, stuffing terminators, CC-skip detection, §2.4.3.3 duplicate packets, and back-to-back sections in one payload. |
| `descriptor`     | §2.6 TLV descriptors — registration / ISO-639 language / CA / video / audio / hierarchy / AVC / HEVC / data-stream-alignment / target-background-grid / video-window / system-clock / multiplex-buffer-utilization / copyright / maximum-bitrate / smoothing-buffer / STD / IBP — plus the DVB `service_descriptor` (tag 0x48, EN 300 468 §6.2.33) carrying the service / provider names, the DVB `short_event_descriptor` (tag 0x4D, EN 300 468 §6.2.37) carrying the event name + short text, the DVB `extended_event_descriptor` (tag 0x4E, EN 300 468 §6.2.15) carrying the detailed two-column `(item_description, item)` list plus non-itemized free text with the `descriptor_number` / `last_descriptor_number` association pair, the DVB `network_name_descriptor` (tag 0x40, EN 300 468 §6.2.27) carrying the delivery-system name, the DVB `bouquet_name_descriptor` (tag 0x47, EN 300 468 §6.2.4) carrying the bouquet name, the DVB `content_descriptor` (tag 0x54, EN 300 468 §6.2.9) carrying the per-event genre classification as a flat array of two-nibble (Table 29) + `user_byte` triples, the DVB `local_time_offset_descriptor` (tag 0x58, EN 300 468 §6.2.20) carrying per-country local-time-offset entries (offset minutes + `time_of_change` instant + next offset), the DVB `partial_transport_stream_descriptor` (tag 0x63, EN 300 468 §7.2.1) carried in the SIT transmission-info loop with the partial-TS `peak_rate` / `minimum_overall_smoothing_rate` / `maximum_overall_smoothing_buffer`, the DVB `stuffing_descriptor` (tag 0x42, EN 300 468 §6.2.40) carrying a raw `stuffing_byte` run for descriptor-loop padding / invalidation, and the DVB PMT elementary-stream descriptors a demuxer reads to route a private-data PES — `stream_identifier_descriptor` (tag 0x52, §6.2.39 → component_tag), `teletext_descriptor` (tag 0x56, §6.2.43 → per-language EBU teletext pages), `subtitling_descriptor` (tag 0x59, §6.2.41 → per-language EN 300 743 subtitle services), `AC-3_descriptor` (tag 0x6A, annex D), `enhanced_AC-3_descriptor` (tag 0x7A, annex D), and `DTS_descriptor` (tag 0x7B, annex G) — plus the SI-table DVB descriptors `service_list_descriptor` (tag 0x41, §6.2.35 → NIT/BAT `(service_id, service_type)` channel list), `country_availability_descriptor` (tag 0x49, §6.2.10 → intended/not-intended country list + polarity flag), `linkage_descriptor` (tag 0x4A, §6.2.19 → `(transport_stream_id, original_network_id, service_id, linkage_type)` header + raw type-specific/private `link_data`), `component_descriptor` (tag 0x50, §6.2.8 → editorial `(stream_content, stream_content_ext, component_type)` + `component_tag` + language + text), `CA_identifier_descriptor` (tag 0x53, §6.2.5 → `CA_system_id` list), `parental_rating_descriptor` (tag 0x55, §6.2.28 → per-country `(country_code, rating)` with a Table-83 `minimum_age_years()` helper), and `private_data_specifier_descriptor` (tag 0x5F, §6.2.31 → 32-bit private scope) — and the NIT delivery-system descriptors `satellite_delivery_system_descriptor` (tag 0x43, §6.2.13.2 → DVB-S/S2 BCD frequency/orbital/symbol-rate + polarization/roll-off/modulation/FEC), `cable_delivery_system_descriptor` (tag 0x44, §6.2.13.1 → DVB-C BCD frequency/symbol-rate + outer/inner FEC + modulation), `terrestrial_delivery_system_descriptor` (tag 0x5A, §6.2.13.4 → DVB-T 10-Hz centre frequency + bandwidth/constellation/hierarchy/code-rate/guard/mode/other-frequency), and `frequency_list_descriptor` (tag 0x62, §6.2.17 → a multiplex's additional centre frequencies + `coding_type`) — and the further PMT/EIT DVB descriptors `service_move_descriptor` (tag 0x60, §6.2.36 → post-move `(onid, tsid, sid)`), `short_smoothing_buffer_descriptor` (tag 0x61, §6.2.38 → `sb_size`/`sb_leak_rate`), `scrambling_descriptor` (tag 0x65, §6.2.32 → `scrambling_mode`), `data_broadcast_id_descriptor` (tag 0x66, §6.2.12 → `data_broadcast_id` + selector bytes), `ancillary_data_descriptor` (tag 0x6B, §6.2.2 → Table-16 audio ancillary-data bit-flags), and `AAC_descriptor` (tag 0x7C, annex H → `profile_and_level` + optional `AAC_type`/`additional_info`) — and the `extension_descriptor` (tag 0x7F, §6.2.16 → a `descriptor_tag_extension` envelope, clause 6.3, decoding `supplementary_audio` (ext 0x06, §6.4.11 → `mix_type`/`editorial_classification`/optional language override) and surfacing other extension sub-tags' selector bytes raw) — and the `data_broadcast_descriptor` (tag 0x64, §6.2.11 → `data_broadcast_id` + `component_tag` + length-prefixed selector + language-tagged text) — and the 13818-1 ISO/IEC 14496 carriage set (§2.6.28–§2.6.53): `private_data_indicator` (0x0F), `MPEG-4_video` (0x1B) / `MPEG-4_audio` (0x1C, with a Table 2-62 profile/level classifier), `IOD` (0x1D — scope/label typed, the 14496-1 InitialObjectDescriptor raw), `SL` (0x1E), `FMC` (0x1F, per-channel `(ES_ID, FlexMuxChannel)` entries), `External_ES_ID` (0x20), `Muxcode` (0x21) / `FmxBufferSize` (0x22, 14496-1-internal bodies surfaced raw but recognised), and `MultiplexBuffer` (0x23 — MBn size + TBn→MBn leak rate with a bit/s helper); every program/program-element descriptor tag the staged 13818-1 edition defines (Table 2-39) now decodes typed. |
| `pes`            | PES packet reassembler — joins TS payloads per-PID into complete PES units. Decodes every Table 2-17 optional header field: PES_scrambling_control / PES_priority / data_alignment_indicator / copyright / original_or_copy on flags1, plus the flag-gated bodies ESCR (42-bit 27 MHz tick), ES_rate (50 bytes/s units), DSM_trick_mode (raw 8-bit **and** typed — `DsmTrickMode` decodes the Table 2-20 trick_mode_control into fast-forward / slow-motion / freeze-frame / fast-reverse / slow-reverse with `FieldId` (Table 2-21), intra_slice_refresh, `CoefficientSelection` frequency truncation (Table 2-22) and rep_cntrl; `to_byte()` is the wire inverse), additional_copy_info, previous_PES_packet_CRC, and the full PES_extension body (16-byte private data, raw pack_header bytes, program_packet_sequence_counter, P-STD buffer scale/size, PES_extension_field_2). The reassembler folds the TS-level `random_access_indicator` into `PesPacket::random_access` per the §2.4.3.5 next-PES-to-start rule (indicators riding payload-less carrier packets included). `PesHeaderSpec` is the write-side mirror — it encodes a complete PES packet with every Table 2-17 optional field (both length forms plus the header-less stream_ids) and rejects spec violations (DTS without/equal-to PTS per §2.7.5, zero ES_rate, width overflows, over-budget optional areas) with `TsError::InvalidField`; the muxer builds its PES envelopes through it. |
| `audio_frame`    | Audio access-unit framing: AC-3 / E-AC-3 (A/52 §5 + Annex E), MPEG-1/2 audio Layers I–III (11172-3 / 13818-3) and AAC ADTS (13818-7) header parsers (frame length, samples per frame, sample rate, channels, bit rate) and `AudioFrameSplitter`, which the demuxer uses to emit one packet per syncframe with interpolated PTS when a PES carries several frames. |
| `stream_type`    | `stream_type` byte → codec class enum covering the full ISO/IEC 13818-1 Table 2-29 base range (`0x01..=0x26`: MPEG-1/2/4 video + audio, AAC-ADTS/LATM, private sections / PES, MHEG, DSM-CC, metadata carriers, IPMP, AVC / SVC / MVC / MVCD, JPEG 2000, stereoscopic views, HEVC + temporal subset) plus AVS video and the HDMV-extended Blu-ray range. Classifies video / audio / subtitle / metadata / private. |
| `atsc`           | ATSC PSIP (A/65:2013) — the North-American SI family. Section parsers for every base-PID (0x1FFB) table: STT (§6.1 — GPS `system_time` + `GPS_UTC_offset` + annex-A daylight-saving control, with a `gps_to_unix` helper), MGT (§6.2 — the version/PID/size directory of every other PSIP table, with typed `table_type` classifiers for EIT-k / event-ETT-k / per-region RRT entries), TVCT + CVCT (§6.3 — virtual channels with UTF-16 `short_name`, major/minor (and CVCT one-part) channel numbers, modulation, `channel_TSID`, `program_number`, ETM location, access/hidden/hide_guide flags, cable `path_select`/`out_of_band`, `service_type`, `source_id`, per-channel descriptor loops), and RRT (§6.4 — region name + rating dimensions/values); plus the MGT-announced guide tables: ATSC EIT (§6.5 — per-`source_id` events with GPS start times, 20-bit durations, MSS titles) and ETT (§6.6 — `ETM_id`-keyed long descriptions with channel/event classification); plus the optional directed-channel-change pair: DCCT (§6.7 — per-test Temporary-Retune/Channel-Redirect context, 10-bit from/to major·minor channel numbers, GPS start/end window, ANDed Table 6.17 selection terms with typed classification, postal-code text + Table 6.19 genre-code unpacking + Table 6.18 demographic bit constants, descriptor loops at term/test/table level) and DCCSCT (§6.8 — Table 6.24 genre/state/county code-set updates with MSS names, reserved update types skipped via `update_data_length`), with MGT classifiers for DCCT-instance (`0x1400+dcc_id`) and DCCSCT rows. All PSIP text decodes through the §6.10 Multiple String Structure (Table 6.41 Unicode range-select modes + UTF-16 mode 0x3F + the annex-C standard Huffman compressions — the Table C4/C6 order-1 code tables are transcribed as data, every multi-entry context pinned as a complete prefix-free tree via the Kraft equality, decode honouring the §C.2.1 escape and ≥128-raw-follow rules). A dedicated PSIP descriptor walker (`iter_atsc_descriptors` — the 0x80–0xAB tags live in the MPEG user-private space, so they are kept apart from the MPEG/DVB `descriptor` module) types the §6.9 core set: caption_service (608/708), content_advisory (per-region RRT dimension/value pairs), extended_channel_name, service_location (PCR PID + per-stream type/PID/language), time_shifted_service, component_name, DCC departing/arriving requests, redistribution_control, genre, and ATSC_private_information (0xAD, A/53 Part 3 §5.8.2 — SMPTE-RA format_identifier + opaque bytes); the AC-3 (0x81, A/52 annex A) and E-AC-3 (0xCC, A/52 annex G) audio_stream_descriptors surface raw with recognised tags. Every parse enforces the §4.1 generic section shape — CRC-32 verified, `protocol_version` 0 only. |
| `clock`          | Per-PCR-PID 27 MHz clock recovery + per-PID continuity-counter classification (§2.4.2.2 / §2.4.3.3 / §2.4.3.5), plus `PtsTracker` — per-PID 33-bit PTS/DTS unwrapping (§2.4.3.7) into a monotonic 64-bit extended timeline with wrap-vs-discontinuity classification and `seed()` wrap-epoch re-entry, so a demuxer landing a seek at a known extended time re-joins the same timeline instead of re-anchoring at raw 33-bit values. |
| `muxer`          | Multi-program writer (`MpegTsMuxer`). The single-program `open` factory groups every stream into `program_number` 1 (PMT PID 0x0100); `MpegTsMuxer::with_config` takes a `MpegTsMuxConfig` of several `ProgramSpec`s for a genuine multi-program TS — the PAT lists every program's `(program_number, pmt_pid)` pair, one PMT is emitted per program on its own PID, and PCR insertion / the §2.7.2 inter-PCR bound are tracked independently per program. Each `Packet` is wrapped in a PES envelope (PTS / DTS per Table 2-22) and fragmented into 188-byte TS packets with per-PID continuity counters + a tail-stuffing pass; oversize PSI splits across packets (§2.4.4 PUSI + pointer_field + continuation). PMT ES_info loops carry an auto `stream_identifier_descriptor` (tag 0x52) with a per-program `component_tag`, an `ISO_639_language_descriptor` (tag 0x0A) for language-tagged audio / subtitle tracks, plus any caller-injected DVB component descriptors (teletext / subtitling / AC-3 / …). DVB SI is emitted on the mux side: SDT (PID 0x0011, `service_descriptor` per program), NIT (PID 0x0010, `network_name` + delivery-system / service_list descriptors), and present/following EIT (PID 0x0012, `short_event_descriptor` per event with DVB MJD+BCD start times). A configured CA descriptor loop emits a CAT (§2.4.4.6, PID 0x0001 — a §2.4.2.3 system PID, so CBR paces it through the pooled TBsys/Bsys); a `TimeSpec` wall-clock anchor emits a TDT (+ TOT with `local_time_offset_descriptor` entries) on PID 0x0014 whose `UTC_time` advances with the elapsed stream time (annex-C MJD arithmetic) at every re-emission. All program / SI tables re-emit mid-stream at a configurable PTS interval (`set_psi_repetition_interval`, default ~200 ms) and once at the trailer. The whole section / descriptor write path lives in the `build` module and round-trips byte-identically through the matching parsers. A keyframe-flagged `Packet` gets the §2.4.3.5 `random_access_indicator` on the first TS packet of its PES envelope (on the PCR PID only when that packet also carries the PCR, per the §2.4.3.5 constraint), so receivers can locate random-access points without parsing the elementary stream. `signal_splice_after` arms a §2.4.3.5 / Annex-K splicing point after the next written frame — its PES envelope's payload packets carry `splicing_point_flag` + `splice_countdown` counting down to zero on the last one (whose final payload byte ends the coded frame by construction), optionally with the seamless `splice_type` / `DTS_next_AU` adaptation-field extension held identical across the run and a negative post-splice countdown on the following packets; audio streams reject a non-zero `splice_type`. A frame whose payload exceeds the 16-bit `PES_packet_length` budget on a bounded (non-video) stream_id splits across several PES envelopes (§2.4.3.7 — timestamps on the first, none on continuations; video keeps the unbounded form). `signal_time_base_discontinuity` arms a §2.4.3.5 / §2.7.6 system time-base change — the next PCR on the program's PCR_PID rides `discontinuity_indicator = 1` and the PCR cadence restarts on the new base. `set_mux_rate` enables CBR pacing on the §2.4.2 T-STD delivery schedule: the byte position defines the arrival clock, every PCR is stamped from it (the receiver-reconstructed transport rate equals the configured rate exactly), null packets bound each frame's delivery lead (0.25 s video; non-video frames are held per track and released 40 ms before decode so the 3584-byte §2.4.2.3 audio buffer never hoards), PCR-only packets keep the §2.7.2 bound across null runs, audio / PSI packets are spaced so no 512-byte transport buffer overflows at the spec drain rates, `set_video_max_bitrate` declares a video stream's §2.4.2.3 `Rmax` so its PID is TB-paced at `Rxn = 1.2 × Rmax` too (a mux rate above that drain would otherwise overflow the video TBn on back-to-back packets; PCR-only packets on a paced PCR PID are booked against the same account), and a frame the clock can no longer deliver in time is an error. CodecId ↔ stream_type mapping mirrors the demuxer so a round-trip preserves the codec set. |
| `build`          | Write-side builders mirroring the `psi` / `descriptor` parse surface: descriptor TLV builders (registration / ISO-639 / stream_identifier / service / network_name / bouquet_name / short_event / service_list / teletext / subtitling / AC-3 / E-AC-3 / DTS / AAC) and long-form PSI section builders (`build_pat` multi-program, `build_pmt`, `build_sdt`, `build_nit`, `build_eit_pf`), each emitting `table_id` through the MPEG-2 CRC-32 trailer. DVB 40-bit MJD+BCD `UTC_time` encoding is the inverse of `decode_utc_time` (EN 300 468 annex-C integer formula). Every builder is round-trip tested against its parser. |
| `demuxer`        | Streaming `Demuxer` (`MpegTsDemuxer`) — scans for the PAT, enumerates every advertised program as a typed `TsProgram` (`programs()`), opens the first by default or any other via `open_program(program_number)` (§2.4.4.5), reassembles the chosen program's PMT (multi-TS-packet aware), and maps each elementary stream to a `CodecParameters` / `StreamInfo`. Timing is reconstructed on the demux path: the selected program's `PCR_PID` (§2.4.4.9) drives a `PcrTracker` for 27 MHz clock recovery (`last_pcr()`), and each PES's 33-bit PTS/DTS is unwrapped per PID (§2.4.3.7, `NearestEpochUnwrap`: every value extends to the wrap epoch nearest the previous one) onto one 64-bit extended timeline, so neither a `2^33` wrap nor B-picture reordering after one produces a 26.5-hour jump; the first timestamp anchors `StreamInfo.start_time`. `duration_micros()` is probed once at open from the head-to-tail PCR span (§2.4.2.2 — first PCR scanned forward from the start, last PCR from a growing trailing window, `base × 300 + extension` 27 MHz delta → microseconds, also mirrored to each `StreamInfo.duration` in 90 kHz units). `seek_to()` is keyframe-accurate per the core `Demuxer` contract (nearest keyframe at or before the target): a PCR-anchored binary search brackets the requested time between those same head/tail PCR anchors and bisects the byte stream — comparing every probed PCR on the **extended** 64-bit timeline (head-anchored zero-wrap modular delta, exact below one ~26.5 h wrap) so a mid-stream `2^33` wrap can't break the search invariant or the tail clamp — then a windowed forward scan from the PCR landing collects access points on the stream's PID and lands on the last one at or before the target, backing off in doubling steps (1 s, 2 s, 4 s, …) when a long GOP outruns the window and falling back to the cached full index as the definitive answer (also the clamp-up path for targets before the first point). Access points are tiered (`AccessPointKind`): §2.4.3.5 `random_access_indicator` announcements win — the landing anchors on the flagged packet (payload-less carrier packets included) so the reassembler re-derives the core keyframe flag — and data-aligned PES starts (§2.4.3.7, alignment per the §2.6.10 descriptor or Tables 2-47/2-48 type '01') serve streams that never set the indicator, with a window-local aligned point never shadowing an indicator keyframe further back; streams signalling neither degrade to the PCR-granular landing (at or before the target; fewer than two PCRs *and* no access points is `Unsupported`). Every landing drops in-flight PES state (continuity history is void after a byte jump, as after a §2.4.3.4 discontinuity — continuation bytes are discarded until the next PUSI) and re-seeds the per-PID PTS/DTS unwrappers at the landed time (wrap-epoch re-entry) so post-seek packets continue the same extended timeline the caller seeked along. `random_access_points()` builds (once, cursor-restoring single pass) the typed tiered index — byte offset, PID, stream index, kind, and the announced PES's extended PTS, unwrapped B-frame-tolerantly (epoch-nearest) — and `seek_to_random_access(stream_index, target)` remains the strict §2.4.3.5-only surface. Round-trip accuracy is pinned by self-muxed fixtures (the muxer writes PCR + indicator keyframes at known timestamps): a CBR sweep and a 64 B–24 KiB VBR layout land exactly on the keyframe grid, multi-program muxes bisect along the selected program's own `PCR_PID`, and wrap-crossing streams seek forward and back across `2^33`. All three physical framings are tolerated transparently — 188-byte plain, 192-byte (4-byte-prefixed) source packets, and 204-byte (16-byte-trailer) packets — detected at open (`packet_layout()`) and stripped at the read layer, with the resync double-sync check, PCR probes, seek bisection, and the RAP index all walking the physical grid. A capture that starts mid-packet or behind leading bytes opens all the same (`leading_bytes()`), and the streaming path keeps going on damaged input — see *Damaged input* below. |
| `ps`             | MPEG-2 program-stream demuxer (`MpegPsDemuxer`, container `"mpegps"`, ISO/IEC 13818-1 §2.5): pack / system headers, PES, program stream map, DVD private_stream_1 sub-streams (AC-3 / DTS / LPCM / sub-picture). Emits one packet per access unit — audio syncframes, MPEG-1/2 pictures, H.264 access units — with keyframe flags and §2.7.5 PTS placement; stream params from the PSM or the first payload headers. `seek_to` lands on the last key frame at or before the target: a bisection over the pack headers' SCR, then a forward read. Pictures whose PES packet codes no time stamp get a decoding time one frame period after the previous one and, for MPEG-1/2 video, a presentation time from `temporal_reference`. ISO/IEC 11172-1 (MPEG-1 Systems) input is refused: not staged. |
| `validate`       | Conformance validation: `validate_ts` walks a whole stream (any framing) in two passes and tallies normative-rule violations with bounded state — §2.4.3.3 continuity-counter errors (per PID + overall), Table 2-5 reserved adaptation_field_control, §2.4.3.5 AF length bounds and field pairings (OPCR without PCR, seamless_splice without splicing_point, RAI-without-PCR on a PCR PID), §2.4.3.5 splice-signalling coherence (a `splice_countdown` contradicting the payload-packet count since the previous annotation, a seamless-splice run dropping or changing its `splice_type` / `DTS_next_AU` before the countdown-zero packet, and a non-zero `splice_type` on a PMT-typed audio PID), §2.7.2 unsignalled inter-PCR gaps over 0,1 s, transport_error packets, and CRC/length-failing PAT/PMT sections. Per-PCR-PID reports carry sample counts, max interval, signalled discontinuities, and a §2.4.2.2 transport-rate estimate; plus per-PID stats, null-packet counts, PAT repetition gaps, and an `is_conformant()` verdict. The muxer's own output is pinned conformant in tests. |
| `tstd`           | The §2.4.2 Transport Stream system target decoder as an executable model: `analyze_tstd` reconstructs the §2.4.2.2 arrival clock from the PCRs (equations 2-1..2-5 — piecewise-constant transport rate between PCR pairs, wrap-aware, previous-rate carry across a signalled time-base discontinuity with decode times re-anchored on the new base) and replays every configured PID through its §2.4.2.3 chain as a fluid model: whole TS packets into the fixed 512-byte `TBn` draining FIFO at `Rxn`; PES bytes on into the audio main buffer `Bn` (PES headers held until the access-unit removal) or through the video `MBn → EBn` leak (`Rbxn`, headers discarded at transfer, `EBn` back-pressure), with whole access units removed at their decode time (DTS else PTS; PES-granular, continuation PES extend the open unit) and PSI PIDs on the `TBsys → Bsys` chain (equation 2-7 `Rsys`). Every §2.4.2.6 condition is checked — TB / `Bn` / `MBn` overflow, `Bn` / `EBn` underflow, empty-once-a-second, the one-second delay bound, `Bsys` overflow — deduplicated per rule + PID with worst figures and total counts, plus per-chain peak-occupancy stats. `TStdStreamModel::audio()` carries the spec-fixed non-ADTS numbers; the video constructors apply the §2.4.2.3 `Rxn` / `Rbxn` / `MBSn` formulas over caller-supplied `Rmax` / VBV figures. The CBR muxer's own output is pinned zero-violation against this model. |

No decoders. Every payload byte on the demux path stays as a borrowed
slice unless reassembly forces a copy; the muxer is the only path that
re-multiplexes.

`ProgramMapTable::iter_program_descriptors` and
`PmtStream::iter_descriptors` lift the raw descriptor bytes carried
inside a PMT into typed [`Descriptor`] records (TLV envelope + a
decoded body for the most common tags). Unrecognised tags surface as
`DescriptorBody::Raw` so downstream callers still see the payload
bytes verbatim. `ConditionalAccessTable::iter_descriptors` exposes
the same view over a CAT's CA_descriptor block.

`ServiceDescriptionTable::parse` reads a DVB SDT section into typed
`SdtService` entries — `service_id` (equal to the PMT
`program_number` for normal services), the two EIT-presence flags, a
typed `RunningStatus` (EN 300 468 Table 6), `free_CA_mode`, and a
per-service descriptor loop. `SdtService::iter_descriptors` lifts that
loop, and the `service_descriptor` (tag 0x48) it usually carries
decodes to `DescriptorBody::Service` exposing the `service_type` byte
plus the raw service / provider name runs. That name is what the
`oxideav remux bluray://` path needs to label an MKV title when the
source TS carries an SDT. DVB text strings keep their original bytes —
the EN 300 468 annex-A character-table selection is deliberately left
to the caller rather than decoded here.

`EventInformationTable::parse` reads a DVB EIT section (EN 300 468
§5.2.4) into typed `EitEvent` entries. The EIT lives on the fixed PID
`0x0012` and comes in four `table_id` classifications — present/
following on the actual TS (`0x4E`) or another TS (`0x4F`), and the
event schedule on the actual TS (`0x50`–`0x5F`) or another TS
(`0x60`–`0x6F`); `parse` accepts all four and records
`other_transport_stream` / `schedule`. Each `EitEvent` carries its
`event_id`, a decoded `start_time` (`EitDateTime` — the 40-bit field's
16-bit Modified Julian Date is converted to a Gregorian
`(year, month, day)` via the annex-C integer formula, and the 24-bit
BCD UTC time is decoded alongside; the all-ones "undefined" sentinel
surfaces as `None`), a `duration` (`EitDuration` — BCD hours/minutes/
seconds with `as_seconds`), a typed `RunningStatus`, `free_CA_mode`,
and a per-event descriptor loop. `EitEvent::iter_descriptors` lifts
that loop, where the `short_event_descriptor` (tag `0x4D`) decodes to
`DescriptorBody::ShortEvent` exposing the language code plus the raw
event-name and short-text runs, and the `extended_event_descriptor`
(tag `0x4E`, §6.2.15) decodes to `DescriptorBody::ExtendedEvent` — the
long-form synopsis the short_event_descriptor's single-descriptor cap
can't hold. It carries a `descriptor_number` / `last_descriptor_number`
pair (an event greater than 256 bytes spreads across an associated set
the caller concatenates in number order), a `Vec` of two-column
`(item_description, item)` pairs (the spec's cast-list shape, e.g.
`b"Producer"` → a name), and the non-itemized free text. Since
`service_id` equals the PMT
`program_number` for normal services, the EIT lets the
`oxideav remux bluray://` path attach human-readable event names and
time ranges to each title. The spec's worked examples
(`0xC0 7912 4500` → 1993-10-13 12:45:00 and `0x01 4530` → 01:45:30)
are pinned as tests. The same event loop's `content_descriptor` (tag
`0x54`, EN 300 468 §6.2.9) decodes to `DescriptorBody::Content` — a
flat array of `ContentNibble` records, each pairing the two 4-bit
content nibbles (the genre, indexed against Table 29: `(0x1, 0x4)` =
comedy, `(0x4, 0x3)` = football/soccer, …) with the
broadcaster-defined `user_byte`. The Table 29 genre strings are
reference data left to the caller; the crate surfaces the raw nibbles
so a player maps them against whatever classification its UI uses.

`NetworkInformationTable::parse` reads a DVB NIT section (EN 300 468
§5.2.1) carried on the fixed PID `0x0010`. The NIT comes in two
`table_id` classifications — the actual network the TS belongs to
(`0x40`) and other networks (`0x41`); `parse` accepts both and records
`other_network`. The section carries a two-level descriptor layout that
mirrors the PMT: a network-level descriptor loop (lifted by
`NetworkInformationTable::iter_descriptors`, where the
`network_name_descriptor` of tag `0x40` decodes to
`DescriptorBody::NetworkName` exposing the raw delivery-system name)
followed by a `transport_stream_loop` of `NitTransportStream` entries.
Each entry pairs `(transport_stream_id, original_network_id)` — the
combination the spec notes uniquely identifies a TS throughout the
application area — with its own descriptor loop, walkable via
`NitTransportStream::iter_descriptors`. The NIT gives the
`oxideav remux bluray://` path the network-level context that frames
the per-service SDT and per-event EIT records. DVB text strings keep
their original bytes — the annex-A character-table selection is left to
the caller, as with the SDT and EIT name descriptors.

`BouquetAssociationTable::parse` reads a DVB BAT section (EN 300 468
§5.2.2). A *bouquet* groups services into a marketable package that may
cross network boundaries, independent of the physical multiplex layout
the NIT describes. The BAT shares the SDT's fixed PID `0x0011` and every
section takes `table_id 0x4A`; the `bouquet_id` rides in the
`table_id_extension` slot. On the wire the section body is byte-for-byte
the NIT shape — a bouquet-level descriptor loop (lifted by
`BouquetAssociationTable::iter_descriptors`, usually carrying the
`bouquet_name_descriptor` of tag `0x47` which decodes to
`DescriptorBody::BouquetName`) followed by a `transport_stream_loop` of
`BatTransportStream` entries, each pairing `(transport_stream_id,
original_network_id)` with its own descriptor loop walkable via
`BatTransportStream::iter_descriptors`. The BAT gives the
`oxideav remux bluray://` path the bouquet-level grouping that frames
the per-service SDT records, and like the SDT/NIT name descriptors the
bouquet-name bytes keep their original annex-A encoding for the caller.

`RunningStatusTable::parse` reads a DVB RST section (EN 300 468 §5.2.7)
from PID `0x0013` / `table_id 0x71`. The RST is the fast event-status
update channel: a dedicated table refreshes the running status of one or
more events quicker than waiting for a full EIT cycle, which matters when
an event starts early or late due to a scheduling change. It is a
**short-form** section (`section_syntax_indicator == 0`, no version /
section header and no CRC), so the whole body is a flat run of fixed
9-byte `RstEntry` records, each locating an event by the
`(transport_stream_id, original_network_id, service_id, event_id)` tuple
and carrying its updated typed `RunningStatus`. A body that is not a
whole number of entries, a `section_length` overrun, or a wrong
`table_id` are rejected.

`TimeDateTable::parse` and `TimeOffsetTable::parse` read the two DVB
time tables that share the fixed PID `0x0014` (EN 300 468 §5.2.5 /
§5.2.6). Both are **short-form** sections — `section_syntax_indicator`
is `0`, so there is no `table_id_extension` / `version_number` /
`section_number` header and the body starts immediately after the
12-bit `section_length`. The TDT (`table_id 0x70`) carries nothing but
the 40-bit `UTC_time` and has no CRC; the TOT (`table_id 0x73`) adds a
CRC-32 (verified the same way as a long-form section) plus a descriptor
loop. Both reuse the same `decode_utc_time` helper that decodes the
EIT `start_time` — 16 bits of MJD converted to a Gregorian
`(year, month, day)` via the annex-C integer formula, then 24 bits of
6-digit BCD UTC time. `TimeOffsetTable::iter_descriptors` walks the
loop, where the `local_time_offset_descriptor` (tag `0x58`) decodes to
`DescriptorBody::LocalTimeOffset` — a flat array of per-country entries
giving the `country_code`, `country_region_id`, signed
`local_time_offset` / `next_time_offset` (in minutes), and the
`time_of_change` instant. The TDT/TOT give the
`oxideav remux bluray://` path an absolute wall-clock anchor for a
title, and the TOT's offset lets a player turn that UTC into local
time across a daylight-saving boundary. The spec's worked example
(`0xC0 7912 4500` → 1993-10-13 12:45:00 UTC) is pinned as a test for
both tables.

`PsiSectionAssembler` is the building block that turns a stream of
TS-packet payloads on a single PSI PID into a stream of complete
sections. The §2.4.4 wire rules are enforced in one place: a PUSI=1
TS payload begins with a `pointer_field` that completes whatever
section was in flight; a PUSI=0 payload contributes continuation
bytes; `0xFF` table_id terminates iteration inside a single payload;
and a `continuity_counter` skip discards the in-flight buffer rather
than concatenating misordered bytes. The demuxer's PAT and PMT
discovery loops both drive an assembler so a PMT with rich descriptor
blocks (multi-language PGS + multi-codec audio + HEVC + … ) can grow
past the ~184-byte single-TS payload budget without losing the
trailing streams.

`PcrTracker` consumes one adaptation field per packet on the
configured `PCR_PID` and emits `PcrEvent::Sample { pcr, jitter_27mhz,
bitrate_bps }` for normal flow or
`PcrEvent::Discontinuity { reason }` when either (a) the adaptation
field carries `discontinuity_indicator = 1` (§2.4.3.5) or (b) the
observed PCR jump exceeds the configured tolerance window. Jitter is
the signed residual in 27 MHz ticks between the observed PCR delta
and the delta predicted by the previous pair's bitrate. Default
window is 100 ms — well above the ±500 ns spec tolerance but tight
enough to catch a clean time-base reset that didn't bother to set the
indicator.

`ContinuityTracker` is a sibling observer for the 4-bit
`continuity_counter` per §2.4.3.3 — emits `Continuous` / `Duplicate`
/ `NoPayload` / `Dropped { gap }` / `Discontinuity`. Duplicate-cap
enforcement (max one repeat per CC) is built in: a second identical
CC reads as a drop, not a second duplicate.

## Checked against a black-box multiplexer and reader

`tests/blackbox_matrix.rs` (runs when `ffmpeg` / `ffprobe` are on the
`PATH`, skips otherwise) writes 65 files with a black-box multiplexer
and compares, stream by stream and packet by packet — payload hash,
size, PTS, DTS, key-frame flag, codec, picture size, sample rate,
channels, language — what this crate's demuxers deliver with what a
black-box reader reports. Each file is then remultiplexed with this
crate's writer, unpaced and at a constant rate, and the reader must
report the same packets for the result with no new warning.

| Direction | Result |
|-----------|--------|
| foreign → this crate (61 generated files that are in scope, three cut / re-framed variants) | 64 / 64 |
| this crate → foreign reader (remux, unpaced + constant rate) | 120 / 120 |
| in the matrix and **not** carried (pinned as failing) | 4 |

The sweep: every video / audio codec the multiplexer writes into a
transport stream; 188 / 192 / 204-byte packets; PCR periods; PAT / PMT
/ SDT periods; header resending, System B, initial discontinuity, NIT;
no `random_access_indicator`; constant rate with null stuffing; one
frame, many frames or 300 bytes per PES packet; time stamps starting
0,3 s below the 2^33 wrap and at one hour; custom PIDs; two audio
languages; two programs; audio-only and video-only; a file cut
mid-packet and one cut mid-stream; and program streams in the `vob`,
`dvd` and `svcd` layouts. Lost, error-flagged and sync-damaged packets
injected into a foreign stream cost the PES packets they hit and
nothing else, and seeking — in a transport stream and in a program
stream — lands on the key frames the reader marks.

Per codec, for streams this crate did not write:

| Codec | Transport stream: demuxed as | Remuxed by this crate | Program stream |
|-------|------------------------------|-----------------------|----------------|
| MPEG-1 / MPEG-2 video | `mpeg1video` / `mpeg2video` (told apart by the sequence extension), size + frame rate | yes | yes; time stamps filled for pictures whose PES packet has none |
| MPEG-4 Visual | `mpeg4video`, no picture size | yes | yes (told from MPEG-2 by its start codes); PTS only where coded |
| H.264 | `h264`, size + frame rate | yes | yes; PTS only where coded |
| H.265 | `h265`, no picture size | yes | by program stream map only, unsplit |
| H.266, EVC, JPEG XS, JPEG 2000, VC-1 | by `stream_type`; **never checked against an outside stream** | by `stream_type` | — |
| MPEG audio layers I–III | `mp1` / `mp2` / `mp3`, one frame per packet, rate + channels | yes | yes |
| AAC ADTS | `aac`, one frame per packet | yes | by program stream map |
| AAC LATM | `aac_latm`, one `AudioSyncStream()` frame per packet | yes | — |
| AC-3 / E-AC-3 | `ac3` / `eac3` (ATSC, DVB and Blu-ray signalling) | yes | AC-3 yes |
| DTS | `dts` (DVB descriptor / registration, Blu-ray type), one access unit per packet; **extension substreams never checked against an outside stream** | yes | yes |
| LPCM | Blu-ray `stream_type` 0x80 as `pcm_s16be` *with its 4-byte header in every packet* and no parameters (header layout not staged) | yes (bytes unchanged) | DVD LPCM 16-bit: samples only; cannot be remuxed into a transport stream |
| DVB subtitles, teletext | `dvb_subtitle` / `dvb_teletext`, one PES packet per packet; **demux never checked against an outside stream** (the reader accepts what this crate writes) | yes | — |
| TrueHD, PGS, TextST | by Blu-ray `stream_type`; not in the matrix | by `stream_type` | — |
| Opus, SMPTE 302M, AV1, SCTE-35, KLV, timed ID3 | **not carried** — their transport-stream carriage is not staged | no | — |
| MPEG-1 system streams (`.mpg` written as ISO/IEC 11172-1) | — | — | **refused** — 11172-1 is not staged |

Notes on what the comparison found to be a matter of convention rather
than an error: a stream starting below the 2^33 wrap is reported from
its raw time stamps upwards (the reader starts it below zero); inside a
PES packet with several audio frames the per-frame times are exact
multiples of the frame duration from the PES time stamp; the reader
keeps three header bytes with DVD LPCM packets.

A remultiplexer passes each stream's source descriptors on
(`MpegTsDemuxer::pmt_entry` → `ProgramSpec::with_es_descriptors`), so
streams identified only by a descriptor stay identified. The paced
writer takes frames in decoding order across streams.

## Damaged input

The streaming path of `MpegTsDemuxer` skips damage and keeps going;
`stats()` (`TsDemuxStats`) counts what happened.

| Defect | Behaviour |
|--------|-----------|
| Stream starts mid-packet / behind leading bytes | The 188 / 192 / 204-byte grid is located in the first 64 KiB (five consecutive packets); every reported offset stays a true source offset. |
| Inserted or deleted bytes, garbage runs | Byte-granular search for the next three aligned sync bytes (`resync_bytes`). At most 256 packets' worth is examined per read; a longer run is reported as an error once, and the next read carries on. |
| Tail cut mid-packet, trailing non-packet bytes | Clean end of stream; every complete PES packet is delivered first. |
| Packet that does not parse (e.g. adaptation field longer than the packet), `transport_error_indicator` | Packet dropped (`malformed_packets`, `transport_errors`). |
| Duplicate packet (§2.4.3.3) | Consumed once (`duplicate_packets`). |
| Lost packets (continuity-counter gap) | The PES packet in flight is delivered with `Packet.flags.corrupt` (`continuity_errors`). |
| PES header that does not parse | That PES packet alone is dropped (`damaged_pes`). |
| PES packet longer than it declares | Truncated to `PES_packet_length`. |
| Unbounded PES packet that never ends | Handed out in pieces at the per-PID ceiling (`set_max_pes_bytes`; default an equal share of 256 MiB, at most 32 MiB): the first piece carries the timestamps, the rest none. |

The PAT and the selected program's PMT are followed while streaming:
when the program moves to another `program_map_PID`, or its PMT assigns
different elementary PIDs or a different `PCR_PID` (spliced captures, a
remultiplexed service), the streams are re-pointed and the PES packet in flight on
the old PID is handed out first (`program_map_changes`). A stream
keeps the entry on its PID when that still names its codec, so a map
that merely lists the same streams in another order moves nothing; a
stream whose codec the new PMT no longer lists stops.

Streams a later PMT **adds**: the program maps in the first 2 MiB are
read at open, and an elementary stream one of them adds is in the
stream list from the start (its packets begin where its map takes
effect). Past that window the list stays as opened — `streams()` never
changes behind a consumer's back — unless
`MpegTsDemuxer::set_admit_new_streams(true)` lets it grow
(`TsDemuxStats::streams_added`).

Memory is bounded whatever the input: the per-PID PES ceiling above,
4096 bytes per section assembler, 4 M entries in the access-point
index, and — in the program-stream demuxer — 16 MiB per video stream
awaiting an access-unit boundary.

## Throughput

`cargo bench --bench throughput` muxes four programs (one 40 kB-frame
video stream and two MPEG audio streams each, 900 pictures, 145 MiB
elementary / 151 MiB transport) and demuxes every program back.
Each figure is the median of three alternating before / after rounds
(each round itself the median of five runs) on an Apple-silicon
machine that was busy with other builds, so the ratios are more
dependable than the absolute numbers:

| Leg | Before | After |
|-----|-------:|------:|
| demux, in-memory source | 1 450 MiB/s | 4 051 MiB/s |
| demux, unbuffered `std::fs::File` | 226 MiB/s | 2 663 MiB/s |
| mux, in-memory sink | 2 342 MiB/s | 3 017 MiB/s |
| mux, unbuffered `std::fs::File` | 51 MiB/s | 1 142 MiB/s |

Demux figures count the whole transport stream once per demuxed
program (three quarters of the packets belong to other programs and
are skipped). The gains come from reading and writing the source /
sink in blocks instead of one 188-byte packet per call, a direct
8192-entry PID table in place of hash maps, collecting PES payload
bytes straight into the outgoing packet, and fragmenting a frame from
its PES header and payload without an intermediate copy. The muxed
stream is byte-identical before and after.

### Streams from another multiplexer

`MPEGTS_BENCH_FILE=<file> cargo bench --bench throughput` runs the legs
on any transport or program stream. On a 60 s, 30 Mbit/s MPEG-2 video +
AC-3 stream written by a black-box multiplexer (223 MiB as a transport
stream; the same packets as 192-byte packets, at a constant 40 Mbit/s
with null stuffing, and as a program stream), in memory, on the same
busy machine (medians of five; the program-stream row is the median of
three alternating before / after rounds):

| Leg | Before | After |
|-----|-------:|------:|
| demux, transport stream (188 / 192-byte / constant rate) | — | 4 950 / 4 960 / 5 520 MiB/s |
| demux, program stream | 1 249 MiB/s | 2 283 MiB/s |
| remux of the demuxed packets into a transport stream | — | 7 990 MiB/s |
| open | — | 1.3 ms (transport), 2.2 ms (program) |
| seek to a key frame + first packet (200 scattered targets) | — | 0.6 ms |

The program-stream gain: the access-unit splitter's start-code search
steps three bytes whenever the third byte rules a prefix out, and a PES
packet is parsed where it was read (two payload copies fewer). Output
is identical. Draining the 223 MiB stream from a file peaks at 4.6 MiB
resident, four copies of it back to back (891 MiB) at 5.2 MiB.

## Fuzzing

`fuzz/` carries a cargo-fuzz harness with four structure-aware
targets, exercised daily by the `Fuzz` workflow (30-minute shared
budget) and runnable locally with `cargo fuzz run <target>`:

| Target             | Contract                                                                 |
|--------------------|--------------------------------------------------------------------------|
| `demux`            | Arbitrary hostile bytes through the whole demux surface — `validate_ts`, the raw packet walk (per-PID PSI assembly across fragmented sections into every PSI/DVB-SI table parser with full descriptor walks, PES reassembly + Table 2-17 header decode, PCR / continuity / PTS-unwrap trackers), the §2.4.2 T-STD replay, and the typed demuxer battery (open, drain to the end, RAP index, all three seek paths). Panic-free, with liveness and memory oracles on the drain: end of stream within a call count bounded by the input, no more payload out than bytes in, in-flight bytes within the configured ceiling, and the identical packet sequence when the source returns only a few bytes per read. |
| `parse_units`      | Hostile bytes straight into the standalone unit parsers (all table parsers, descriptor walks, `PesPacket::parse`, the section assembler, `decode_utc_time`) plus encode∘parse fixed points: recipe-driven `PesHeaderSpec` / `AdaptationFieldSpec` encodes must parse back to the same wire fields, and the PAT/PMT builders must parse cleanly. |
| `mux_roundtrip`    | Valid-by-construction multi-program plans — programs × streams × frames × DVB SDT/EIT/NIT × §2.4.3.5/Annex-K splice runs × §2.7.6 time-base discontinuities × §2.4.2 CBR pacing × PSI repetition × §2.7.5 DTS × 33-bit-wrap timelines — must mux, come out `validate_ts`-conformant, satisfy the T-STD model in CBR mode, and re-demux to the exact per-stream (PTS, DTS, payload, keyframe) sequence per program. |
| `structured_mutate`| A writer-shaped fixture from the same plan space under fuzz-directed sync-byte kills, TS-header / PSI-section-header / CRC-region flips, packet drops and duplicates, byte insertions and deletions (grid shifts), truncation, 192/204-byte physical reframing, and leading bytes ahead of the first packet, fed back through the full hostile battery. |

The committed corpus holds named seeds plus regression inputs for
every finding the harness has caught; `fuzz/corpus/<target>/
regression_*` inputs are also pinned as in-tree unit tests where the
fix lives.

## License

MIT — see [`LICENSE`](LICENSE).
