# oxideav-mpegts

Pure-Rust, clean-room **MPEG-TS** (Transport Stream) demuxer per
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
| `packet`         | 188-byte TS packet — sync byte, flags, PID, adaptation field (PCR + OPCR + splice_countdown + transport_private_data + adaptation_field_extension with ltw / piecewise_rate / seamless_splice), payload. |
| `psi`            | PAT + PMT + CAT (Conditional Access Table, §2.4.4.6) + TSDT (Transport Stream Description Table, §2.4.4.12 — TS-wide descriptor loop on PID 0x0002 / table_id 0x03) + SDT (DVB Service Description Table, ETSI EN 300 468 §5.2.3 — service loop on PID 0x0011 / table_id 0x42 actual + 0x46 other, with typed `RunningStatus`) + EIT (DVB Event Information Table, EN 300 468 §5.2.4 — event loop on PID 0x0012 / table_id 0x4E/0x4F present-following + 0x50–0x6F schedule, with MJD/BCD `start_time` + BCD `duration` decoded per annex C) + NIT (DVB Network Information Table, EN 300 468 §5.2.1 — PID 0x0010 / table_id 0x40 actual + 0x41 other, with the `network_id` plus a network-level descriptor loop and a typed `transport_stream_loop` of `(transport_stream_id, original_network_id)` entries each carrying their own descriptor loop) + TDT (DVB Time and Date Table, EN 300 468 §5.2.5 — short-form section on PID 0x0014 / table_id 0x70 carrying just the 40-bit MJD/BCD `UTC_time`) + TOT (DVB Time Offset Table, EN 300 468 §5.2.6 — short-form section on PID 0x0014 / table_id 0x73, the `UTC_time` plus a CRC-verified descriptor loop that usually carries the `local_time_offset_descriptor`) section parsers, plus `PsiSectionAssembler` — per-PID reassembler that joins long sections across multiple 188-byte TS packets (§2.4.4 pointer_field + PUSI continuation). Handles up-to-1024-byte sections, stuffing terminators, CC-skip detection, and back-to-back sections in one payload. |
| `descriptor`     | §2.6 TLV descriptors — registration / ISO-639 language / CA / video / audio / hierarchy / AVC / HEVC / data-stream-alignment / target-background-grid / video-window / system-clock / multiplex-buffer-utilization / copyright / maximum-bitrate / smoothing-buffer / STD / IBP — plus the DVB `service_descriptor` (tag 0x48, EN 300 468 §6.2.33) carrying the service / provider names, the DVB `short_event_descriptor` (tag 0x4D, EN 300 468 §6.2.37) carrying the event name + short text, the DVB `extended_event_descriptor` (tag 0x4E, EN 300 468 §6.2.15) carrying the detailed two-column `(item_description, item)` list plus non-itemized free text with the `descriptor_number` / `last_descriptor_number` association pair, the DVB `network_name_descriptor` (tag 0x40, EN 300 468 §6.2.27) carrying the delivery-system name, the DVB `content_descriptor` (tag 0x54, EN 300 468 §6.2.9) carrying the per-event genre classification as a flat array of two-nibble (Table 29) + `user_byte` triples, the DVB `local_time_offset_descriptor` (tag 0x58, EN 300 468 §6.2.20) carrying per-country local-time-offset entries (offset minutes + `time_of_change` instant + next offset), and the DVB PMT elementary-stream descriptors a demuxer reads to route a private-data PES — `stream_identifier_descriptor` (tag 0x52, §6.2.39 → component_tag), `teletext_descriptor` (tag 0x56, §6.2.43 → per-language EBU teletext pages), `subtitling_descriptor` (tag 0x59, §6.2.41 → per-language EN 300 743 subtitle services), `AC-3_descriptor` (tag 0x6A, annex D), `enhanced_AC-3_descriptor` (tag 0x7A, annex D), and `DTS_descriptor` (tag 0x7B, annex G). |
| `pes`            | PES packet reassembler — joins TS payloads per-PID into complete PES units. Decodes every Table 2-17 optional header field: PES_scrambling_control / PES_priority / data_alignment_indicator / copyright / original_or_copy on flags1, plus the flag-gated bodies ESCR (42-bit 27 MHz tick), ES_rate (50 bytes/s units), DSM_trick_mode (raw 8-bit), additional_copy_info, previous_PES_packet_CRC, and the full PES_extension body (16-byte private data, raw pack_header bytes, program_packet_sequence_counter, P-STD buffer scale/size, PES_extension_field_2). |
| `stream_type`    | `stream_type` byte → codec class enum covering the full ISO/IEC 13818-1 Table 2-29 base range (`0x01..=0x26`: MPEG-1/2/4 video + audio, AAC-ADTS/LATM, private sections / PES, MHEG, DSM-CC, metadata carriers, IPMP, AVC / SVC / MVC / MVCD, JPEG 2000, stereoscopic views, HEVC + temporal subset) plus AVS video and the HDMV-extended Blu-ray range. Classifies video / audio / subtitle / metadata / private. |
| `clock`          | Per-PCR-PID 27 MHz clock recovery + per-PID continuity-counter classification (§2.4.2.2 / §2.4.3.3 / §2.4.3.5), plus `PtsTracker` — per-PID 33-bit PTS/DTS unwrapping (§2.4.3.7) into a monotonic 64-bit extended timeline with wrap-vs-discontinuity classification. |

No decoders. No re-multiplexing. Every payload byte stays as a
borrowed slice unless reassembly forces a copy.

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

## License

MIT — see [`LICENSE`](LICENSE).
