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
| `psi`            | PAT + PMT + CAT (Conditional Access Table, §2.4.4.6) section parsers, plus `PsiSectionAssembler` — per-PID reassembler that joins long sections across multiple 188-byte TS packets (§2.4.4 pointer_field + PUSI continuation). Handles up-to-1024-byte sections, stuffing terminators, CC-skip detection, and back-to-back sections in one payload. |
| `descriptor`     | §2.6 TLV descriptors — registration / ISO-639 language / CA / video / audio / hierarchy / AVC / HEVC / data-stream-alignment / system-clock / copyright / maximum-bitrate / smoothing-buffer / STD. |
| `pes`            | PES packet reassembler — joins TS payloads per-PID into complete PES units. Decodes every Table 2-17 optional header field: PES_scrambling_control / PES_priority / data_alignment_indicator / copyright / original_or_copy on flags1, plus the flag-gated bodies ESCR (42-bit 27 MHz tick), ES_rate (50 bytes/s units), DSM_trick_mode (raw 8-bit), additional_copy_info, previous_PES_packet_CRC, and a PES_extension-present flag. |
| `stream_type`    | `stream_type` byte → BD-relevant codec class enum.                          |
| `clock`          | Per-PCR-PID 27 MHz clock recovery + per-PID continuity-counter classification (§2.4.2.2 / §2.4.3.3 / §2.4.3.5). |

No decoders. No re-multiplexing. Every payload byte stays as a
borrowed slice unless reassembly forces a copy.

`ProgramMapTable::iter_program_descriptors` and
`PmtStream::iter_descriptors` lift the raw descriptor bytes carried
inside a PMT into typed [`Descriptor`] records (TLV envelope + a
decoded body for the most common tags). Unrecognised tags surface as
`DescriptorBody::Raw` so downstream callers still see the payload
bytes verbatim. `ConditionalAccessTable::iter_descriptors` exposes
the same view over a CAT's CA_descriptor block.

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
