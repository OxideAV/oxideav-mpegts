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
| `packet`         | 188-byte TS packet — sync byte, flags, PID, adaptation field, payload.      |
| `psi`            | PAT (Program Association Table) + PMT (Program Map Table) sections.         |
| `pes`            | PES packet reassembler — joins TS payloads per-PID into complete PES units. |
| `stream_type`    | `stream_type` byte → BD-relevant codec class enum.                          |

No decoders. No re-multiplexing. Every payload byte stays as a
borrowed slice unless reassembly forces a copy.

## License

MIT — see [`LICENSE`](LICENSE).
