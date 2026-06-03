//! PES (Packetized Elementary Stream) reassembly per
//! ISO/IEC 13818-1 §2.4.3.6.
//!
//! Wire layout (Table 2-21):
//!
//! ```text
//! packet_start_code_prefix (24, = 0x00_00_01)
//! stream_id (8)
//! PES_packet_length (16)
//! ```
//!
//! For most `stream_id` values an "Optional PES header" follows:
//!
//! ```text
//! '10' (2) | PES_scrambling_control (2) | PES_priority (1) |
//! data_alignment_indicator (1) | copyright (1) | original_or_copy (1) |
//! PTS_DTS_flags (2) | ESCR_flag (1) | ES_rate_flag (1) |
//! DSM_trick_mode_flag (1) | additional_copy_info_flag (1) |
//! PES_CRC_flag (1) | PES_extension_flag (1) |
//! PES_header_data_length (8) |
//! <optional headers per flags above> |
//! <padding (0xFF)> |
//! <data>
//! ```
//!
//! PTS/DTS (Table 2-22) — 5 bytes each, four `'0001'`/`'0011'` marker
//! prefixes for the 33-bit 90 kHz timestamp:
//!
//! ```text
//! '0011' | PTS[32..30] | '1' | PTS[29..15] | '1' | PTS[14..0] | '1'
//! ```
//!
//! ## Reassembly model
//!
//! Live transport streams interleave PES packets across many TS
//! packets on the same PID. A PES packet begins on a TS packet whose
//! `payload_unit_start_indicator` is set; subsequent TS packets with
//! the same PID contain continuation bytes; a new PUSI=1 packet ends
//! the previous PES packet and starts the next.
//!
//! Callers drive [`PesReassembler::feed`] with each TS packet for a
//! given PID. The reassembler returns `Some(PesPacket)` exactly when
//! the *previous* PES packet has been completed by either:
//!
//! - a TS packet with PUSI=1 arriving (which starts the next packet),
//!   or
//! - the caller invoking [`PesReassembler::flush`] at end-of-stream.

use crate::{TsError, TsPacket};

/// "stream_id" values whose PES packet has no Optional PES header —
/// the body bytes follow the 6-byte fixed header directly.
///
/// Per ISO/IEC 13818-1 §2.4.3.7: program_stream_map, padding_stream,
/// private_stream_2, ECM, EMM, program_stream_directory, DSMCC_stream,
/// H.222.1 type E.
fn has_optional_pes_header(stream_id: u8) -> bool {
    !matches!(
        stream_id,
        0xBC // program_stream_map
        | 0xBE // padding_stream
        | 0xBF // private_stream_2
        | 0xF0 // ECM
        | 0xF1 // EMM
        | 0xFF // program_stream_directory
        | 0xF2 // DSM-CC stream
        | 0xF8 // ITU-T Rec. H.222.1 type E
    )
}

/// One complete PES packet — `stream_id`, optional PTS/DTS, payload,
/// and the per-spec optional-header fields parsed from §2.4.3.7
/// Table 2-17.
///
/// Fields after `payload` mirror the optional flags in the byte
/// immediately after the `'10'` marker. They are populated only for
/// `stream_id` values that carry the optional PES header; for the
/// header-less stream IDs (program_stream_map, padding_stream, …) they
/// stay at their `None` / zero defaults.
#[derive(Debug, Clone)]
pub struct PesPacket {
    /// `stream_id` byte from the PES header (Table 2-18).
    pub stream_id: u8,
    /// 2-bit `PES_scrambling_control` (Table 2-19).
    pub pes_scrambling_control: u8,
    /// `PES_priority` flag.
    pub pes_priority: bool,
    /// `data_alignment_indicator` flag (refer to
    /// `data_stream_alignment_descriptor`, §2.6.10).
    pub data_alignment_indicator: bool,
    /// `copyright` flag.
    pub copyright: bool,
    /// `original_or_copy` flag — `true` when the payload is an
    /// original.
    pub original_or_copy: bool,
    /// 33-bit Presentation Time Stamp (90 kHz), when present.
    pub pts_90k: Option<u64>,
    /// 33-bit Decoding Time Stamp (90 kHz), when present.
    pub dts_90k: Option<u64>,
    /// 42-bit Elementary Stream Clock Reference (27 MHz), when
    /// present. Computed as `ESCR_base * 300 + ESCR_extension` per
    /// equation 2-13.
    pub escr_27mhz: Option<u64>,
    /// 22-bit `ES_rate` field, in units of 50 bytes/second, when
    /// present. The decoded byte-rate is `value * 50`.
    pub es_rate_50bps: Option<u32>,
    /// Raw 8-bit DSM trick-mode byte (`trick_mode_control` in the top
    /// 3 bits, mode-specific tail in the bottom 5), when present.
    pub dsm_trick_mode: Option<u8>,
    /// 7-bit `additional_copy_info`, when present.
    pub additional_copy_info: Option<u8>,
    /// 16-bit `previous_PES_packet_CRC` value, when present.
    pub previous_pes_packet_crc: Option<u16>,
    /// True when the `PES_extension_flag` was set in the header. The
    /// extension sub-fields aren't surfaced individually but the flag
    /// is preserved so callers can tell whether the (skipped) body
    /// was present.
    pub pes_extension_present: bool,
    /// Elementary-stream payload bytes (after the optional PES header).
    pub payload: Vec<u8>,
}

impl PesPacket {
    /// Parse a complete, contiguous PES packet (header + body).
    ///
    /// `bytes` runs from the `packet_start_code_prefix` through the
    /// end of the PES payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, TsError> {
        if bytes.len() < 6 {
            return Err(TsError::Truncated {
                what: "PES header",
                have: bytes.len(),
                need: 6,
            });
        }
        if bytes[0] != 0x00 || bytes[1] != 0x00 || bytes[2] != 0x01 {
            return Err(TsError::BadPesStartCode([bytes[0], bytes[1], bytes[2]]));
        }
        let stream_id = bytes[3];
        let _pes_packet_length = u16::from_be_bytes([bytes[4], bytes[5]]);

        if !has_optional_pes_header(stream_id) {
            return Ok(Self {
                stream_id,
                pes_scrambling_control: 0,
                pes_priority: false,
                data_alignment_indicator: false,
                copyright: false,
                original_or_copy: false,
                pts_90k: None,
                dts_90k: None,
                escr_27mhz: None,
                es_rate_50bps: None,
                dsm_trick_mode: None,
                additional_copy_info: None,
                previous_pes_packet_crc: None,
                pes_extension_present: false,
                payload: bytes[6..].to_vec(),
            });
        }
        if bytes.len() < 9 {
            return Err(TsError::Truncated {
                what: "PES optional header",
                have: bytes.len(),
                need: 9,
            });
        }
        // bytes[6]: '10' marker | scrambling(2) | priority | data_alignment |
        //          copyright | original_or_copy.
        // bytes[7]: PTS_DTS_flags(2) | ESCR | ES_rate | DSM_trick_mode |
        //          additional_copy_info | PES_CRC | PES_extension.
        // bytes[8]: PES_header_data_length.
        let flags1 = bytes[6];
        let pes_scrambling_control = (flags1 >> 4) & 0b11;
        let pes_priority = (flags1 & 0b0000_1000) != 0;
        let data_alignment_indicator = (flags1 & 0b0000_0100) != 0;
        let copyright = (flags1 & 0b0000_0010) != 0;
        let original_or_copy = (flags1 & 0b0000_0001) != 0;

        let flags2 = bytes[7];
        let pts_dts_flags = (flags2 >> 6) & 0b11;
        let escr_flag = (flags2 & 0b0010_0000) != 0;
        let es_rate_flag = (flags2 & 0b0001_0000) != 0;
        let dsm_trick_mode_flag = (flags2 & 0b0000_1000) != 0;
        let additional_copy_info_flag = (flags2 & 0b0000_0100) != 0;
        let pes_crc_flag = (flags2 & 0b0000_0010) != 0;
        let pes_extension_flag = (flags2 & 0b0000_0001) != 0;

        let pes_header_data_length = bytes[8] as usize;
        let header_end = 9 + pes_header_data_length;
        if bytes.len() < header_end {
            return Err(TsError::Truncated {
                what: "PES optional header body",
                have: bytes.len(),
                need: header_end,
            });
        }
        let mut pts_90k = None;
        let mut dts_90k = None;
        let mut escr_27mhz = None;
        let mut es_rate_50bps = None;
        let mut dsm_trick_mode = None;
        let mut additional_copy_info = None;
        let mut previous_pes_packet_crc = None;
        let opt = &bytes[9..header_end];
        let mut cursor = 0usize;
        match pts_dts_flags {
            0b10 => {
                // PTS only.
                if opt.len() < cursor + 5 {
                    return Err(TsError::Truncated {
                        what: "PES PTS",
                        have: opt.len(),
                        need: cursor + 5,
                    });
                }
                pts_90k = Some(decode_timestamp(&opt[cursor..cursor + 5])?);
                cursor += 5;
            }
            0b11 => {
                if opt.len() < cursor + 10 {
                    return Err(TsError::Truncated {
                        what: "PES PTS+DTS",
                        have: opt.len(),
                        need: cursor + 10,
                    });
                }
                pts_90k = Some(decode_timestamp(&opt[cursor..cursor + 5])?);
                dts_90k = Some(decode_timestamp(&opt[cursor + 5..cursor + 10])?);
                cursor += 10;
            }
            0b00 => { /* no PTS/DTS */ }
            // 0b01 is forbidden by spec.
            _ => return Err(TsError::Unsupported("PES PTS_DTS_flags = 0b01")),
        }
        if escr_flag {
            if opt.len() < cursor + 6 {
                return Err(TsError::Truncated {
                    what: "PES ESCR",
                    have: opt.len(),
                    need: cursor + 6,
                });
            }
            escr_27mhz = Some(decode_escr(&opt[cursor..cursor + 6])?);
            cursor += 6;
        }
        if es_rate_flag {
            if opt.len() < cursor + 3 {
                return Err(TsError::Truncated {
                    what: "PES ES_rate",
                    have: opt.len(),
                    need: cursor + 3,
                });
            }
            // marker_bit | ES_rate(22) | marker_bit. Bits 21..15 in
            // opt[cursor] (lower 7), bits 14..7 in opt[cursor+1],
            // bits 6..0 in upper 7 of opt[cursor+2].
            let b0 = opt[cursor] as u32;
            let b1 = opt[cursor + 1] as u32;
            let b2 = opt[cursor + 2] as u32;
            let es_rate = ((b0 & 0x7F) << 15) | (b1 << 7) | ((b2 >> 1) & 0x7F);
            es_rate_50bps = Some(es_rate);
            cursor += 3;
        }
        if dsm_trick_mode_flag {
            if opt.len() < cursor + 1 {
                return Err(TsError::Truncated {
                    what: "PES DSM_trick_mode",
                    have: opt.len(),
                    need: cursor + 1,
                });
            }
            dsm_trick_mode = Some(opt[cursor]);
            cursor += 1;
        }
        if additional_copy_info_flag {
            if opt.len() < cursor + 1 {
                return Err(TsError::Truncated {
                    what: "PES additional_copy_info",
                    have: opt.len(),
                    need: cursor + 1,
                });
            }
            // marker_bit | additional_copy_info(7).
            additional_copy_info = Some(opt[cursor] & 0x7F);
            cursor += 1;
        }
        if pes_crc_flag {
            if opt.len() < cursor + 2 {
                return Err(TsError::Truncated {
                    what: "PES previous_PES_packet_CRC",
                    have: opt.len(),
                    need: cursor + 2,
                });
            }
            previous_pes_packet_crc = Some(u16::from_be_bytes([opt[cursor], opt[cursor + 1]]));
            cursor += 2;
        }
        // pes_extension_flag body: we record only its presence. The
        // body is bounded by `pes_header_data_length` and the rest is
        // stuffing — both of which we skip past via `header_end`.
        let _ = cursor;

        Ok(Self {
            stream_id,
            pes_scrambling_control,
            pes_priority,
            data_alignment_indicator,
            copyright,
            original_or_copy,
            pts_90k,
            dts_90k,
            escr_27mhz,
            es_rate_50bps,
            dsm_trick_mode,
            additional_copy_info,
            previous_pes_packet_crc,
            pes_extension_present: pes_extension_flag,
            payload: bytes[header_end..].to_vec(),
        })
    }
}

/// Decode a 6-byte ESCR field (Table 2-17) into a 27 MHz tick count.
///
/// Layout (48 bits, Table 2-17 / equations 2-13..2-15):
///
/// ```text
/// reserved(2) | ESCR_base[32..30](3)  | marker(1) |
/// ESCR_base[29..15](15) | marker(1)   |
/// ESCR_base[14..0](15)  | marker(1)   |
/// ESCR_extension(9)     | marker(1)
/// ```
///
/// Result: `ESCR_base * 300 + ESCR_extension` per equation 2-13 (a
/// 42-bit value held in a u64 — top 22 bits always zero).
fn decode_escr(b: &[u8]) -> Result<u64, TsError> {
    if b.len() < 6 {
        return Err(TsError::Truncated {
            what: "ESCR",
            have: b.len(),
            need: 6,
        });
    }
    // Bit packing across 6 bytes (MSB-first per spec bslbf/uimsbf):
    //
    //   b[0]: r r B B B M b b      where B B B = base[32..30],
    //                              M = marker, b b = base[29..28]
    //   b[1]: b b b b b b b b      = base[27..20]
    //   b[2]: b b b b b M b b      base[19..15] (top 5 of the byte),
    //                              marker, base[14..13]
    //   b[3]: b b b b b b b b      = base[12..5]
    //   b[4]: b b b b b M e e      base[4..0], marker, ext[8..7]
    //   b[5]: e e e e e e e M      ext[6..0], marker
    let base_32_30 = ((b[0] >> 3) & 0b0000_0111) as u64;
    let base_29_15 = (((b[0] as u64) & 0b0000_0011) << 13)
        | ((b[1] as u64) << 5)
        | (((b[2] as u64) >> 3) & 0b0001_1111);
    let base_14_0 = (((b[2] as u64) & 0b0000_0011) << 13)
        | ((b[3] as u64) << 5)
        | (((b[4] as u64) >> 3) & 0b0001_1111);
    let escr_ext = (((b[4] as u64) & 0b0000_0011) << 7) | (((b[5] as u64) >> 1) & 0x7F);

    let base = (base_32_30 << 30) | (base_29_15 << 15) | base_14_0;
    Ok(base * 300 + escr_ext)
}

/// Decode a 5-byte PTS or DTS field (Table 2-22).
fn decode_timestamp(b: &[u8]) -> Result<u64, TsError> {
    if b.len() < 5 {
        return Err(TsError::Truncated {
            what: "PTS/DTS",
            have: b.len(),
            need: 5,
        });
    }
    // Top nibble of b[0] is the 4-bit marker ('0010' for PTS-only,
    // '0011' for PTS-of-PTS+DTS, '0001' for DTS). We don't validate
    // it — just extract the timestamp.
    let t32_30 = ((b[0] >> 1) & 0b0000_0111) as u64;
    let t29_22 = b[1] as u64;
    let t21_15 = ((b[2] >> 1) & 0b0111_1111) as u64;
    let t14_7 = b[3] as u64;
    let t6_0 = ((b[4] >> 1) & 0b0111_1111) as u64;
    let ts = (t32_30 << 30) | (t29_22 << 22) | (t21_15 << 15) | (t14_7 << 7) | t6_0;
    Ok(ts)
}

/// Per-PID PES reassembler.
///
/// Tracks one in-flight PES packet's accumulated payload bytes; emits
/// a parsed [`PesPacket`] when the next PUSI=1 TS packet arrives or
/// the caller flushes.
#[derive(Debug, Default)]
pub struct PesReassembler {
    /// Accumulated PES packet bytes (starts at packet_start_code_prefix).
    buf: Vec<u8>,
    /// Set once a PUSI=1 TS packet has populated `buf`.
    started: bool,
}

impl PesReassembler {
    /// Create an empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next TS packet (must have the same PID as the prior
    /// feeds). Returns `Some(PesPacket)` when a complete PES packet
    /// has been finalised by this packet's PUSI=1.
    pub fn feed(&mut self, ts: &TsPacket<'_>) -> Result<Option<PesPacket>, TsError> {
        if ts.payload_unit_start {
            // The arriving PES packet's PUSI=1 closes the prior PES
            // packet (if any).
            let finished = if self.started {
                Some(PesPacket::parse(&self.buf)?)
            } else {
                None
            };
            self.buf.clear();
            self.buf.extend_from_slice(ts.payload);
            self.started = true;
            Ok(finished)
        } else if self.started {
            self.buf.extend_from_slice(ts.payload);
            Ok(None)
        } else {
            // Continuation bytes before we've seen the first PUSI=1 —
            // discard, per spec we can't anchor the packet yet.
            Ok(None)
        }
    }

    /// Drain the buffered PES packet (call at end-of-stream).
    pub fn flush(&mut self) -> Result<Option<PesPacket>, TsError> {
        if !self.started {
            return Ok(None);
        }
        let buf = std::mem::take(&mut self.buf);
        self.started = false;
        Ok(Some(PesPacket::parse(&buf)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TS_PACKET_LEN, TS_SYNC_BYTE};

    /// Encode a PTS/DTS into 5 bytes per Table 2-22, with the given
    /// 4-bit prefix nibble.
    fn encode_timestamp(prefix: u8, ts: u64) -> [u8; 5] {
        // 33-bit timestamp.
        let t = ts & 0x1_FFFF_FFFF;
        let t32_30 = ((t >> 30) & 0b0111) as u8;
        let t29_15 = ((t >> 15) & 0x7FFF) as u16;
        let t14_0 = (t & 0x7FFF) as u16;
        [
            (prefix << 4) | (t32_30 << 1) | 0b1,
            ((t29_15 >> 7) & 0xFF) as u8,
            (((t29_15 & 0x7F) << 1) as u8) | 0b1,
            ((t14_0 >> 7) & 0xFF) as u8,
            (((t14_0 & 0x7F) << 1) as u8) | 0b1,
        ]
    }

    /// Build a video PES packet (stream_id 0xE0) with a PTS and the
    /// given payload bytes.
    fn build_pes(stream_id: u8, pts: u64, payload: &[u8]) -> Vec<u8> {
        let pts_bytes = encode_timestamp(0b0010, pts);
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, stream_id]);
        // PES_packet_length covers bytes from byte 6 onward.
        let pes_packet_length: u16 = (3 + 5 + payload.len()) as u16;
        v.extend_from_slice(&pes_packet_length.to_be_bytes());
        // byte 6: '10' marker | scrambling=0 | priority=0 | data_align=0 |
        //         copyright=0 | original_or_copy=0  ⇒ 0b1000_0000.
        v.push(0b1000_0000);
        // byte 7: PTS_DTS_flags=0b10 (PTS only), rest 0  ⇒ 0b1000_0000.
        v.push(0b1000_0000);
        // byte 8: PES_header_data_length = 5 (just PTS).
        v.push(5);
        v.extend_from_slice(&pts_bytes);
        v.extend_from_slice(payload);
        v
    }

    /// Wrap PES bytes into TS packets, splitting at `chunk_len` bytes
    /// from the PES start, with the given PID. The first packet has
    /// PUSI=1; the rest PUSI=0. Every packet is 188 bytes. When the
    /// PES bytes don't fill a packet's payload area (the typical case
    /// for the final packet of a PES packet on a real broadcast), an
    /// adaptation field is inserted before the payload to absorb the
    /// shortfall — matching ISO/IEC 13818-1 §2.4.3.4 stuffing
    /// behaviour.
    fn pes_into_ts(pid: u16, pes: &[u8], chunk_len: usize) -> Vec<u8> {
        assert!(chunk_len > 0 && chunk_len <= 184);
        let mut out = Vec::new();
        let mut cursor = 0;
        let mut first = true;
        let mut cc: u8 = 0;
        while cursor < pes.len() {
            let pusi = if first { 0b0100_0000 } else { 0 };
            let pid_hi = ((pid >> 8) & 0x1F) as u8;
            let pid_lo = (pid & 0xFF) as u8;
            let remaining = pes.len() - cursor;
            let take = remaining.min(chunk_len).min(184);
            // If the PES bytes don't fill 184 bytes, insert an AF of
            // the required size before them. AF length byte counts
            // ONLY the bytes after it: so for a stuffing AF of N
            // total bytes, length byte = N-1, then N-1 0xFF stuffing
            // bytes.
            let af_total = 184 - take;
            let af_control: u8 = if af_total > 0 { 0b11 } else { 0b01 };
            let b3 = (af_control << 4) | (cc & 0x0F);
            let mut pkt = vec![TS_SYNC_BYTE, pusi | pid_hi, pid_lo, b3];
            if af_total > 0 {
                // length byte counts bytes after itself.
                pkt.push((af_total - 1) as u8);
                // Per spec, an AF with only stuffing has length>=1
                // (length byte + 0+ stuffing) when there is no flags
                // byte room; but the standard requires a flags byte
                // when length>0. We allocate the flags byte and use
                // the rest as 0xFF stuffing.
                if af_total >= 2 {
                    pkt.push(0); // flags = none
                    pkt.extend(std::iter::repeat(0xFF).take(af_total - 2));
                }
                // af_total == 1 ⇒ only the length byte (length=0,
                // see above), already emitted.
            }
            pkt.extend_from_slice(&pes[cursor..cursor + take]);
            cursor += take;
            assert_eq!(pkt.len(), TS_PACKET_LEN);
            out.extend_from_slice(&pkt);
            cc = (cc + 1) & 0x0F;
            first = false;
        }
        out
    }

    #[test]
    fn decode_timestamp_round_trip() {
        for ts in [0u64, 1, 90_000, 0x1_FFFF_FFFF] {
            let enc = encode_timestamp(0b0010, ts);
            let dec = decode_timestamp(&enc).unwrap();
            assert_eq!(dec, ts);
        }
    }

    #[test]
    fn parse_complete_pes_packet_pts_only() {
        let pes = build_pes(0xE0, 90_000, b"hello world");
        let parsed = PesPacket::parse(&pes).unwrap();
        assert_eq!(parsed.stream_id, 0xE0);
        assert_eq!(parsed.pts_90k, Some(90_000));
        assert_eq!(parsed.dts_90k, None);
        assert_eq!(parsed.payload, b"hello world");
    }

    #[test]
    fn parse_complete_pes_packet_pts_dts() {
        let pts_bytes = encode_timestamp(0b0011, 200_000);
        let dts_bytes = encode_timestamp(0b0001, 180_000);
        let payload = b"AVCdata";
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        let pes_packet_length: u16 = (3 + 10 + payload.len()) as u16;
        v.extend_from_slice(&pes_packet_length.to_be_bytes());
        v.push(0b1000_0000);
        v.push(0b1100_0000); // PTS_DTS_flags = 0b11
        v.push(10);
        v.extend_from_slice(&pts_bytes);
        v.extend_from_slice(&dts_bytes);
        v.extend_from_slice(payload);
        let parsed = PesPacket::parse(&v).unwrap();
        assert_eq!(parsed.pts_90k, Some(200_000));
        assert_eq!(parsed.dts_90k, Some(180_000));
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reassemble_pes_split_across_three_ts_packets() {
        let payload: Vec<u8> = (0..400u32).map(|i| (i & 0xFF) as u8).collect();
        let pes = build_pes(0xE0, 12345, &payload);
        // chunk_len = 150 ⇒ ~3 TS packets for a ~410-byte PES.
        let ts_buf = pes_into_ts(0x100, &pes, 150);
        // Append a second PUSI=1 packet (with a tiny "next" PES) so
        // feed() emits the previous packet.
        let next_pes = build_pes(0xE0, 67890, b"X");
        let next_ts = pes_into_ts(0x100, &next_pes, 184);
        let mut full = ts_buf;
        full.extend_from_slice(&next_ts);

        let mut r = PesReassembler::new();
        let mut packets = Vec::new();
        for pkt in crate::iter_packets(&full) {
            let pkt = pkt.unwrap();
            if let Some(done) = r.feed(&pkt).unwrap() {
                packets.push(done);
            }
        }
        if let Some(done) = r.flush().unwrap() {
            packets.push(done);
        }

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].pts_90k, Some(12345));
        // Payload should match exactly — stuffing is part of the TS
        // packet, not the PES packet. But because we pad TS packets
        // with 0xFF *after* the PES bytes, the last TS packet's
        // payload area carries some trailing stuffing that gets
        // appended to `buf`. We assert the PES prefix matches and
        // the parser still pulls out the right header + initial
        // payload bytes.
        assert_eq!(&packets[0].payload[..payload.len()], &payload[..]);
        assert_eq!(packets[1].pts_90k, Some(67890));
    }

    #[test]
    fn pusi_starts_new_packet_and_emits_previous() {
        let pes1 = build_pes(0xC0, 1000, b"first");
        let pes2 = build_pes(0xC0, 2000, b"second");
        let ts1 = pes_into_ts(0x101, &pes1, 184);
        let ts2 = pes_into_ts(0x101, &pes2, 184);

        let mut r = PesReassembler::new();
        let mut emitted = Vec::new();
        for buf in [&ts1, &ts2] {
            for pkt in crate::iter_packets(buf) {
                let pkt = pkt.unwrap();
                if let Some(done) = r.feed(&pkt).unwrap() {
                    emitted.push(done);
                }
            }
        }
        // Only `pes1` should have been emitted (closed by `pes2`'s
        // PUSI=1). `pes2` is still buffered.
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].pts_90k, Some(1000));
        assert_eq!(&emitted[0].payload[..5], b"first");
        let flushed = r.flush().unwrap().expect("buffered pes2");
        assert_eq!(flushed.pts_90k, Some(2000));
        assert_eq!(&flushed.payload[..6], b"second");
    }

    #[test]
    fn padding_stream_has_no_optional_header() {
        // stream_id = 0xBE (padding_stream) — no optional PES header.
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0xBE]);
        let payload = [0xFFu8; 12];
        let len: u16 = payload.len() as u16;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(&payload);
        let p = PesPacket::parse(&v).unwrap();
        assert_eq!(p.stream_id, 0xBE);
        assert_eq!(p.pts_90k, None);
        assert_eq!(p.dts_90k, None);
        assert_eq!(p.payload, &payload);
    }

    #[test]
    fn bad_pes_start_code_rejected() {
        let mut v = vec![0x00, 0x00, 0x02, 0xE0, 0, 0];
        v.extend_from_slice(&[0u8; 3]);
        let err = PesPacket::parse(&v).unwrap_err();
        match err {
            TsError::BadPesStartCode(_) => {}
            other => panic!("expected BadPesStartCode, got {other:?}"),
        }
    }

    /// Encode a 42-bit ESCR into the 6-byte spec layout (Table 2-17).
    fn encode_escr(escr_42: u64) -> [u8; 6] {
        let base = (escr_42 / 300) & 0x1_FFFF_FFFF;
        let ext = (escr_42 % 300) & 0x1FF;
        let base_32_30 = ((base >> 30) & 0b111) as u8;
        let base_29_15 = ((base >> 15) & 0x7FFF) as u32;
        let base_14_0 = (base & 0x7FFF) as u32;
        let ext = ext as u32;
        let b0 = 0b1100_0000 // reserved bits set to 1, matches typical encoder
            | (base_32_30 << 3)
            | 0b0000_0100 // marker
            | (((base_29_15 >> 13) & 0b11) as u8);
        let b1 = ((base_29_15 >> 5) & 0xFF) as u8;
        let b2 = (((base_29_15 & 0x1F) as u8) << 3)
            | 0b0000_0100 // marker
            | (((base_14_0 >> 13) & 0b11) as u8);
        let b3 = ((base_14_0 >> 5) & 0xFF) as u8;
        let b4 = (((base_14_0 & 0x1F) as u8) << 3)
            | 0b0000_0100 // marker
            | (((ext >> 7) & 0b11) as u8);
        let b5 = (((ext & 0x7F) as u8) << 1) | 0b0000_0001; // marker
        [b0, b1, b2, b3, b4, b5]
    }

    /// Encode a 22-bit ES_rate into the 3-byte spec layout.
    fn encode_es_rate(rate: u32) -> [u8; 3] {
        let r = rate & 0x3F_FFFF;
        [
            0b1000_0000 | ((r >> 15) as u8 & 0x7F),
            ((r >> 7) & 0xFF) as u8,
            (((r & 0x7F) << 1) as u8) | 0x01,
        ]
    }

    #[test]
    fn escr_round_trip_round_numbers() {
        // Spec ESCR range: ESCR_base is 33-bit and ESCR_extension is
        // in [0, 299], so the addressable 27 MHz tick range is
        // [0, (2^33 - 1) * 300 + 299].
        let max_escr: u64 = (((1u64 << 33) - 1) * 300) + 299;
        for &target in &[0u64, 1, 299, 300, 27_000_000, 27_000_001, max_escr] {
            let enc = encode_escr(target);
            let dec = decode_escr(&enc).unwrap();
            assert_eq!(dec, target, "target {target:#x} encoded {enc:02X?}");
        }
    }

    #[test]
    fn parse_pes_with_every_optional_field() {
        // Build a PES header carrying all flag-gated optional fields
        // (PTS+DTS, ESCR, ES_rate, DSM_trick_mode, additional_copy_info,
        // PES_CRC, PES_extension marker).
        let pts_bytes = encode_timestamp(0b0011, 300_000);
        let dts_bytes = encode_timestamp(0b0001, 240_000);
        let escr_bytes = encode_escr(27_000_123);
        let es_rate_bytes = encode_es_rate(123_456);
        let dsm_byte: u8 = 0b010_00000; // trick_mode_control = freeze_frame
        let aci_byte: u8 = 0x80 | 0x42; // marker_bit=1 | aci=0x42
        let pes_crc_bytes: [u8; 2] = [0xCA, 0xFE];
        // PES_extension flag set with a minimal extension byte
        // (all sub-flags zero, no body) so PES_header_data_length
        // accounts for it.
        let pes_ext_flags: u8 = 0b0000_0000;
        let optional: Vec<u8> = [
            pts_bytes.as_slice(),
            dts_bytes.as_slice(),
            escr_bytes.as_slice(),
            es_rate_bytes.as_slice(),
            std::slice::from_ref(&dsm_byte),
            std::slice::from_ref(&aci_byte),
            pes_crc_bytes.as_slice(),
            std::slice::from_ref(&pes_ext_flags),
        ]
        .concat();
        let payload = b"\x01\x02\x03\x04";
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        let pes_packet_length: u16 = (3 + optional.len() + payload.len()) as u16;
        v.extend_from_slice(&pes_packet_length.to_be_bytes());
        // flags1: '10' marker | scrambling=00 | priority=1 |
        //         data_alignment=1 | copyright=1 | original_or_copy=1
        v.push(0b1000_1111);
        // flags2: PTS_DTS=11 | ESCR=1 | ES_rate=1 | DSM=1 | ACI=1 |
        //         PES_CRC=1 | PES_extension=1 = 0b11_11_11_11
        v.push(0b1111_1111);
        v.push(optional.len() as u8);
        v.extend_from_slice(&optional);
        v.extend_from_slice(payload);
        let p = PesPacket::parse(&v).unwrap();
        assert_eq!(p.stream_id, 0xE0);
        assert_eq!(p.pes_scrambling_control, 0);
        assert!(p.pes_priority);
        assert!(p.data_alignment_indicator);
        assert!(p.copyright);
        assert!(p.original_or_copy);
        assert_eq!(p.pts_90k, Some(300_000));
        assert_eq!(p.dts_90k, Some(240_000));
        assert_eq!(p.escr_27mhz, Some(27_000_123));
        assert_eq!(p.es_rate_50bps, Some(123_456));
        assert_eq!(p.dsm_trick_mode, Some(0b010_00000));
        assert_eq!(p.additional_copy_info, Some(0x42));
        assert_eq!(p.previous_pes_packet_crc, Some(0xCAFE));
        assert!(p.pes_extension_present);
        assert_eq!(p.payload, payload);
    }

    #[test]
    fn parse_pes_no_optional_fields_defaults() {
        // PTS-only PES, no ESCR / ES_rate / DSM / ACI / CRC / ext.
        let pes = build_pes(0xE0, 90_000, b"abcd");
        let p = PesPacket::parse(&pes).unwrap();
        assert_eq!(p.pts_90k, Some(90_000));
        assert_eq!(p.escr_27mhz, None);
        assert_eq!(p.es_rate_50bps, None);
        assert_eq!(p.dsm_trick_mode, None);
        assert_eq!(p.additional_copy_info, None);
        assert_eq!(p.previous_pes_packet_crc, None);
        assert!(!p.pes_extension_present);
        // Flag bits in the all-zero flags1 byte we set.
        assert!(!p.pes_priority);
        assert!(!p.copyright);
        assert_eq!(p.pes_scrambling_control, 0);
    }

    #[test]
    fn parse_pes_truncated_optional_body_rejected() {
        // PTS_DTS=11 (claims 10 bytes) but PES_header_data_length=5,
        // so the body can't hold both timestamps.
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        // length covers from byte 6 onward: flags(3) + optional(5) = 8
        v.extend_from_slice(&8u16.to_be_bytes());
        v.push(0b1000_0000);
        v.push(0b1100_0000);
        v.push(5); // header_data_length too small for PTS+DTS
        v.extend_from_slice(&[0u8; 5]);
        let err = PesPacket::parse(&v).unwrap_err();
        match err {
            TsError::Truncated { what, .. } => {
                assert_eq!(what, "PES PTS+DTS");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
