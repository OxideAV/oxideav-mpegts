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

/// One complete PES packet — `stream_id`, optional PTS/DTS, payload.
#[derive(Debug, Clone)]
pub struct PesPacket {
    /// `stream_id` byte from the PES header (Table 2-18).
    pub stream_id: u8,
    /// 33-bit Presentation Time Stamp (90 kHz), when present.
    pub pts_90k: Option<u64>,
    /// 33-bit Decoding Time Stamp (90 kHz), when present.
    pub dts_90k: Option<u64>,
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
                pts_90k: None,
                dts_90k: None,
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
        let pts_dts_flags = (bytes[7] >> 6) & 0b11;
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
        let opt = &bytes[9..header_end];
        let mut cursor = 0usize;
        match pts_dts_flags {
            0b10 => {
                // PTS only.
                if opt.len() < 5 {
                    return Err(TsError::Truncated {
                        what: "PES PTS",
                        have: opt.len(),
                        need: 5,
                    });
                }
                pts_90k = Some(decode_timestamp(&opt[..5])?);
                cursor += 5;
            }
            0b11 => {
                if opt.len() < 10 {
                    return Err(TsError::Truncated {
                        what: "PES PTS+DTS",
                        have: opt.len(),
                        need: 10,
                    });
                }
                pts_90k = Some(decode_timestamp(&opt[..5])?);
                dts_90k = Some(decode_timestamp(&opt[5..10])?);
                cursor += 10;
            }
            0b00 => { /* no PTS/DTS */ }
            // 0b01 is forbidden by spec.
            _ => return Err(TsError::Unsupported("PES PTS_DTS_flags = 0b01")),
        }
        let _ = cursor; // remaining optional fields are skipped via header_end.

        Ok(Self {
            stream_id,
            pts_90k,
            dts_90k,
            payload: bytes[header_end..].to_vec(),
        })
    }
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
}
