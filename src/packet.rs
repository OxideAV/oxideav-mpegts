//! 188-byte MPEG-TS packet parser per ISO/IEC 13818-1 §2.4.3.
//!
//! Wire layout (Table 2-2):
//!
//! ```text
//! byte 0       sync_byte (= 0x47)
//! byte 1..3    transport_error_indicator (1) | payload_unit_start_indicator (1) |
//!              transport_priority (1) | PID (13) |
//!              transport_scrambling_control (2) | adaptation_field_control (2) |
//!              continuity_counter (4)
//! byte 4..     optional adaptation field + payload bytes
//! ```
//!
//! Adaptation field layout (§2.4.3.4, Table 2-6):
//!
//! ```text
//! adaptation_field_length (8)
//! flags (8): discontinuity_indicator | random_access_indicator |
//!            elementary_stream_priority_indicator | PCR_flag | OPCR_flag |
//!            splicing_point_flag | transport_private_data_flag |
//!            adaptation_field_extension_flag
//! optional PCR  (48 bits = 33-bit base + 6 reserved + 9-bit extension)
//! optional OPCR (48 bits, coded like PCR)
//! optional splice_countdown (8, tcimsbf)
//! optional transport_private_data: length (8) + N data bytes
//! optional adaptation_field_extension:
//!     length (8)
//!     ltw_flag (1) | piecewise_rate_flag (1) | seamless_splice_flag (1) | reserved (5)
//!     if ltw_flag: ltw_valid_flag (1) | ltw_offset (15)
//!     if piecewise_rate_flag: reserved (2) | piecewise_rate (22)
//!     if seamless_splice_flag: splice_type (4) | DTS_next_AU (3 × 15-bit pieces
//!         interleaved with marker bits, 5 bytes total)
//! stuffing bytes (0xFF)
//! ```

use crate::TsError;

/// Fixed size of a transport-stream packet (188 bytes).
pub const TS_PACKET_LEN: usize = 188;

/// Spec-defined sync byte at offset 0 of every TS packet.
pub const TS_SYNC_BYTE: u8 = 0x47;

/// Parsed adaptation field accompanying a TS packet.
#[derive(Debug, Clone, Copy)]
pub struct AdaptationField<'a> {
    /// Value of the `adaptation_field_length` byte. Counts the bytes
    /// that follow it within the adaptation field (so the AF occupies
    /// `length + 1` bytes of the packet payload area).
    pub length: u8,
    /// `discontinuity_indicator` flag.
    pub discontinuity_indicator: bool,
    /// `random_access_indicator` flag.
    pub random_access_indicator: bool,
    /// `elementary_stream_priority_indicator` flag.
    pub elementary_stream_priority_indicator: bool,
    /// `PCR_flag` — when set, [`Self::pcr_base`] and
    /// [`Self::pcr_extension`] are populated.
    pub pcr_flag: bool,
    /// `OPCR_flag`.
    pub opcr_flag: bool,
    /// `splicing_point_flag`.
    pub splicing_point_flag: bool,
    /// `transport_private_data_flag`.
    pub transport_private_data_flag: bool,
    /// `adaptation_field_extension_flag`.
    pub adaptation_field_extension_flag: bool,
    /// 33-bit `program_clock_reference_base`, when [`Self::pcr_flag`].
    pub pcr_base: Option<u64>,
    /// 9-bit `program_clock_reference_extension`, when
    /// [`Self::pcr_flag`].
    pub pcr_extension: Option<u16>,
    /// 33-bit `original_program_clock_reference_base`, when
    /// [`Self::opcr_flag`].
    pub opcr_base: Option<u64>,
    /// 9-bit `original_program_clock_reference_extension`, when
    /// [`Self::opcr_flag`].
    pub opcr_extension: Option<u16>,
    /// Signed 8-bit `splice_countdown` (§2.4.3.5), present when
    /// [`Self::splicing_point_flag`].
    pub splice_countdown: Option<i8>,
    /// `private_data_byte` slice, when
    /// [`Self::transport_private_data_flag`]. Length equals the
    /// `transport_private_data_length` byte on the wire.
    pub transport_private_data: Option<&'a [u8]>,
    /// Decoded adaptation field extension body, when
    /// [`Self::adaptation_field_extension_flag`].
    pub adaptation_field_extension: Option<AdaptationFieldExtension>,
    /// Raw adaptation-field bytes including the
    /// `adaptation_field_length` byte itself.
    pub raw: &'a [u8],
}

/// Parsed `adaptation_field_extension` body (§2.4.3.5, Table 2-6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdaptationFieldExtension {
    /// Value of the `adaptation_field_extension_length` byte (count of
    /// bytes after it, including reserved padding).
    pub length: u8,
    /// `ltw_flag`.
    pub ltw_flag: bool,
    /// `piecewise_rate_flag`.
    pub piecewise_rate_flag: bool,
    /// `seamless_splice_flag`.
    pub seamless_splice_flag: bool,
    /// `ltw_valid_flag`, when [`Self::ltw_flag`].
    pub ltw_valid_flag: Option<bool>,
    /// 15-bit `ltw_offset`, when [`Self::ltw_flag`]. Meaningful only if
    /// `ltw_valid_flag == Some(true)` per §2.4.3.5.
    pub ltw_offset: Option<u16>,
    /// 22-bit `piecewise_rate` (units of 50 bytes/s · 8 bits/byte ÷ R
    /// per §2.4.3.5), when [`Self::piecewise_rate_flag`].
    pub piecewise_rate: Option<u32>,
    /// 4-bit `splice_type` (§2.4.3.5 / Tables 2-7..2-16), when
    /// [`Self::seamless_splice_flag`].
    pub splice_type: Option<u8>,
    /// 33-bit `DTS_next_AU` (90 kHz units), when
    /// [`Self::seamless_splice_flag`].
    pub dts_next_au: Option<u64>,
}

/// A parsed 188-byte TS packet.
#[derive(Debug, Clone, Copy)]
pub struct TsPacket<'a> {
    /// 13-bit PID identifying the packet's elementary stream / PSI
    /// section.
    pub pid: u16,
    /// `payload_unit_start_indicator` — first byte of payload is the
    /// start of a new PES packet or a PSI section's `pointer_field`.
    pub payload_unit_start: bool,
    /// `transport_error_indicator` — at least one uncorrectable bit
    /// error exists in the packet.
    pub transport_error: bool,
    /// `transport_priority` — payload has higher priority than other
    /// packets with the same PID.
    pub transport_priority: bool,
    /// 2-bit `transport_scrambling_control` field.
    pub transport_scrambling_control: u8,
    /// 4-bit `continuity_counter`.
    pub continuity_counter: u8,
    /// Optional parsed adaptation field. `Some` exactly when
    /// `adaptation_field_control & 0b10 != 0`.
    pub adaptation_field: Option<AdaptationField<'a>>,
    /// Payload slice — bytes after the header and optional adaptation
    /// field. Empty when `adaptation_field_control & 0b01 == 0`.
    pub payload: &'a [u8],
    /// Raw 188-byte packet, including header.
    pub bytes: &'a [u8],
}

impl<'a> TsPacket<'a> {
    /// Parse a 188-byte transport-stream packet.
    ///
    /// Returns [`TsError::Truncated`] if `bytes.len() != 188` and
    /// [`TsError::BadSyncByte`] if byte 0 is not `0x47`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TsError> {
        if bytes.len() < TS_PACKET_LEN {
            return Err(TsError::Truncated {
                what: "TS packet",
                have: bytes.len(),
                need: TS_PACKET_LEN,
            });
        }
        let bytes = &bytes[..TS_PACKET_LEN];
        if bytes[0] != TS_SYNC_BYTE {
            return Err(TsError::BadSyncByte(bytes[0]));
        }

        let b1 = bytes[1];
        let b2 = bytes[2];
        let b3 = bytes[3];

        let transport_error = (b1 & 0b1000_0000) != 0;
        let payload_unit_start = (b1 & 0b0100_0000) != 0;
        let transport_priority = (b1 & 0b0010_0000) != 0;
        let pid = (((b1 & 0b0001_1111) as u16) << 8) | (b2 as u16);
        let transport_scrambling_control = (b3 >> 6) & 0b11;
        let adaptation_field_control = (b3 >> 4) & 0b11;
        let continuity_counter = b3 & 0b1111;

        let has_af = (adaptation_field_control & 0b10) != 0;
        let has_payload = (adaptation_field_control & 0b01) != 0;

        // Cursor into the packet, starting just after the 4-byte
        // header.
        let mut cursor: usize = 4;
        let mut adaptation_field = None;

        if has_af {
            // AF occupies `af_len + 1` bytes (the length byte itself
            // plus `af_len` payload bytes). Cap at the remaining
            // packet size — a malformed AF length is treated as
            // covering the rest of the packet.
            let af_len = bytes[cursor] as usize;
            let af_total = af_len + 1;
            let af_end = cursor.checked_add(af_total).ok_or(TsError::Truncated {
                what: "TS adaptation_field",
                have: bytes.len() - cursor,
                need: af_total,
            })?;
            if af_end > TS_PACKET_LEN {
                return Err(TsError::Truncated {
                    what: "TS adaptation_field",
                    have: TS_PACKET_LEN - cursor,
                    need: af_total,
                });
            }

            let af_raw = &bytes[cursor..af_end];
            adaptation_field = Some(parse_adaptation_field(af_raw)?);
            cursor = af_end;
        }

        let payload = if has_payload {
            &bytes[cursor..]
        } else {
            &[][..]
        };

        Ok(Self {
            pid,
            payload_unit_start,
            transport_error,
            transport_priority,
            transport_scrambling_control,
            continuity_counter,
            adaptation_field,
            payload,
            bytes,
        })
    }
}

fn parse_adaptation_field(raw: &[u8]) -> Result<AdaptationField<'_>, TsError> {
    // raw[0] is adaptation_field_length; raw.len() == length + 1.
    let length = raw[0];
    if length == 0 {
        return Ok(AdaptationField {
            length: 0,
            discontinuity_indicator: false,
            random_access_indicator: false,
            elementary_stream_priority_indicator: false,
            pcr_flag: false,
            opcr_flag: false,
            splicing_point_flag: false,
            transport_private_data_flag: false,
            adaptation_field_extension_flag: false,
            pcr_base: None,
            pcr_extension: None,
            opcr_base: None,
            opcr_extension: None,
            splice_countdown: None,
            transport_private_data: None,
            adaptation_field_extension: None,
            raw,
        });
    }
    if raw.len() < 2 {
        return Err(TsError::Truncated {
            what: "TS adaptation_field flags",
            have: raw.len(),
            need: 2,
        });
    }
    let flags = raw[1];
    let discontinuity_indicator = (flags & 0b1000_0000) != 0;
    let random_access_indicator = (flags & 0b0100_0000) != 0;
    let elementary_stream_priority_indicator = (flags & 0b0010_0000) != 0;
    let pcr_flag = (flags & 0b0001_0000) != 0;
    let opcr_flag = (flags & 0b0000_1000) != 0;
    let splicing_point_flag = (flags & 0b0000_0100) != 0;
    let transport_private_data_flag = (flags & 0b0000_0010) != 0;
    let adaptation_field_extension_flag = (flags & 0b0000_0001) != 0;

    let mut cursor = 2usize;

    // PCR (§2.4.3.5).
    let (pcr_base, pcr_extension) = if pcr_flag {
        let (b, e) = parse_clock_reference(raw, cursor, "TS adaptation_field PCR")?;
        cursor += 6;
        (Some(b), Some(e))
    } else {
        (None, None)
    };

    // OPCR (§2.4.3.5) — same wire shape as PCR.
    let (opcr_base, opcr_extension) = if opcr_flag {
        let (b, e) = parse_clock_reference(raw, cursor, "TS adaptation_field OPCR")?;
        cursor += 6;
        (Some(b), Some(e))
    } else {
        (None, None)
    };

    // splice_countdown — single signed byte (§2.4.3.5).
    let splice_countdown = if splicing_point_flag {
        if cursor + 1 > raw.len() {
            return Err(TsError::Truncated {
                what: "TS adaptation_field splice_countdown",
                have: raw.len() - cursor,
                need: 1,
            });
        }
        let v = raw[cursor] as i8;
        cursor += 1;
        Some(v)
    } else {
        None
    };

    // transport_private_data — 8-bit length + N bytes (§2.4.3.5).
    let transport_private_data = if transport_private_data_flag {
        if cursor + 1 > raw.len() {
            return Err(TsError::Truncated {
                what: "TS adaptation_field transport_private_data_length",
                have: raw.len() - cursor,
                need: 1,
            });
        }
        let n = raw[cursor] as usize;
        cursor += 1;
        let end = cursor.checked_add(n).ok_or(TsError::Truncated {
            what: "TS adaptation_field private_data",
            have: raw.len() - cursor,
            need: n,
        })?;
        if end > raw.len() {
            return Err(TsError::Truncated {
                what: "TS adaptation_field private_data",
                have: raw.len() - cursor,
                need: n,
            });
        }
        let slice = &raw[cursor..end];
        cursor = end;
        Some(slice)
    } else {
        None
    };

    // adaptation_field_extension — variable length, with optional ltw /
    // piecewise_rate / seamless_splice sub-fields (§2.4.3.5).
    let adaptation_field_extension = if adaptation_field_extension_flag {
        Some(parse_extension(raw, &mut cursor)?)
    } else {
        None
    };

    // Trailing bytes (up to raw.len()) are stuffing_byte (0xFF) per
    // Table 2-6 — silently accepted.
    let _ = cursor;

    Ok(AdaptationField {
        length,
        discontinuity_indicator,
        random_access_indicator,
        elementary_stream_priority_indicator,
        pcr_flag,
        opcr_flag,
        splicing_point_flag,
        transport_private_data_flag,
        adaptation_field_extension_flag,
        pcr_base,
        pcr_extension,
        opcr_base,
        opcr_extension,
        splice_countdown,
        transport_private_data,
        adaptation_field_extension,
        raw,
    })
}

/// Decode a 6-byte program_clock_reference (33-bit base + 6 reserved +
/// 9-bit extension) at `raw[cursor..]`.
fn parse_clock_reference(
    raw: &[u8],
    cursor: usize,
    what: &'static str,
) -> Result<(u64, u16), TsError> {
    if cursor + 6 > raw.len() {
        return Err(TsError::Truncated {
            what,
            have: raw.len() - cursor,
            need: 6,
        });
    }
    let p = &raw[cursor..cursor + 6];
    let base: u64 = ((p[0] as u64) << 25)
        | ((p[1] as u64) << 17)
        | ((p[2] as u64) << 9)
        | ((p[3] as u64) << 1)
        | (((p[4] >> 7) & 0b1) as u64);
    let ext: u16 = (((p[4] & 0b0000_0001) as u16) << 8) | (p[5] as u16);
    Ok((base, ext))
}

fn parse_extension(raw: &[u8], cursor: &mut usize) -> Result<AdaptationFieldExtension, TsError> {
    if *cursor + 1 > raw.len() {
        return Err(TsError::Truncated {
            what: "TS adaptation_field_extension_length",
            have: raw.len() - *cursor,
            need: 1,
        });
    }
    let ext_len = raw[*cursor] as usize;
    *cursor += 1;
    let ext_end = cursor.checked_add(ext_len).ok_or(TsError::Truncated {
        what: "TS adaptation_field_extension body",
        have: raw.len() - *cursor,
        need: ext_len,
    })?;
    if ext_end > raw.len() {
        return Err(TsError::Truncated {
            what: "TS adaptation_field_extension body",
            have: raw.len() - *cursor,
            need: ext_len,
        });
    }
    // The flag byte counts toward ext_len; need at least 1.
    if ext_len < 1 {
        // Spec-permitted zero-length extension: just yield the header
        // sentinel; everything below stays defaulted.
        return Ok(AdaptationFieldExtension {
            length: 0,
            ..Default::default()
        });
    }
    let flags = raw[*cursor];
    *cursor += 1;
    let body_end = ext_end; // hard ceiling for the sub-fields below.
    let ltw_flag = (flags & 0b1000_0000) != 0;
    let piecewise_rate_flag = (flags & 0b0100_0000) != 0;
    let seamless_splice_flag = (flags & 0b0010_0000) != 0;

    let (ltw_valid_flag, ltw_offset) = if ltw_flag {
        if *cursor + 2 > body_end {
            return Err(TsError::Truncated {
                what: "TS adaptation_field ltw",
                have: body_end - *cursor,
                need: 2,
            });
        }
        let b0 = raw[*cursor];
        let b1 = raw[*cursor + 1];
        *cursor += 2;
        let valid = (b0 & 0b1000_0000) != 0;
        let offset = (((b0 & 0b0111_1111) as u16) << 8) | (b1 as u16);
        (Some(valid), Some(offset))
    } else {
        (None, None)
    };

    let piecewise_rate = if piecewise_rate_flag {
        if *cursor + 3 > body_end {
            return Err(TsError::Truncated {
                what: "TS adaptation_field piecewise_rate",
                have: body_end - *cursor,
                need: 3,
            });
        }
        let p0 = raw[*cursor] & 0b0011_1111;
        let p1 = raw[*cursor + 1];
        let p2 = raw[*cursor + 2];
        *cursor += 3;
        Some(((p0 as u32) << 16) | ((p1 as u32) << 8) | (p2 as u32))
    } else {
        None
    };

    let (splice_type, dts_next_au) = if seamless_splice_flag {
        if *cursor + 5 > body_end {
            return Err(TsError::Truncated {
                what: "TS adaptation_field seamless_splice",
                have: body_end - *cursor,
                need: 5,
            });
        }
        // Layout: splice_type (4) | DTS[32..30] (3) | marker (1)
        //         DTS[29..22] (8)
        //         DTS[21..15] (7) | marker (1)
        //         DTS[14..7]  (8)
        //         DTS[6..0]   (7) | marker (1)
        let b0 = raw[*cursor];
        let b1 = raw[*cursor + 1];
        let b2 = raw[*cursor + 2];
        let b3 = raw[*cursor + 3];
        let b4 = raw[*cursor + 4];
        *cursor += 5;
        let stype = (b0 >> 4) & 0b1111;
        let dts: u64 = (((b0 >> 1) & 0b0000_0111) as u64) << 30
            | (b1 as u64) << 22
            | (((b2 >> 1) & 0b0111_1111) as u64) << 15
            | (b3 as u64) << 7
            | (((b4 >> 1) & 0b0111_1111) as u64);
        (Some(stype), Some(dts))
    } else {
        (None, None)
    };

    // Reserved padding fills the rest of the extension body — skip it.
    *cursor = body_end;

    Ok(AdaptationFieldExtension {
        length: ext_len as u8,
        ltw_flag,
        piecewise_rate_flag,
        seamless_splice_flag,
        ltw_valid_flag,
        ltw_offset,
        piecewise_rate,
        splice_type,
        dts_next_au,
    })
}

/// Iterator over a contiguous sequence of 188-byte TS packets.
#[derive(Debug)]
pub struct TsPacketIter<'a> {
    rest: &'a [u8],
    halted: bool,
}

impl<'a> Iterator for TsPacketIter<'a> {
    type Item = Result<TsPacket<'a>, TsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.halted || self.rest.len() < TS_PACKET_LEN {
            return None;
        }
        let (head, tail) = self.rest.split_at(TS_PACKET_LEN);
        self.rest = tail;
        match TsPacket::parse(head) {
            Ok(pkt) => Some(Ok(pkt)),
            Err(e) => {
                // Stop iteration after the first malformed packet —
                // the caller decided this slice was contiguous TS,
                // so a bad sync byte means we've lost alignment.
                self.halted = true;
                Some(Err(e))
            }
        }
    }
}

/// Walk a contiguous byte slice of 188-byte TS packets.
///
/// Stops cleanly at a truncated tail (returns no further items) and
/// halts at the first malformed sync byte after yielding the
/// [`TsError::BadSyncByte`] error.
pub fn iter_packets(bytes: &[u8]) -> TsPacketIter<'_> {
    TsPacketIter {
        rest: bytes,
        halted: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 188-byte packet from a 4-byte header and a tail. The
    /// tail is padded with `0xFF` up to 184 bytes.
    fn make_packet(header: [u8; 4], tail: &[u8]) -> Vec<u8> {
        assert!(tail.len() <= 184);
        let mut v = Vec::with_capacity(TS_PACKET_LEN);
        v.extend_from_slice(&header);
        v.extend_from_slice(tail);
        v.resize(TS_PACKET_LEN, 0xFF);
        v
    }

    #[test]
    fn bare_audio_packet_payload_only() {
        // PID = 0x1100, PUSI = 1, AF control = 0b01 (payload only),
        // CC = 5.
        let header = [
            0x47,
            0b0100_0001, // PUSI=1, PID hi = 0x01
            0x00,        // PID lo = 0x00 → PID = 0x100
            0b0001_0101, // scrambling=0, AF=0b01, CC=5
        ];
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let bytes = make_packet(header, &payload);
        let pkt = TsPacket::parse(&bytes).unwrap();
        assert_eq!(pkt.pid, 0x0100);
        assert!(pkt.payload_unit_start);
        assert!(!pkt.transport_error);
        assert_eq!(pkt.continuity_counter, 5);
        assert!(pkt.adaptation_field.is_none());
        // Payload covers bytes 4..188.
        assert_eq!(pkt.payload.len(), 184);
        assert_eq!(&pkt.payload[..4], &payload);
    }

    #[test]
    fn packet_with_adaptation_field_and_pcr() {
        // AF carries a PCR. We choose:
        //   PCR base = 0x1_2345_6789  (33 bits, fits in u64)
        //   PCR ext  = 0x0AB           (9 bits, fits in u16)
        let base: u64 = 0x1_2345_6789;
        let ext: u16 = 0x0AB;
        // 6 PCR bytes: base[32..25] base[24..17] base[16..9] base[8..1]
        // [base0 (1)|reserved 0b111111|ext_hi (1)]  [ext_lo (8)]
        let p0 = ((base >> 25) & 0xFF) as u8;
        let p1 = ((base >> 17) & 0xFF) as u8;
        let p2 = ((base >> 9) & 0xFF) as u8;
        let p3 = ((base >> 1) & 0xFF) as u8;
        let p4 = (((base & 0b1) as u8) << 7) | 0b0111_1110 | (((ext >> 8) & 0b1) as u8);
        let p5 = (ext & 0xFF) as u8;

        // AF: length=7 (1 flags byte + 6 PCR bytes), flags=0x50 (RAI=1,
        // PCR=1), then 6 PCR bytes.
        let af_len: u8 = 1 + 6;
        let af = [af_len, 0b0101_0000, p0, p1, p2, p3, p4, p5];

        // Header: PID = 0x100, PUSI=0, AF control = 0b11 (AF + payload),
        // CC = 0xA.
        let header = [0x47, 0x01, 0x00, 0b0011_1010];

        // Payload tail: a few "PES start" bytes for flavour.
        let mut tail = Vec::new();
        tail.extend_from_slice(&af);
        tail.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0]);

        let bytes = make_packet(header, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        assert_eq!(pkt.pid, 0x0100);
        assert!(!pkt.payload_unit_start);
        assert_eq!(pkt.continuity_counter, 0xA);
        let af = pkt.adaptation_field.expect("af present");
        assert_eq!(af.length, 7);
        assert!(af.random_access_indicator);
        assert!(af.pcr_flag);
        assert_eq!(af.pcr_base, Some(base));
        assert_eq!(af.pcr_extension, Some(ext));
        // Payload starts after header (4 bytes) + AF (8 bytes).
        assert_eq!(pkt.payload.len(), TS_PACKET_LEN - 4 - 8);
        assert_eq!(&pkt.payload[..4], &[0x00, 0x00, 0x01, 0xE0]);
    }

    #[test]
    fn af_only_packet_has_empty_payload() {
        // AF control = 0b10 (AF only, no payload). AF length 183 ⇒ AF
        // occupies all of bytes 4..188 (length byte + 183 stuffing).
        let header = [0x47, 0x01, 0x00, 0b0010_0000];
        // AF: length=183, flags=0, then 182 stuffing bytes 0xFF.
        let mut tail = Vec::new();
        tail.push(183);
        tail.push(0);
        tail.extend(std::iter::repeat(0xFF).take(182));
        let bytes = make_packet(header, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        assert!(pkt.adaptation_field.is_some());
        assert_eq!(pkt.adaptation_field.unwrap().length, 183);
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn wrong_sync_byte_iterator_halts() {
        let good_header = [0x47, 0x01, 0x00, 0b0001_0000];
        let good = make_packet(good_header, &[]);
        let mut bad = good.clone();
        bad[0] = 0x48; // wrong sync
        let mut buf = Vec::new();
        buf.extend_from_slice(&good);
        buf.extend_from_slice(&bad);
        buf.extend_from_slice(&good);

        let mut it = iter_packets(&buf);
        let first = it.next().unwrap().unwrap();
        assert_eq!(first.pid, 0x0100);
        let second = it.next().unwrap();
        match second {
            Err(TsError::BadSyncByte(0x48)) => {}
            other => panic!("expected BadSyncByte(0x48), got {other:?}"),
        }
        // After a sync break the iterator yields no more items.
        assert!(it.next().is_none());
    }

    #[test]
    fn truncated_tail_yields_nothing_extra() {
        let good_header = [0x47, 0x00, 0x00, 0b0001_0000];
        let good = make_packet(good_header, &[]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&good);
        buf.extend_from_slice(&[0x47, 0x00]); // 2 stray bytes
        let mut it = iter_packets(&buf);
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().is_none());
    }

    /// Encode a 6-byte program_clock_reference (33-bit base + 6 reserved
    /// ones + 9-bit extension) per §2.4.3.5.
    fn encode_clock_reference(base: u64, ext: u16) -> [u8; 6] {
        let b0 = ((base >> 25) & 0xFF) as u8;
        let b1 = ((base >> 17) & 0xFF) as u8;
        let b2 = ((base >> 9) & 0xFF) as u8;
        let b3 = ((base >> 1) & 0xFF) as u8;
        let b4 = (((base & 0b1) as u8) << 7) | 0b0111_1110 | (((ext >> 8) & 0b1) as u8);
        let b5 = (ext & 0xFF) as u8;
        [b0, b1, b2, b3, b4, b5]
    }

    /// Wrap a custom adaptation-field payload (everything after the
    /// flags byte) into a 188-byte TS packet whose AF_control = 0b11.
    fn ts_packet_with_af(af_flags: u8, af_tail: &[u8]) -> Vec<u8> {
        // af_len counts the flags byte + tail.
        let af_len = (1 + af_tail.len()) as u8;
        let header = [0x47, 0x01, 0x00, 0b0011_0000];
        let mut tail = Vec::new();
        tail.push(af_len);
        tail.push(af_flags);
        tail.extend_from_slice(af_tail);
        make_packet(header, &tail)
    }

    #[test]
    fn af_opcr_unpacked() {
        // PCR + OPCR — same wire shape, different base/ext values.
        let pcr_base: u64 = 0x0_0000_0001;
        let pcr_ext: u16 = 0x000;
        let opcr_base: u64 = 0x1_FEDC_BA98;
        let opcr_ext: u16 = 0x1FE;
        let mut tail = Vec::new();
        tail.extend_from_slice(&encode_clock_reference(pcr_base, pcr_ext));
        tail.extend_from_slice(&encode_clock_reference(opcr_base, opcr_ext));
        // flags: PCR + OPCR.
        let bytes = ts_packet_with_af(0b0001_1000, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let af = pkt.adaptation_field.expect("af");
        assert_eq!(af.pcr_base, Some(pcr_base));
        assert_eq!(af.pcr_extension, Some(pcr_ext));
        assert_eq!(af.opcr_base, Some(opcr_base));
        assert_eq!(af.opcr_extension, Some(opcr_ext));
    }

    #[test]
    fn af_splice_countdown_signed() {
        // splicing_point_flag only — single signed byte.
        let bytes = ts_packet_with_af(0b0000_0100, &[(-3i8) as u8]);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let af = pkt.adaptation_field.expect("af");
        assert!(af.splicing_point_flag);
        assert_eq!(af.splice_countdown, Some(-3));
    }

    #[test]
    fn af_transport_private_data() {
        // transport_private_data_flag — 1-byte length + payload.
        let payload: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let mut tail = Vec::new();
        tail.push(payload.len() as u8);
        tail.extend_from_slice(payload);
        let bytes = ts_packet_with_af(0b0000_0010, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let af = pkt.adaptation_field.expect("af");
        assert!(af.transport_private_data_flag);
        assert_eq!(af.transport_private_data, Some(payload));
    }

    #[test]
    fn af_extension_with_ltw_and_piecewise_rate() {
        // Extension: ltw_flag + piecewise_rate_flag, no seamless_splice.
        // ltw_valid_flag=1, ltw_offset=0x1234. piecewise_rate=0x2A_3B4C.
        // ext_len = flags(1) + ltw(2) + piecewise(3) = 6.
        let ltw_offset: u16 = 0x1234;
        let b0 = 0b1000_0000 | ((ltw_offset >> 8) & 0x7F) as u8;
        let b1 = (ltw_offset & 0xFF) as u8;
        let pwr: u32 = 0x2A_3B4C;
        let p0 = ((pwr >> 16) & 0x3F) as u8 | 0b1100_0000; // reserved=11
        let p1 = ((pwr >> 8) & 0xFF) as u8;
        let p2 = (pwr & 0xFF) as u8;
        let tail = vec![
            6,           // adaptation_field_extension_length
            0b1100_0000, // ltw + piecewise, no seamless
            b0,
            b1,
            p0,
            p1,
            p2,
        ];
        // flag = adaptation_field_extension_flag only.
        let bytes = ts_packet_with_af(0b0000_0001, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let af = pkt.adaptation_field.expect("af");
        let ext = af.adaptation_field_extension.expect("ext");
        assert_eq!(ext.length, 6);
        assert!(ext.ltw_flag);
        assert!(ext.piecewise_rate_flag);
        assert!(!ext.seamless_splice_flag);
        assert_eq!(ext.ltw_valid_flag, Some(true));
        assert_eq!(ext.ltw_offset, Some(0x1234));
        assert_eq!(ext.piecewise_rate, Some(0x2A_3B4C));
        assert_eq!(ext.splice_type, None);
        assert_eq!(ext.dts_next_au, None);
    }

    #[test]
    fn af_extension_seamless_splice_dts() {
        // seamless_splice only. splice_type = 5, DTS_next_AU = some
        // 33-bit value. ext_len = flags(1) + seamless(5) = 6.
        let dts: u64 = 0x1_2345_6789;
        let splice_type: u8 = 5;
        let b0 = (splice_type << 4) | (((dts >> 30) & 0b0111) as u8) << 1 | 0b1;
        let b1 = ((dts >> 22) & 0xFF) as u8;
        let b2 = (((dts >> 15) & 0b0111_1111) as u8) << 1 | 0b1;
        let b3 = ((dts >> 7) & 0xFF) as u8;
        let b4 = (((dts & 0b0111_1111) as u8) << 1) | 0b1;
        let mut tail = Vec::new();
        tail.push(6); // ext_len
        tail.push(0b0010_0000); // seamless_splice only
        tail.extend_from_slice(&[b0, b1, b2, b3, b4]);
        let bytes = ts_packet_with_af(0b0000_0001, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let ext = pkt
            .adaptation_field
            .unwrap()
            .adaptation_field_extension
            .expect("ext");
        assert!(ext.seamless_splice_flag);
        assert_eq!(ext.splice_type, Some(splice_type));
        assert_eq!(ext.dts_next_au, Some(dts));
    }

    #[test]
    fn af_extension_with_reserved_padding_is_accepted() {
        // ext_len = 4: flags(1) + ltw(2) + 1 byte of reserved padding.
        // Parser must not error and must skip the padding.
        let ltw_offset: u16 = 0x0ABC;
        let b0 = ((ltw_offset >> 8) & 0x7F) as u8; // ltw_valid=0
        let b1 = (ltw_offset & 0xFF) as u8;
        let tail = vec![
            4,           // ext_len includes flags + ltw + padding
            0b1000_0000, // ltw only
            b0,
            b1,
            0xFF, // reserved padding
        ];
        let bytes = ts_packet_with_af(0b0000_0001, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let ext = pkt
            .adaptation_field
            .unwrap()
            .adaptation_field_extension
            .expect("ext");
        assert_eq!(ext.length, 4);
        assert!(ext.ltw_flag);
        assert_eq!(ext.ltw_valid_flag, Some(false));
        assert_eq!(ext.ltw_offset, Some(0x0ABC));
    }

    #[test]
    fn af_all_optional_subfields_together() {
        // Every flag set; the AF carries PCR + OPCR + splice_countdown +
        // 2-byte transport_private_data + a minimal extension with
        // ltw_flag only. Verifies cursor ordering through the §2.4.3.4
        // production.
        let pcr_base: u64 = 100;
        let pcr_ext: u16 = 50;
        let opcr_base: u64 = 200;
        let opcr_ext: u16 = 60;
        let priv_data: &[u8] = &[0xAB, 0xCD];
        let mut tail = Vec::new();
        tail.extend_from_slice(&encode_clock_reference(pcr_base, pcr_ext));
        tail.extend_from_slice(&encode_clock_reference(opcr_base, opcr_ext));
        tail.push(7i8 as u8); // splice_countdown
        tail.push(priv_data.len() as u8); // transport_private_data_length
        tail.extend_from_slice(priv_data);
        // Extension: ext_len = flags(1) + ltw(2) = 3, ltw_valid=0,
        // ltw_offset = 0.
        tail.push(3);
        tail.push(0b1000_0000);
        tail.push(0x00);
        tail.push(0x00);
        let bytes = ts_packet_with_af(0b0001_1111, &tail);
        let pkt = TsPacket::parse(&bytes).unwrap();
        let af = pkt.adaptation_field.expect("af");
        assert_eq!(af.pcr_base, Some(pcr_base));
        assert_eq!(af.opcr_base, Some(opcr_base));
        assert_eq!(af.opcr_extension, Some(opcr_ext));
        assert_eq!(af.splice_countdown, Some(7));
        assert_eq!(af.transport_private_data, Some(priv_data));
        let ext = af.adaptation_field_extension.expect("ext");
        assert_eq!(ext.length, 3);
        assert_eq!(ext.ltw_valid_flag, Some(false));
        assert_eq!(ext.ltw_offset, Some(0));
    }

    #[test]
    fn af_extension_truncated_body_errors() {
        // ext_len claims 5 but only flags + 1 byte present in AF.
        let tail = vec![
            5,           // ext_len
            0b1000_0000, // ltw_flag set
            0x00,        // only one byte where ltw needs two
        ];
        let af_len = (1 + tail.len()) as u8;
        let header = [0x47, 0x01, 0x00, 0b0011_0000];
        let mut packet_tail = Vec::new();
        packet_tail.push(af_len);
        packet_tail.push(0b0000_0001);
        packet_tail.extend_from_slice(&tail);
        let bytes = make_packet(header, &packet_tail);
        let err = TsPacket::parse(&bytes).unwrap_err();
        match err {
            TsError::Truncated { .. } => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
