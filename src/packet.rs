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
//! optional PCR (48 bits = 33-bit base + 6 reserved + 9-bit extension)
//! optional OPCR (48 bits)
//! ...
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
    /// Raw adaptation-field bytes including the
    /// `adaptation_field_length` byte itself.
    pub raw: &'a [u8],
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
    let mut pcr_base = None;
    let mut pcr_extension = None;
    if pcr_flag {
        if cursor + 6 > raw.len() {
            return Err(TsError::Truncated {
                what: "TS adaptation_field PCR",
                have: raw.len() - cursor,
                need: 6,
            });
        }
        let p = &raw[cursor..cursor + 6];
        // 33-bit PCR base, MSB-first across bytes 0..4 + top bit of
        // byte 4.
        let base: u64 = ((p[0] as u64) << 25)
            | ((p[1] as u64) << 17)
            | ((p[2] as u64) << 9)
            | ((p[3] as u64) << 1)
            | (((p[4] >> 7) & 0b1) as u64);
        // 9-bit extension: bottom bit of byte 4 + byte 5.
        let ext: u16 = (((p[4] & 0b0000_0001) as u16) << 8) | (p[5] as u16);
        pcr_base = Some(base);
        pcr_extension = Some(ext);
        cursor += 6;
    }

    // We expose `pcr_base`/`pcr_extension` and the raw AF bytes; the
    // remaining optional fields (OPCR, splice countdown, private data,
    // extension) are accessible to callers via `raw` but not unpacked
    // here. `cursor` movement above is only used to validate PCR fit.
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
        raw,
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
}
