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
pub(crate) fn has_optional_pes_header(stream_id: u8) -> bool {
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
    /// [`Self::trick_mode`] decodes it per §2.4.3.7 Tables 2-20..2-22.
    pub dsm_trick_mode: Option<u8>,
    /// 7-bit `additional_copy_info`, when present.
    pub additional_copy_info: Option<u8>,
    /// 16-bit `previous_PES_packet_CRC` value, when present.
    pub previous_pes_packet_crc: Option<u16>,
    /// Decoded `PES_extension` body, present exactly when the
    /// `PES_extension_flag` was set in the header (Table 2-17,
    /// concluded). `pes_extension.is_some()` is the old
    /// "extension present" signal; the sub-fields are now decoded.
    pub pes_extension: Option<PesExtension>,
    /// `true` when a TS-level `random_access_indicator` (§2.4.3.5)
    /// announced this PES packet — i.e. the indicator was set on the
    /// TS packet this PES started in, or on a preceding same-PID
    /// packet after the previous PES start ("the next PES packet to
    /// start in the payload of Transport Stream packets with the
    /// current PID"). Set by [`PesReassembler`]; always `false` from a
    /// bare [`PesPacket::parse`], which sees no TS-layer flags.
    pub random_access: bool,
    /// Elementary-stream payload bytes (after the optional PES header).
    pub payload: Vec<u8>,
}

/// Decoded `PES_extension` body — the flag-gated tail of the optional
/// PES header per ISO/IEC 13818-1 Table 2-17 (concluded) / §2.4.3.7.
///
/// Wire layout when `PES_extension_flag == 1`:
///
/// ```text
/// PES_private_data_flag (1) | pack_header_field_flag (1) |
/// program_packet_sequence_counter_flag (1) | P-STD_buffer_flag (1) |
/// reserved (3) | PES_extension_flag_2 (1) |
/// [PES_private_data (128)] |
/// [pack_field_length (8) + pack_header()] |
/// [marker (1) + program_packet_sequence_counter (7) +
///  marker (1) + MPEG1_MPEG2_identifier (1) + original_stuff_length (6)] |
/// ['01' (2) + P-STD_buffer_scale (1) + P-STD_buffer_size (13)] |
/// [marker (1) + PES_extension_field_length (7) + reserved bytes]
/// ```
///
/// Each `Option` field maps to one of the five sub-flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PesExtension {
    /// 16-byte `PES_private_data` (§2.4.3.7: private data that,
    /// combined with surrounding fields, must not emulate the
    /// `packet_start_code_prefix`).
    pub private_data: Option<[u8; 16]>,
    /// Raw `pack_header()` bytes (an ISO/IEC 11172-1 or Program Stream
    /// pack header carried verbatim; `pack_field_length` gives its
    /// size). Always `None` in a conforming Program Stream; this crate
    /// surfaces the bytes without interpreting them.
    pub pack_header: Option<Vec<u8>>,
    /// `program_packet_sequence_counter` group, when present.
    pub program_packet_sequence_counter: Option<ProgramPacketSequenceCounter>,
    /// `P-STD_buffer_scale` / `P-STD_buffer_size` pair, when present.
    pub p_std_buffer: Option<PStdBuffer>,
    /// Raw bytes of the `PES_extension_flag_2` field — in this edition
    /// of the spec every one of the `PES_extension_field_length` bytes
    /// is `reserved`, so they are surfaced verbatim.
    pub extension_field_2: Option<Vec<u8>>,
}

/// `program_packet_sequence_counter` group (Table 2-17, concluded) — an
/// optional 7-bit per-program PES packet counter providing continuity-
/// counter-like functionality across a Program Stream or ISO/IEC
/// 11172-1 stream carried in PES packets (§2.4.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramPacketSequenceCounter {
    /// 7-bit counter; wraps to 0 past its maximum. No two consecutive
    /// PES packets in the program multiplex may carry the same value.
    pub counter: u8,
    /// `MPEG1_MPEG2_identifier` — `true` when this PES packet carries
    /// information from an ISO/IEC 11172-1 stream, `false` for a
    /// Program Stream.
    pub mpeg1_mpeg2_identifier: bool,
    /// 6-bit `original_stuff_length` — number of stuffing bytes used
    /// in the original PES packet header (or original ISO/IEC 11172-1
    /// packet header).
    pub original_stuff_length: u8,
}

/// `P-STD_buffer_scale` + `P-STD_buffer_size` pair (Table 2-17,
/// concluded). Semantics are only defined when the PES packet is
/// carried in a Program Stream (§2.4.3.7): the pair sizes the P-STD
/// input buffer BSn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PStdBuffer {
    /// `P-STD_buffer_scale` — scaling factor for `size`: `false` ⇒
    /// units of 128 bytes (required for audio stream_ids), `true` ⇒
    /// units of 1024 bytes (required for video stream_ids).
    pub scale: bool,
    /// 13-bit `P-STD_buffer_size`, in units selected by `scale`.
    pub size: u16,
}

impl PStdBuffer {
    /// Buffer size in bytes: `size * 128` when `scale` is clear,
    /// `size * 1024` when set (§2.4.3.7).
    pub fn size_bytes(&self) -> u32 {
        u32::from(self.size) * if self.scale { 1024 } else { 128 }
    }
}

/// `field_id` — which field(s) of a picture to display in a trick
/// mode (§2.4.3.7 Table 2-21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    /// `'00'` — display from top field only.
    TopFieldOnly,
    /// `'01'` — display from bottom field only.
    BottomFieldOnly,
    /// `'10'` — display complete frame.
    CompleteFrame,
    /// `'11'` — reserved.
    Reserved,
}

impl FieldId {
    fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0b00 => Self::TopFieldOnly,
            0b01 => Self::BottomFieldOnly,
            0b10 => Self::CompleteFrame,
            _ => Self::Reserved,
        }
    }

    /// The 2-bit Table 2-21 code.
    pub fn to_bits(self) -> u8 {
        match self {
            Self::TopFieldOnly => 0b00,
            Self::BottomFieldOnly => 0b01,
            Self::CompleteFrame => 0b10,
            Self::Reserved => 0b11,
        }
    }
}

/// `frequency_truncation` — which restricted coefficient set may have
/// been used to code the video in this PES packet (§2.4.3.7
/// Table 2-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoefficientSelection {
    /// `'00'` — only DC coefficients are non-zero.
    DcOnly,
    /// `'01'` — only the first three coefficients are non-zero.
    FirstThree,
    /// `'10'` — only the first six coefficients are non-zero.
    FirstSix,
    /// `'11'` — all coefficients may be non-zero.
    All,
}

impl CoefficientSelection {
    fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0b00 => Self::DcOnly,
            0b01 => Self::FirstThree,
            0b10 => Self::FirstSix,
            _ => Self::All,
        }
    }

    /// The 2-bit Table 2-22 code.
    pub fn to_bits(self) -> u8 {
        match self {
            Self::DcOnly => 0b00,
            Self::FirstThree => 0b01,
            Self::FirstSix => 0b10,
            Self::All => 0b11,
        }
    }
}

/// Decoded `DSM_trick_mode` byte (§2.4.3.7): the 3-bit
/// `trick_mode_control` (Table 2-20) plus the mode-specific bottom
/// five bits. The field describes the trick mode applied to the
/// associated **video** stream; for other elementary-stream types the
/// byte's meaning is undefined (surface the raw byte instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsmTrickMode {
    /// `'000'` — fast-forward video stream.
    FastForward {
        /// Which field(s) to display (Table 2-21).
        field_id: FieldId,
        /// Coded slices may skip macroblocks; the decoder may
        /// substitute co-sited macroblocks of previous pictures.
        intra_slice_refresh: bool,
        /// Restricted coefficient set (Table 2-22).
        frequency_truncation: CoefficientSelection,
    },
    /// `'001'` — slow-motion video stream: display each picture
    /// `N × rep_cntrl` picture/field durations (§2.4.3.7).
    SlowMotion {
        /// 5-bit repeat control; the value `0` is forbidden.
        rep_cntrl: u8,
    },
    /// `'010'` — freeze-frame video stream. `field_id` refers to the
    /// first video access unit commencing in this PES packet (or the
    /// most recent one, for a zero-payload PES).
    FreezeFrame {
        /// Which field(s) to display (Table 2-21).
        field_id: FieldId,
    },
    /// `'011'` — fast-reverse video stream (same sub-fields as
    /// fast-forward).
    FastReverse {
        /// Which field(s) to display (Table 2-21).
        field_id: FieldId,
        /// Coded slices may skip macroblocks; the decoder may
        /// substitute co-sited macroblocks of previous pictures.
        intra_slice_refresh: bool,
        /// Restricted coefficient set (Table 2-22).
        frequency_truncation: CoefficientSelection,
    },
    /// `'100'` — slow-reverse video stream.
    SlowReverse {
        /// 5-bit repeat control; the value `0` is forbidden.
        rep_cntrl: u8,
    },
    /// `'101'..'111'` — reserved `trick_mode_control` values; the
    /// bottom five bits are surfaced raw.
    Reserved {
        /// The reserved 3-bit `trick_mode_control` value (5..=7).
        trick_mode_control: u8,
        /// The mode-specific bottom five bits, verbatim.
        bits: u8,
    },
}

impl DsmTrickMode {
    /// Decode a raw `DSM_trick_mode` byte (`trick_mode_control` in the
    /// top 3 bits, mode-specific tail in the bottom 5).
    pub fn from_byte(b: u8) -> Self {
        let tail = b & 0x1F;
        match (b >> 5) & 0b111 {
            0b000 => Self::FastForward {
                field_id: FieldId::from_bits(tail >> 3),
                intra_slice_refresh: (tail & 0b100) != 0,
                frequency_truncation: CoefficientSelection::from_bits(tail),
            },
            0b001 => Self::SlowMotion { rep_cntrl: tail },
            0b010 => Self::FreezeFrame {
                field_id: FieldId::from_bits(tail >> 3),
            },
            0b011 => Self::FastReverse {
                field_id: FieldId::from_bits(tail >> 3),
                intra_slice_refresh: (tail & 0b100) != 0,
                frequency_truncation: CoefficientSelection::from_bits(tail),
            },
            0b100 => Self::SlowReverse { rep_cntrl: tail },
            control => Self::Reserved {
                trick_mode_control: control,
                bits: tail,
            },
        }
    }

    /// Encode back to the wire byte. Freeze-frame's three reserved
    /// bits are emitted as `'111'`; a `rep_cntrl` wider than 5 bits is
    /// masked. `from_byte(x).to_byte()` preserves every meaningful
    /// bit.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::FastForward {
                field_id,
                intra_slice_refresh,
                frequency_truncation,
            } => {
                (field_id.to_bits() << 3)
                    | (u8::from(intra_slice_refresh) << 2)
                    | frequency_truncation.to_bits()
            }
            Self::SlowMotion { rep_cntrl } => (0b001 << 5) | (rep_cntrl & 0x1F),
            Self::FreezeFrame { field_id } => (0b010 << 5) | (field_id.to_bits() << 3) | 0b111,
            Self::FastReverse {
                field_id,
                intra_slice_refresh,
                frequency_truncation,
            } => {
                (0b011 << 5)
                    | (field_id.to_bits() << 3)
                    | (u8::from(intra_slice_refresh) << 2)
                    | frequency_truncation.to_bits()
            }
            Self::SlowReverse { rep_cntrl } => (0b100 << 5) | (rep_cntrl & 0x1F),
            Self::Reserved {
                trick_mode_control,
                bits,
            } => ((trick_mode_control & 0b111) << 5) | (bits & 0x1F),
        }
    }
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
                pes_extension: None,
                random_access: false,
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
        // PES_extension body (Table 2-17, concluded). Bounded by
        // `pes_header_data_length`; anything after it up to
        // `header_end` is stuffing.
        let pes_extension = if pes_extension_flag {
            let (ext, used) = PesExtension::parse(&opt[cursor..])?;
            cursor += used;
            Some(ext)
        } else {
            None
        };
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
            pes_extension,
            random_access: false,
            payload: bytes[header_end..].to_vec(),
        })
    }
}

impl PesPacket {
    /// Decode the `DSM_trick_mode` byte into its typed §2.4.3.7 view
    /// (Table 2-20 `trick_mode_control` + the mode-specific
    /// `field_id` / `intra_slice_refresh` / `frequency_truncation` /
    /// `rep_cntrl` bits). `None` when the header carried no trick-mode
    /// field. Meaningful for video elementary streams only — the spec
    /// leaves the bits undefined for other stream types, so callers of
    /// non-video PIDs should stick to the raw
    /// [`Self::dsm_trick_mode`] byte.
    pub fn trick_mode(&self) -> Option<DsmTrickMode> {
        self.dsm_trick_mode.map(DsmTrickMode::from_byte)
    }
}

impl PesExtension {
    /// Parse a `PES_extension` body from the head of `b` (the bytes
    /// remaining in the optional-header area once the earlier
    /// flag-gated fields have been consumed). Returns the decoded
    /// extension and the number of bytes it occupied.
    fn parse(b: &[u8]) -> Result<(Self, usize), TsError> {
        if b.is_empty() {
            return Err(TsError::Truncated {
                what: "PES extension flags",
                have: 0,
                need: 1,
            });
        }
        // PES_private_data_flag (1) | pack_header_field_flag (1) |
        // program_packet_sequence_counter_flag (1) | P-STD_buffer_flag (1) |
        // reserved (3) | PES_extension_flag_2 (1).
        let flags = b[0];
        let private_data_flag = (flags & 0b1000_0000) != 0;
        let pack_header_field_flag = (flags & 0b0100_0000) != 0;
        let ppsc_flag = (flags & 0b0010_0000) != 0;
        let p_std_buffer_flag = (flags & 0b0001_0000) != 0;
        let extension_flag_2 = (flags & 0b0000_0001) != 0;
        let mut cursor = 1usize;

        let mut ext = Self::default();
        if private_data_flag {
            if b.len() < cursor + 16 {
                return Err(TsError::Truncated {
                    what: "PES_private_data",
                    have: b.len(),
                    need: cursor + 16,
                });
            }
            let mut pd = [0u8; 16];
            pd.copy_from_slice(&b[cursor..cursor + 16]);
            ext.private_data = Some(pd);
            cursor += 16;
        }
        if pack_header_field_flag {
            if b.len() < cursor + 1 {
                return Err(TsError::Truncated {
                    what: "pack_field_length",
                    have: b.len(),
                    need: cursor + 1,
                });
            }
            let pack_field_length = b[cursor] as usize;
            cursor += 1;
            if b.len() < cursor + pack_field_length {
                return Err(TsError::Truncated {
                    what: "pack_header",
                    have: b.len(),
                    need: cursor + pack_field_length,
                });
            }
            ext.pack_header = Some(b[cursor..cursor + pack_field_length].to_vec());
            cursor += pack_field_length;
        }
        if ppsc_flag {
            if b.len() < cursor + 2 {
                return Err(TsError::Truncated {
                    what: "program_packet_sequence_counter",
                    have: b.len(),
                    need: cursor + 2,
                });
            }
            // marker (1) | program_packet_sequence_counter (7),
            // marker (1) | MPEG1_MPEG2_identifier (1) |
            // original_stuff_length (6).
            ext.program_packet_sequence_counter = Some(ProgramPacketSequenceCounter {
                counter: b[cursor] & 0x7F,
                mpeg1_mpeg2_identifier: (b[cursor + 1] & 0b0100_0000) != 0,
                original_stuff_length: b[cursor + 1] & 0x3F,
            });
            cursor += 2;
        }
        if p_std_buffer_flag {
            if b.len() < cursor + 2 {
                return Err(TsError::Truncated {
                    what: "P-STD_buffer",
                    have: b.len(),
                    need: cursor + 2,
                });
            }
            // '01' (2) | P-STD_buffer_scale (1) | P-STD_buffer_size (13).
            ext.p_std_buffer = Some(PStdBuffer {
                scale: (b[cursor] & 0b0010_0000) != 0,
                size: (u16::from(b[cursor] & 0x1F) << 8) | u16::from(b[cursor + 1]),
            });
            cursor += 2;
        }
        if extension_flag_2 {
            if b.len() < cursor + 1 {
                return Err(TsError::Truncated {
                    what: "PES_extension_field_length",
                    have: b.len(),
                    need: cursor + 1,
                });
            }
            // marker (1) | PES_extension_field_length (7), then that
            // many reserved bytes (surfaced verbatim).
            let len = (b[cursor] & 0x7F) as usize;
            cursor += 1;
            if b.len() < cursor + len {
                return Err(TsError::Truncated {
                    what: "PES_extension_field",
                    have: b.len(),
                    need: cursor + len,
                });
            }
            ext.extension_field_2 = Some(b[cursor..cursor + len].to_vec());
            cursor += len;
        }
        Ok((ext, cursor))
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
    /// `random_access_indicator` state for the in-flight PES in `buf`
    /// — the indicator seen on the TS packet the PES started in, or on
    /// a preceding same-PID packet (§2.4.3.5: the indicator announces
    /// "the next PES packet to start").
    current_rai: bool,
    /// A `random_access_indicator` observed *after* the current PES
    /// start (e.g. on a payload-less PCR carrier packet interleaved
    /// mid-PES); it applies to the next PES to start.
    pending_rai: bool,
}

impl PesReassembler {
    /// Create an empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next TS packet (must have the same PID as the prior
    /// feeds). Returns `Some(PesPacket)` when a complete PES packet
    /// has been finalised by this packet's PUSI=1.
    ///
    /// The TS packet's `random_access_indicator` (§2.4.3.5) is folded
    /// into the emitted [`PesPacket::random_access`]: the indicator
    /// marks the next PES packet to start on the PID, so a flag on the
    /// starting packet — or on any same-PID packet since the previous
    /// start — tags the PES that begins at the next PUSI.
    pub fn feed(&mut self, ts: &TsPacket<'_>) -> Result<Option<PesPacket>, TsError> {
        let rai = ts
            .adaptation_field
            .as_ref()
            .is_some_and(|af| af.random_access_indicator);
        if ts.payload_unit_start {
            // The arriving PES packet's PUSI=1 closes the prior PES
            // packet (if any).
            let finished = if self.started {
                let mut pes = PesPacket::parse(&self.buf)?;
                pes.random_access = self.current_rai;
                Some(pes)
            } else {
                None
            };
            self.buf.clear();
            self.buf.extend_from_slice(ts.payload);
            self.started = true;
            // The PES starting here is announced by an indicator on
            // this very packet or one seen since the previous start.
            self.current_rai = self.pending_rai || rai;
            self.pending_rai = false;
            Ok(finished)
        } else {
            if rai {
                // Announces the *next* PES to start on this PID.
                self.pending_rai = true;
            }
            if self.started {
                self.buf.extend_from_slice(ts.payload);
            }
            // Continuation bytes before we've seen the first PUSI=1
            // are discarded — per spec we can't anchor the packet yet.
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
        let mut pes = PesPacket::parse(&buf)?;
        pes.random_access = self.current_rai;
        self.current_rai = false;
        Ok(Some(pes))
    }
}

/// Write-side specification of a PES packet header — the mirror of
/// the [`PesPacket`] parse surface for every §2.4.3.7 Table 2-17
/// optional field. [`Self::encode`] emits a complete PES packet
/// (start code through payload) that reads back identically through
/// [`PesPacket::parse`].
#[derive(Debug, Clone, Default)]
pub struct PesHeaderSpec {
    /// `stream_id` (Table 2-18). The header-less IDs
    /// (program_stream_map, padding_stream, private_stream_2, ECM,
    /// EMM, program_stream_directory, DSM-CC, H.222.1 type E) encode
    /// without the optional header; every field below is then
    /// rejected if set.
    pub stream_id: u8,
    /// 2-bit `PES_scrambling_control` (Table 2-19).
    pub pes_scrambling_control: u8,
    /// `PES_priority`.
    pub pes_priority: bool,
    /// `data_alignment_indicator`.
    pub data_alignment_indicator: bool,
    /// `copyright`.
    pub copyright: bool,
    /// `original_or_copy`.
    pub original_or_copy: bool,
    /// 33-bit PTS (90 kHz).
    pub pts_90k: Option<u64>,
    /// 33-bit DTS (90 kHz). Legal only alongside a PTS it differs
    /// from — §2.7.5: a DTS shall appear iff a PTS is present and the
    /// decoding time differs.
    pub dts_90k: Option<u64>,
    /// 42-bit ESCR as a composed 27 MHz tick count
    /// (`base × 300 + extension`, equation 2-13).
    pub escr_27mhz: Option<u64>,
    /// 22-bit `ES_rate` in 50 bytes/s units. The value 0 is forbidden
    /// (§2.4.3.7).
    pub es_rate_50bps: Option<u32>,
    /// DSM trick mode (encoded via [`DsmTrickMode::to_byte`]).
    pub trick_mode: Option<DsmTrickMode>,
    /// 7-bit `additional_copy_info`.
    pub additional_copy_info: Option<u8>,
    /// 16-bit `previous_PES_packet_CRC`.
    pub previous_pes_packet_crc: Option<u16>,
    /// `PES_extension` body — the parsed [`PesExtension`] doubles as
    /// the write spec.
    pub pes_extension: Option<PesExtension>,
    /// Emit `PES_packet_length = 0` (unbounded). Only legal for the
    /// video stream_ids `0xE0..=0xEF` carried in a Transport Stream
    /// (§2.4.3.7); rejected otherwise.
    pub unbounded_length: bool,
}

impl PesHeaderSpec {
    /// Convenience: a header with just a PTS (and optionally a DTS).
    pub fn with_timestamps(stream_id: u8, pts_90k: u64, dts_90k: Option<u64>) -> Self {
        Self {
            stream_id,
            pts_90k: Some(pts_90k),
            dts_90k,
            ..Default::default()
        }
    }

    /// Encode a complete PES packet: `packet_start_code_prefix`,
    /// `stream_id`, `PES_packet_length`, the optional header per
    /// Table 2-17, then `payload`.
    ///
    /// Returns [`TsError::InvalidField`] for spec-violating requests:
    /// field-width overflows, a DTS without a PTS (or equal to it,
    /// §2.7.5), a zero `ES_rate`, optional fields on a header-less
    /// `stream_id`, an optional-header area over the 8-bit
    /// `PES_header_data_length` budget, `unbounded_length` on a
    /// non-video `stream_id`, or a bounded packet whose length
    /// overflows the 16-bit `PES_packet_length` field.
    pub fn encode(&self, payload: &[u8]) -> Result<Vec<u8>, TsError> {
        if !has_optional_pes_header(self.stream_id) {
            if self.pts_90k.is_some()
                || self.dts_90k.is_some()
                || self.escr_27mhz.is_some()
                || self.es_rate_50bps.is_some()
                || self.trick_mode.is_some()
                || self.additional_copy_info.is_some()
                || self.previous_pes_packet_crc.is_some()
                || self.pes_extension.is_some()
            {
                return Err(TsError::InvalidField {
                    what: "optional PES fields on a header-less stream_id",
                });
            }
            let len = u16::try_from(payload.len()).map_err(|_| TsError::InvalidField {
                what: "PES payload exceeds PES_packet_length",
            })?;
            let mut out = Vec::with_capacity(6 + payload.len());
            out.extend_from_slice(&[0x00, 0x00, 0x01, self.stream_id]);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
            return Ok(out);
        }

        // ---- Validate field widths + pairings. ----
        if self.pes_scrambling_control > 0b11 {
            return Err(TsError::InvalidField {
                what: "PES_scrambling_control exceeds 2 bits",
            });
        }
        if let Some(pts) = self.pts_90k {
            if pts > 0x1_FFFF_FFFF {
                return Err(TsError::InvalidField {
                    what: "PTS exceeds 33 bits",
                });
            }
        }
        if let Some(dts) = self.dts_90k {
            if dts > 0x1_FFFF_FFFF {
                return Err(TsError::InvalidField {
                    what: "DTS exceeds 33 bits",
                });
            }
            match self.pts_90k {
                None => {
                    return Err(TsError::InvalidField {
                        what: "DTS without PTS",
                    })
                }
                Some(pts) if pts == dts => {
                    // §2.7.5: a DTS shall appear only when the
                    // decoding time differs from the presentation
                    // time.
                    return Err(TsError::InvalidField {
                        what: "DTS equal to PTS shall not be coded",
                    });
                }
                Some(_) => {}
            }
        }
        if let Some(escr) = self.escr_27mhz {
            if escr / 300 > 0x1_FFFF_FFFF {
                return Err(TsError::InvalidField {
                    what: "ESCR base exceeds 33 bits",
                });
            }
        }
        if let Some(rate) = self.es_rate_50bps {
            if rate == 0 {
                return Err(TsError::InvalidField {
                    what: "ES_rate value 0 is forbidden",
                });
            }
            if rate > 0x3F_FFFF {
                return Err(TsError::InvalidField {
                    what: "ES_rate exceeds 22 bits",
                });
            }
        }
        if let Some(aci) = self.additional_copy_info {
            if aci > 0x7F {
                return Err(TsError::InvalidField {
                    what: "additional_copy_info exceeds 7 bits",
                });
            }
        }

        // ---- Optional header body. ----
        let mut opt = Vec::new();
        let pts_dts_flags: u8 = match (self.pts_90k, self.dts_90k) {
            (Some(pts), Some(dts)) => {
                opt.extend_from_slice(&encode_ts33(0b0011, pts));
                opt.extend_from_slice(&encode_ts33(0b0001, dts));
                0b11
            }
            (Some(pts), None) => {
                opt.extend_from_slice(&encode_ts33(0b0010, pts));
                0b10
            }
            (None, None) => 0b00,
            (None, Some(_)) => unreachable!("rejected above"),
        };
        if let Some(escr) = self.escr_27mhz {
            opt.extend_from_slice(&encode_escr(escr));
        }
        if let Some(rate) = self.es_rate_50bps {
            // marker | ES_rate(22) | marker.
            opt.push(0b1000_0000 | ((rate >> 15) & 0x7F) as u8);
            opt.push(((rate >> 7) & 0xFF) as u8);
            opt.push((((rate & 0x7F) as u8) << 1) | 1);
        }
        if let Some(tm) = self.trick_mode {
            opt.push(tm.to_byte());
        }
        if let Some(aci) = self.additional_copy_info {
            opt.push(0b1000_0000 | aci); // marker | 7 bits
        }
        if let Some(crc) = self.previous_pes_packet_crc {
            opt.extend_from_slice(&crc.to_be_bytes());
        }
        if let Some(ext) = &self.pes_extension {
            encode_pes_extension(ext, &mut opt)?;
        }
        let header_data_length = u8::try_from(opt.len()).map_err(|_| TsError::InvalidField {
            what: "optional PES header exceeds PES_header_data_length",
        })?;

        // ---- PES_packet_length (bytes after the length field). ----
        let tail_len = 3 + opt.len() + payload.len();
        let pes_packet_length: u16 = if self.unbounded_length {
            if !(0xE0..=0xEF).contains(&self.stream_id) {
                return Err(TsError::InvalidField {
                    what: "unbounded PES_packet_length on a non-video stream_id",
                });
            }
            0
        } else {
            u16::try_from(tail_len).map_err(|_| TsError::InvalidField {
                what: "PES packet exceeds PES_packet_length (use unbounded_length)",
            })?
        };

        let mut out = Vec::with_capacity(9 + opt.len() + payload.len());
        out.extend_from_slice(&[0x00, 0x00, 0x01, self.stream_id]);
        out.extend_from_slice(&pes_packet_length.to_be_bytes());
        out.push(
            0b1000_0000
                | (self.pes_scrambling_control << 4)
                | (u8::from(self.pes_priority) << 3)
                | (u8::from(self.data_alignment_indicator) << 2)
                | (u8::from(self.copyright) << 1)
                | u8::from(self.original_or_copy),
        );
        out.push(
            (pts_dts_flags << 6)
                | (u8::from(self.escr_27mhz.is_some()) << 5)
                | (u8::from(self.es_rate_50bps.is_some()) << 4)
                | (u8::from(self.trick_mode.is_some()) << 3)
                | (u8::from(self.additional_copy_info.is_some()) << 2)
                | (u8::from(self.previous_pes_packet_crc.is_some()) << 1)
                | u8::from(self.pes_extension.is_some()),
        );
        out.push(header_data_length);
        out.extend_from_slice(&opt);
        out.extend_from_slice(payload);
        Ok(out)
    }
}

/// Encode a 33-bit PTS/DTS into the 5-byte Table 2-17 form with the
/// given 4-bit prefix (`0010` lone PTS, `0011` PTS of a pair, `0001`
/// DTS).
fn encode_ts33(prefix: u8, ts: u64) -> [u8; 5] {
    let t = ts & 0x1_FFFF_FFFF;
    [
        (prefix << 4) | ((((t >> 30) & 0b111) as u8) << 1) | 1,
        ((t >> 22) & 0xFF) as u8,
        ((((t >> 15) & 0x7F) as u8) << 1) | 1,
        ((t >> 7) & 0xFF) as u8,
        (((t & 0x7F) as u8) << 1) | 1,
    ]
}

/// Encode a composed 27 MHz ESCR (`base × 300 + extension`) into the
/// 6-byte Table 2-17 field — the inverse of the internal decoder.
/// Reserved bits are written as `1`.
fn encode_escr(escr_27mhz: u64) -> [u8; 6] {
    let base = escr_27mhz / 300;
    let ext = escr_27mhz % 300;
    let b32_30 = ((base >> 30) & 0b111) as u8;
    let b29_28 = ((base >> 28) & 0b11) as u8;
    let b27_20 = ((base >> 20) & 0xFF) as u8;
    let b19_15 = ((base >> 15) & 0x1F) as u8;
    let b14_13 = ((base >> 13) & 0b11) as u8;
    let b12_5 = ((base >> 5) & 0xFF) as u8;
    let b4_0 = (base & 0x1F) as u8;
    let e8_7 = ((ext >> 7) & 0b11) as u8;
    let e6_0 = (ext & 0x7F) as u8;
    [
        0b1100_0000 | (b32_30 << 3) | 0b100 | b29_28,
        b27_20,
        (b19_15 << 3) | 0b100 | b14_13,
        b12_5,
        (b4_0 << 3) | 0b100 | e8_7,
        (e6_0 << 1) | 1,
    ]
}

/// Append the `PES_extension` body (Table 2-17, concluded) for `ext`
/// to `out`, validating field widths.
fn encode_pes_extension(ext: &PesExtension, out: &mut Vec<u8>) -> Result<(), TsError> {
    if let Some(ppsc) = &ext.program_packet_sequence_counter {
        if ppsc.counter > 0x7F {
            return Err(TsError::InvalidField {
                what: "program_packet_sequence_counter exceeds 7 bits",
            });
        }
        if ppsc.original_stuff_length > 0x3F {
            return Err(TsError::InvalidField {
                what: "original_stuff_length exceeds 6 bits",
            });
        }
    }
    if let Some(p_std) = &ext.p_std_buffer {
        if p_std.size > 0x1FFF {
            return Err(TsError::InvalidField {
                what: "P-STD_buffer_size exceeds 13 bits",
            });
        }
    }
    if let Some(pack) = &ext.pack_header {
        if pack.len() > 255 {
            return Err(TsError::InvalidField {
                what: "pack_header exceeds pack_field_length",
            });
        }
    }
    if let Some(f2) = &ext.extension_field_2 {
        if f2.len() > 0x7F {
            return Err(TsError::InvalidField {
                what: "PES_extension_field_2 exceeds 7 bits of length",
            });
        }
    }
    out.push(
        (u8::from(ext.private_data.is_some()) << 7)
            | (u8::from(ext.pack_header.is_some()) << 6)
            | (u8::from(ext.program_packet_sequence_counter.is_some()) << 5)
            | (u8::from(ext.p_std_buffer.is_some()) << 4)
            | 0b0000_1110 // reserved bits written as 1
            | u8::from(ext.extension_field_2.is_some()),
    );
    if let Some(pd) = &ext.private_data {
        out.extend_from_slice(pd);
    }
    if let Some(pack) = &ext.pack_header {
        out.push(pack.len() as u8);
        out.extend_from_slice(pack);
    }
    if let Some(ppsc) = &ext.program_packet_sequence_counter {
        out.push(0b1000_0000 | ppsc.counter);
        out.push(
            0b1000_0000 | (u8::from(ppsc.mpeg1_mpeg2_identifier) << 6) | ppsc.original_stuff_length,
        );
    }
    if let Some(p_std) = &ext.p_std_buffer {
        out.push(0b0100_0000 | (u8::from(p_std.scale) << 5) | ((p_std.size >> 8) as u8 & 0x1F));
        out.push(p_std.size as u8);
    }
    if let Some(f2) = &ext.extension_field_2 {
        out.push(0b1000_0000 | (f2.len() as u8));
        out.extend_from_slice(f2);
    }
    Ok(())
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
        // Extension flag set with an all-zero sub-flag byte ⇒ present
        // but every sub-field absent.
        assert_eq!(p.pes_extension, Some(PesExtension::default()));
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
        assert!(p.pes_extension.is_none());
        // Flag bits in the all-zero flags1 byte we set.
        assert!(!p.pes_priority);
        assert!(!p.copyright);
        assert_eq!(p.pes_scrambling_control, 0);
    }

    /// Wrap a raw PES_extension body (sub-flag byte + gated fields)
    /// into a minimal video PES packet whose only optional field is
    /// the extension.
    fn build_pes_with_extension(ext_body: &[u8]) -> Vec<u8> {
        let payload = b"data";
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        let pes_packet_length: u16 = (3 + ext_body.len() + payload.len()) as u16;
        v.extend_from_slice(&pes_packet_length.to_be_bytes());
        v.push(0b1000_0000); // '10' marker, all flags1 clear
        v.push(0b0000_0001); // only PES_extension_flag set
        v.push(ext_body.len() as u8);
        v.extend_from_slice(ext_body);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn parse_pes_extension_every_sub_field() {
        // Sub-flags: private_data | pack_header | ppsc | P-STD | ext2
        // (reserved bits set to 1 to prove they're ignored).
        let mut ext = vec![0b1111_1111u8];
        let private: [u8; 16] = *b"0123456789ABCDEF";
        ext.extend_from_slice(&private);
        // pack_field_length = 3, then 3 opaque pack_header bytes.
        ext.extend_from_slice(&[3, 0xAA, 0xBB, 0xCC]);
        // marker|counter=0x55, marker|MPEG1_MPEG2=1|orig_stuff_len=0x21.
        ext.push(0b1101_0101);
        ext.push(0b1110_0001);
        // '01' | scale=1 | size=0x1234 (13-bit).
        ext.push(0b0111_0010);
        ext.push(0x34);
        // marker | PES_extension_field_length=2, then 2 reserved bytes.
        ext.push(0b1000_0010);
        ext.extend_from_slice(&[0xDE, 0xAD]);

        let pes = build_pes_with_extension(&ext);
        let p = PesPacket::parse(&pes).unwrap();
        let e = p.pes_extension.expect("extension present");
        assert_eq!(e.private_data, Some(private));
        assert_eq!(e.pack_header.as_deref(), Some(&[0xAA, 0xBB, 0xCC][..]));
        let ppsc = e.program_packet_sequence_counter.unwrap();
        assert_eq!(ppsc.counter, 0x55);
        assert!(ppsc.mpeg1_mpeg2_identifier);
        assert_eq!(ppsc.original_stuff_length, 0x21);
        let pstd = e.p_std_buffer.unwrap();
        assert!(pstd.scale);
        assert_eq!(pstd.size, 0x1234);
        assert_eq!(pstd.size_bytes(), 0x1234 * 1024);
        assert_eq!(e.extension_field_2.as_deref(), Some(&[0xDE, 0xAD][..]));
        assert_eq!(p.payload, b"data");
    }

    #[test]
    fn parse_pes_extension_p_std_scale_clear_units_128() {
        // Only the P-STD_buffer pair: '01' | scale=0 | size=10.
        let ext = [0b0001_0000u8, 0b0100_0000, 10];
        let pes = build_pes_with_extension(&ext);
        let p = PesPacket::parse(&pes).unwrap();
        let pstd = p.pes_extension.unwrap().p_std_buffer.unwrap();
        assert!(!pstd.scale);
        assert_eq!(pstd.size, 10);
        assert_eq!(pstd.size_bytes(), 1280);
    }

    #[test]
    fn parse_pes_extension_truncated_private_data_rejected() {
        // private_data flag set but only 4 of the 16 bytes present.
        let ext = [0b1000_0000u8, 1, 2, 3, 4];
        let pes = build_pes_with_extension(&ext);
        let err = PesPacket::parse(&pes).unwrap_err();
        match err {
            TsError::Truncated { what, .. } => assert_eq!(what, "PES_private_data"),
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_pes_extension_truncated_field_2_rejected() {
        // ext2 flag set, PES_extension_field_length = 5 but no bytes.
        let ext = [0b0000_0001u8, 0b1000_0101];
        let pes = build_pes_with_extension(&ext);
        let err = PesPacket::parse(&pes).unwrap_err();
        match err {
            TsError::Truncated { what, .. } => assert_eq!(what, "PES_extension_field"),
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rai_marks_the_pes_starting_in_the_flagged_packet() {
        // Two PES packets on one PID; the second's start packet
        // carries a random_access_indicator. Only the second emitted
        // PesPacket must have `random_access == true`.
        let pid = 0x101;
        let pes1 = build_pes(0xE0, 1000, b"first");
        let pes2 = build_pes(0xE0, 2000, b"second");
        let ts1 = pes_into_ts(pid, &pes1, 184);
        // Hand-build pes2's single TS packet with an AF carrying RAI:
        // header(4) + AF {len, flags(RAI), 0xFF stuffing} + PES bytes.
        let mut ts2 = vec![
            TS_SYNC_BYTE,
            0b0100_0000 | ((pid >> 8) as u8 & 0x1F),
            (pid & 0xFF) as u8,
            0b0011_0000, // AF + payload, cc=0
        ];
        let af_total = TS_PACKET_LEN - 4 - pes2.len();
        ts2.push((af_total - 1) as u8);
        ts2.push(0b0100_0000); // random_access_indicator
        ts2.extend(std::iter::repeat(0xFF).take(af_total - 2));
        ts2.extend_from_slice(&pes2);
        assert_eq!(ts2.len(), TS_PACKET_LEN);

        let mut r = PesReassembler::new();
        let mut emitted = Vec::new();
        for chunk in ts1.chunks(TS_PACKET_LEN).chain(ts2.chunks(TS_PACKET_LEN)) {
            let pkt = TsPacket::parse(chunk).unwrap();
            if let Some(pes) = r.feed(&pkt).unwrap() {
                emitted.push(pes);
            }
        }
        if let Some(pes) = r.flush().unwrap() {
            emitted.push(pes);
        }
        assert_eq!(emitted.len(), 2);
        assert!(!emitted[0].random_access, "first PES was not announced");
        assert!(emitted[1].random_access, "second PES start carried RAI");
        assert_eq!(emitted[1].payload, b"second");
    }

    #[test]
    fn rai_on_payloadless_carrier_packet_marks_next_pes() {
        // §2.4.3.5: the indicator announces "the next PES packet to
        // start" — it may ride a payload-less (e.g. PCR-only) packet
        // ahead of the PES start.
        let pid = 0x101;
        let pes = build_pes(0xE0, 5000, b"announced");

        // AF-only packet with RAI, no payload.
        let mut carrier = vec![
            TS_SYNC_BYTE,
            (pid >> 8) as u8 & 0x1F,
            (pid & 0xFF) as u8,
            0b0010_0000, // AF only, cc=0
            183,         // adaptation_field_length spans the packet
            0b0100_0000, // random_access_indicator
        ];
        carrier.extend(std::iter::repeat(0xFF).take(TS_PACKET_LEN - carrier.len()));

        let start = pes_into_ts(pid, &pes, 184);

        let mut r = PesReassembler::new();
        let mut emitted = Vec::new();
        for chunk in carrier
            .chunks(TS_PACKET_LEN)
            .chain(start.chunks(TS_PACKET_LEN))
        {
            let pkt = TsPacket::parse(chunk).unwrap();
            if let Some(p) = r.feed(&pkt).unwrap() {
                emitted.push(p);
            }
        }
        if let Some(p) = r.flush().unwrap() {
            emitted.push(p);
        }
        assert_eq!(emitted.len(), 1);
        assert!(emitted[0].random_access);
        assert_eq!(emitted[0].payload, b"announced");
    }

    #[test]
    fn trick_mode_decodes_all_five_modes() {
        // fast_forward '000' | field_id '10' | refresh 1 | trunc '01'
        assert_eq!(
            DsmTrickMode::from_byte(0b0001_0101),
            DsmTrickMode::FastForward {
                field_id: FieldId::CompleteFrame,
                intra_slice_refresh: true,
                frequency_truncation: CoefficientSelection::FirstThree,
            }
        );
        // slow_motion '001' | rep_cntrl 0b10110 (22)
        assert_eq!(
            DsmTrickMode::from_byte(0b0011_0110),
            DsmTrickMode::SlowMotion { rep_cntrl: 22 }
        );
        // freeze_frame '010' | field_id '01' | reserved '101' (ignored)
        assert_eq!(
            DsmTrickMode::from_byte(0b0100_1101),
            DsmTrickMode::FreezeFrame {
                field_id: FieldId::BottomFieldOnly,
            }
        );
        // fast_reverse '011' | field_id '00' | refresh 0 | trunc '11'
        assert_eq!(
            DsmTrickMode::from_byte(0b0110_0011),
            DsmTrickMode::FastReverse {
                field_id: FieldId::TopFieldOnly,
                intra_slice_refresh: false,
                frequency_truncation: CoefficientSelection::All,
            }
        );
        // slow_reverse '100' | rep_cntrl 1
        assert_eq!(
            DsmTrickMode::from_byte(0b1000_0001),
            DsmTrickMode::SlowReverse { rep_cntrl: 1 }
        );
        // reserved control values '101'..'111' surface raw.
        assert_eq!(
            DsmTrickMode::from_byte(0b1101_0101),
            DsmTrickMode::Reserved {
                trick_mode_control: 0b110,
                bits: 0b10101,
            }
        );
    }

    #[test]
    fn trick_mode_byte_round_trips() {
        // Every byte value: decode → encode must preserve all
        // meaningful bits (freeze_frame's 3 reserved bits and the
        // reserved control values' tails are don't-cares on re-encode,
        // so compare through a second decode).
        for b in 0..=255u8 {
            let decoded = DsmTrickMode::from_byte(b);
            let re = DsmTrickMode::from_byte(decoded.to_byte());
            assert_eq!(decoded, re, "byte {b:#010b} unstable through round-trip");
        }
        // Typed → wire → typed is identity for the spec-defined modes.
        for tm in [
            DsmTrickMode::FastForward {
                field_id: FieldId::Reserved,
                intra_slice_refresh: true,
                frequency_truncation: CoefficientSelection::DcOnly,
            },
            DsmTrickMode::SlowMotion { rep_cntrl: 31 },
            DsmTrickMode::FreezeFrame {
                field_id: FieldId::CompleteFrame,
            },
            DsmTrickMode::FastReverse {
                field_id: FieldId::BottomFieldOnly,
                intra_slice_refresh: false,
                frequency_truncation: CoefficientSelection::FirstSix,
            },
            DsmTrickMode::SlowReverse { rep_cntrl: 7 },
        ] {
            assert_eq!(DsmTrickMode::from_byte(tm.to_byte()), tm);
        }
    }

    #[test]
    fn trick_mode_field_parses_from_pes_header() {
        // PES header with DSM_trick_mode_flag set: flags2 bit 3.
        let payload = b"vid";
        let trick = 0b0001_0101u8; // fast_forward, complete frame
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x00, 0x01, 0xE0]);
        let pes_packet_length: u16 = (3 + 1 + payload.len()) as u16;
        v.extend_from_slice(&pes_packet_length.to_be_bytes());
        v.push(0b1000_0000);
        v.push(0b0000_1000); // DSM_trick_mode_flag only
        v.push(1); // PES_header_data_length = 1 (the trick byte)
        v.push(trick);
        v.extend_from_slice(payload);
        let parsed = PesPacket::parse(&v).unwrap();
        assert_eq!(parsed.dsm_trick_mode, Some(trick));
        assert_eq!(
            parsed.trick_mode(),
            Some(DsmTrickMode::FastForward {
                field_id: FieldId::CompleteFrame,
                intra_slice_refresh: true,
                frequency_truncation: CoefficientSelection::FirstThree,
            })
        );
        assert_eq!(parsed.payload, payload);
        // No trick-mode field → None.
        let plain = build_pes(0xE0, 1234, b"x");
        assert_eq!(PesPacket::parse(&plain).unwrap().trick_mode(), None);
    }

    #[test]
    fn pes_header_spec_full_house_round_trips() {
        let spec = PesHeaderSpec {
            stream_id: 0xE0,
            pes_scrambling_control: 0b10,
            pes_priority: true,
            data_alignment_indicator: true,
            copyright: true,
            original_or_copy: true,
            pts_90k: Some(0x1_2345_6789),
            dts_90k: Some(0x1_2345_0000),
            escr_27mhz: Some(0x1_FFFF_FFFF * 300 + 299),
            es_rate_50bps: Some(0x3F_FFFF),
            trick_mode: Some(DsmTrickMode::SlowMotion { rep_cntrl: 5 }),
            additional_copy_info: Some(0x55),
            previous_pes_packet_crc: Some(0xBEEF),
            pes_extension: Some(PesExtension {
                private_data: Some([0xA5; 16]),
                pack_header: Some(vec![0x01, 0x02, 0x03]),
                program_packet_sequence_counter: Some(ProgramPacketSequenceCounter {
                    counter: 0x7F,
                    mpeg1_mpeg2_identifier: true,
                    original_stuff_length: 0x3F,
                }),
                p_std_buffer: Some(PStdBuffer {
                    scale: true,
                    size: 0x1FFF,
                }),
                extension_field_2: Some(vec![0xEE; 7]),
            }),
            unbounded_length: false,
        };
        let payload = b"elementary bytes";
        let bytes = spec.encode(payload).unwrap();
        let parsed = PesPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.stream_id, 0xE0);
        assert_eq!(parsed.pes_scrambling_control, 0b10);
        assert!(parsed.pes_priority);
        assert!(parsed.data_alignment_indicator);
        assert!(parsed.copyright);
        assert!(parsed.original_or_copy);
        assert_eq!(parsed.pts_90k, Some(0x1_2345_6789));
        assert_eq!(parsed.dts_90k, Some(0x1_2345_0000));
        assert_eq!(parsed.escr_27mhz, Some(0x1_FFFF_FFFF * 300 + 299));
        assert_eq!(parsed.es_rate_50bps, Some(0x3F_FFFF));
        assert_eq!(
            parsed.trick_mode(),
            Some(DsmTrickMode::SlowMotion { rep_cntrl: 5 })
        );
        assert_eq!(parsed.additional_copy_info, Some(0x55));
        assert_eq!(parsed.previous_pes_packet_crc, Some(0xBEEF));
        assert_eq!(parsed.pes_extension, spec.pes_extension);
        assert_eq!(parsed.payload, payload);
        // Bounded length covers flags + optional header + payload.
        let expect_len = (bytes.len() - 6) as u16;
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), expect_len);
    }

    #[test]
    fn pes_header_spec_unbounded_and_headerless_forms() {
        // Unbounded video form: PES_packet_length = 0.
        let spec = PesHeaderSpec {
            unbounded_length: true,
            ..PesHeaderSpec::with_timestamps(0xE0, 90_000, None)
        };
        let bytes = spec.encode(&[0xAA; 32]).unwrap();
        assert_eq!(&bytes[4..6], &[0, 0]);
        assert_eq!(PesPacket::parse(&bytes).unwrap().pts_90k, Some(90_000));

        // Header-less stream id (private_stream_2): payload directly
        // after the 6-byte fixed header.
        let spec = PesHeaderSpec {
            stream_id: 0xBF,
            ..Default::default()
        };
        let bytes = spec.encode(b"raw").unwrap();
        assert_eq!(bytes.len(), 9);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 3);
        let parsed = PesPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.payload, b"raw");
        assert_eq!(parsed.pts_90k, None);
    }

    #[test]
    fn pes_header_spec_rejects_spec_violations() {
        let base = |f: fn(&mut PesHeaderSpec)| {
            let mut s = PesHeaderSpec {
                stream_id: 0xC0,
                ..Default::default()
            };
            f(&mut s);
            s
        };
        for spec in [
            base(|s| s.dts_90k = Some(100)), // DTS without PTS
            base(|s| {
                s.pts_90k = Some(100);
                s.dts_90k = Some(100); // DTS == PTS (§2.7.5)
            }),
            base(|s| s.pts_90k = Some(1 << 33)), // PTS width
            base(|s| s.escr_27mhz = Some((1u64 << 33) * 300)), // ESCR width
            base(|s| s.es_rate_50bps = Some(0)), // forbidden 0
            base(|s| s.es_rate_50bps = Some(0x40_0000)), // rate width
            base(|s| s.additional_copy_info = Some(0x80)), // 7-bit
            base(|s| s.pes_scrambling_control = 4), // 2-bit
            base(|s| s.unbounded_length = true), // audio id
            base(|s| {
                // header-less id with an optional field
                s.stream_id = 0xBF;
                s.pts_90k = Some(1);
            }),
            base(|s| {
                s.pes_extension = Some(PesExtension {
                    p_std_buffer: Some(PStdBuffer {
                        scale: false,
                        size: 0x2000, // 13-bit overflow
                    }),
                    ..Default::default()
                });
            }),
            base(|s| {
                s.pes_extension = Some(PesExtension {
                    extension_field_2: Some(vec![0; 128]), // 7-bit len
                    ..Default::default()
                });
            }),
            base(|s| {
                // optional area past the 255-byte budget
                s.pts_90k = Some(1);
                s.pes_extension = Some(PesExtension {
                    pack_header: Some(vec![0; 251]),
                    ..Default::default()
                });
            }),
        ] {
            assert!(
                matches!(spec.encode(&[]), Err(TsError::InvalidField { .. })),
                "spec should be rejected: {spec:?}"
            );
        }
        // Bounded audio packet larger than PES_packet_length can hold.
        let spec = PesHeaderSpec {
            stream_id: 0xC0,
            ..Default::default()
        };
        assert!(matches!(
            spec.encode(&vec![0u8; 70_000]),
            Err(TsError::InvalidField { .. })
        ));
    }

    #[test]
    fn escr_encode_decode_round_trips() {
        for escr in [
            0u64,
            1,
            299,
            300,
            90_000 * 300 + 123,
            0x1_FFFF_FFFF * 300 + 299, // maximum
        ] {
            let spec = PesHeaderSpec {
                stream_id: 0xE0,
                escr_27mhz: Some(escr),
                ..Default::default()
            };
            let bytes = spec.encode(b"x").unwrap();
            assert_eq!(
                PesPacket::parse(&bytes).unwrap().escr_27mhz,
                Some(escr),
                "escr {escr}"
            );
        }
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
