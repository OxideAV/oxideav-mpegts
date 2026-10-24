//! Audio elementary-stream frame framing — the sync-word + header
//! parse that sizes one access unit of AC-3 / E-AC-3 (ATSC A/52
//! §5.3.1 / §5.4.1 / Annex E §2.2), MPEG-1/2 audio (ISO/IEC 11172-3
//! §2.4.1.3 / ISO/IEC 13818-3 §2.4.2.3) and AAC ADTS (ISO/IEC 13818-7
//! §6.2 Tables 8–9), plus the per-stream [`AudioFrameSplitter`] that
//! cuts a PES payload carrying several frames into one access unit per
//! packet.
//!
//! ## Why a demuxer needs this
//!
//! ISO/IEC 13818-1 lets an audio PES packet carry any number of whole
//! or partial access units (§2.4.3.7 — a PES payload is "data bytes";
//! only the §2.7.5 timestamp rule ties the PTS to the first access
//! unit that *commences* in the packet). Broadcast and camcorder
//! muxers routinely pack 2–8 syncframes per PES. The fleet's packet
//! contract downstream is one access unit per [`oxideav_core::Packet`]
//! (Matroska Blocks and MP4 samples are frames by construction, and the
//! audio decoders consume exactly one syncframe per call), so the
//! demuxer splits here and interpolates the per-frame timestamps from
//! the PES PTS: `pts_k = PTS + k × samples_per_frame × 90 000 / fs`
//! (§2.4.3.7 — PTS is in units of the 27 MHz system clock ÷ 300).
//!
//! ## Spec anchors
//!
//! * AC-3: `syncinfo()` Table 5.1 — `syncword` 0x0B77 (§5.4.1.1),
//!   `crc1`, `fscod` (Table 5.6), `frmsizecod` (Table 5.18 → words per
//!   syncframe, ×2 bytes). `bsi()` Table 5.2 — `bsid`, `bsmod`, `acmod`
//!   (Table 5.8 → `nfchans`), `lfeon` (nchans = nfchans + lfeon). One
//!   syncframe = 6 blocks × 256 = 1536 samples per channel.
//! * E-AC-3 (Annex E): `bsi()` Table E1.2 — `strmtyp`, `substreamid`,
//!   `frmsiz` (words − 1, §2.3.1.3), `fscod` / `fscod2` (Tables
//!   E2.2 / E2.3), `numblkscod` (Table E2.4 → 1/2/3/6 blocks of 256
//!   samples), `acmod`, `lfeon`, `bsid` (16, §2.3.1.6). AC-3 and E-AC-3
//!   share the 0x0B77 syncword; the `bsid` field (bits 0..5 of byte 5 in
//!   both syntaxes) selects the syntax: ≤ 8 AC-3, 11..=16 E-AC-3.
//! * MPEG audio: `header()` (11172-3 §2.4.1.3) — 12-bit `syncword`,
//!   `ID`, `layer`, `protection_bit`, `bitrate_index`,
//!   `sampling_frequency`, `padding_bit`, `mode`. Frame length from the
//!   §2.4.2.3 padding formula: Layer I `(12 × bitrate / fs + padding) ×
//!   4` bytes (4-byte slots), Layers II/III `144 × bitrate / fs +
//!   padding` bytes; 13818-3 §2.4.3.2 changes the Layer III constant to
//!   72 for the lower-sampling-frequency (`ID = 0`) extension whose
//!   frame carries 576 samples. Samples per frame: 384 (Layer I), 1152
//!   (Layers II/III), 576 (13818-3 Layer III).
//! * AAC ADTS: `adts_fixed_header()` Table 8 — 12-bit `syncword`,
//!   `ID`, `layer`, `protection_absent`, `profile`,
//!   `sampling_frequency_index` (Table 35), `channel_configuration`
//!   (Table 42 implicit speaker mapping); `adts_variable_header()`
//!   Table 9 — 13-bit `frame_length` ("length of the frame including
//!   headers and error_check in bytes"), `adts_buffer_fullness`,
//!   `number_of_raw_data_blocks_in_frame` (each raw_data_block is 1024
//!   samples per channel).
//!
//! Formats whose framing is not staged (DTS, TrueHD, LPCM, MPEG-2.5
//! 11-bit-sync audio) are passed through by the splitter untouched —
//! one PES payload stays one packet.

/// Which syntax framed an audio access unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioFrameKind {
    /// ATSC A/52 §5 AC-3 syncframe (`bsid` ≤ 8).
    Ac3,
    /// ATSC A/52 Annex E E-AC-3 syncframe (`bsid` 11..=16).
    Eac3,
    /// ISO/IEC 11172-3 / 13818-3 Layer I frame.
    MpegLayer1,
    /// ISO/IEC 11172-3 / 13818-3 Layer II frame.
    MpegLayer2,
    /// ISO/IEC 11172-3 / 13818-3 Layer III frame.
    MpegLayer3,
    /// ISO/IEC 13818-7 ADTS frame (one or more raw_data_blocks).
    AacAdts,
}

/// Header-derived facts about one audio access unit: its byte length
/// on the wire and the parameters a [`oxideav_core::CodecParameters`]
/// record wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioFrameInfo {
    /// Framing syntax the header matched.
    pub kind: AudioFrameKind,
    /// Total frame length in bytes, header included — the distance to
    /// the next syncword.
    pub frame_len: usize,
    /// PCM samples per channel this frame decodes to.
    pub samples_per_frame: u32,
    /// Sampling frequency in Hz.
    pub sample_rate: u32,
    /// Coded channel count (LFE counted), or `0` when the header does
    /// not say (ADTS `channel_configuration = 0`, PCE-defined).
    pub channels: u16,
    /// Nominal bit rate in bit/s when the header codes one (`None`
    /// for E-AC-3, whose rate follows from `frmsiz`, and for ADTS).
    pub bit_rate: Option<u32>,
}

impl AudioFrameInfo {
    /// Duration of this frame in 90 kHz ticks, rounded to nearest.
    /// `samples × 90 000 / sample_rate` — exact for 32 / 48 kHz
    /// families, fractional (and therefore rounded) for 44.1 kHz.
    pub fn duration_90k(&self) -> u32 {
        if self.sample_rate == 0 {
            return 0;
        }
        let num = self.samples_per_frame as u64 * 90_000 + self.sample_rate as u64 / 2;
        (num / self.sample_rate as u64) as u32
    }
}

/// AC-3 / E-AC-3 syncword (A/52 §5.4.1.1): `0x0B77`.
pub const AC3_SYNCWORD: [u8; 2] = [0x0B, 0x77];

/// Samples per channel in one AC-3 syncframe: 6 audio blocks × 256
/// (A/52 §5.3.3 / §4.3.3 — the frame holds six blocks).
pub const AC3_SAMPLES_PER_SYNCFRAME: u32 = 1536;

/// Table 5.18 — words per syncframe indexed by `frmsizecod`, 48 kHz
/// column (transcribed).
const AC3_FRAME_WORDS_48K: [u16; 38] = [
    64, 64, 80, 80, 96, 96, 112, 112, 128, 128, 160, 160, 192, 192, 224, 224, 256, 256, 320, 320,
    384, 384, 448, 448, 512, 512, 640, 640, 768, 768, 896, 896, 1024, 1024, 1152, 1152, 1280, 1280,
];

/// Table 5.18 — words per syncframe for the 44.1 kHz column (the odd
/// `frmsizecod` of each bit-rate pair is one word longer).
const AC3_FRAME_WORDS_44K: [u16; 38] = [
    69, 70, 87, 88, 104, 105, 121, 122, 139, 140, 174, 175, 208, 209, 243, 244, 278, 279, 348, 349,
    417, 418, 487, 488, 557, 558, 696, 697, 835, 836, 975, 976, 1114, 1115, 1253, 1254, 1393, 1394,
];

/// Table 5.18 — words per syncframe for the 32 kHz column.
const AC3_FRAME_WORDS_32K: [u16; 38] = [
    96, 96, 120, 120, 144, 144, 168, 168, 192, 192, 240, 240, 288, 288, 336, 336, 384, 384, 480,
    480, 576, 576, 672, 672, 768, 768, 960, 960, 1152, 1152, 1344, 1344, 1536, 1536, 1728, 1728,
    1920, 1920,
];

/// Table 5.18 — nominal bit rate (kbit/s) per `frmsizecod >> 1`.
const AC3_BIT_RATE_KBPS: [u16; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];

/// Table 5.8 — `nfchans` (full-bandwidth channels) per `acmod`.
const AC3_NFCHANS: [u16; 8] = [2, 1, 2, 3, 3, 4, 4, 5];

/// Table 5.6 / E2.2 — sampling rate per `fscod` (`'11'` reserved /
/// E-AC-3 `fscod2` escape).
const AC3_SAMPLE_RATE: [u32; 3] = [48_000, 44_100, 32_000];

/// Table E2.3 — reduced sampling rate per `fscod2`.
const EAC3_SAMPLE_RATE2: [u32; 3] = [24_000, 22_050, 16_000];

/// Table E2.4 — audio blocks per syncframe per `numblkscod`.
const EAC3_BLOCKS: [u32; 4] = [1, 2, 3, 6];

/// Parse the head of an AC-3 or E-AC-3 syncframe (A/52 Table 5.1 +
/// Table 5.2 head, or Table E1.2). Needs the first 8 bytes for an
/// exact AC-3 `lfeon` (7 suffice to size the frame; E-AC-3 needs 6). Returns
/// `None` when the syncword is absent, a reserved code is used, or the
/// `bsid` names neither syntax.
pub fn parse_ac3_frame(b: &[u8]) -> Option<AudioFrameInfo> {
    if b.len() < 6 || b[0] != AC3_SYNCWORD[0] || b[1] != AC3_SYNCWORD[1] {
        return None;
    }
    // Both syntaxes place a 5-bit bsid at the top of byte 5: AC-3 after
    // syncword(16) + crc1(16) + fscod(2) + frmsizecod(6) = 40 bits;
    // E-AC-3 after syncword(16) + strmtyp(2) + substreamid(3) +
    // frmsiz(11) + fscod(2) + numblkscod/fscod2(2) + acmod(3) +
    // lfeon(1) = 40 bits.
    let bsid = b[5] >> 3;
    if bsid <= 8 {
        // AC-3 — Table 5.1: fscod = byte4[7:6], frmsizecod = byte4[5:0].
        let fscod = (b[4] >> 6) as usize;
        let frmsizecod = (b[4] & 0x3F) as usize;
        if fscod > 2 || frmsizecod >= 38 {
            return None;
        }
        let words = match fscod {
            0 => AC3_FRAME_WORDS_48K[frmsizecod],
            1 => AC3_FRAME_WORDS_44K[frmsizecod],
            _ => AC3_FRAME_WORDS_32K[frmsizecod],
        } as usize;
        // Table 5.2: bsid(5) bsmod(3) | acmod(3) ... — acmod needs byte 6.
        if b.len() < 7 {
            return None;
        }
        let acmod = (b[6] >> 5) as usize;
        // lfeon's position depends on the conditional mix-level /
        // dsurmod fields between acmod and lfeon (Table 5.2):
        //   cmixlev   2 bits if (acmod & 1) && acmod != 1
        //   surmixlev 2 bits if acmod & 4
        //   dsurmod   2 bits if acmod == 2
        let mut bit = 8 * 6 + 3; // after acmod
        if (acmod & 1) != 0 && acmod != 1 {
            bit += 2;
        }
        if (acmod & 4) != 0 {
            bit += 2;
        }
        if acmod == 2 {
            bit += 2;
        }
        // At most 9 bits past byte 6 → byte 7; a 7-byte head that ends
        // before lfeon reports it absent.
        let lfeon = read_bit(b, bit).unwrap_or(0);
        return Some(AudioFrameInfo {
            kind: AudioFrameKind::Ac3,
            frame_len: words * 2,
            samples_per_frame: AC3_SAMPLES_PER_SYNCFRAME,
            sample_rate: AC3_SAMPLE_RATE[fscod],
            channels: AC3_NFCHANS[acmod] + lfeon as u16,
            bit_rate: Some(AC3_BIT_RATE_KBPS[frmsizecod >> 1] as u32 * 1000),
        });
    }
    if (11..=16).contains(&bsid) {
        // E-AC-3 — Table E1.2 (bit offsets after the 16-bit syncword):
        //   strmtyp 2 | substreamid 3 | frmsiz 11 | fscod 2 |
        //   (fscod2 2 | numblkscod implied 3) or numblkscod 2 |
        //   acmod 3 | lfeon 1 | bsid 5
        let frmsiz = (((b[2] & 0x07) as usize) << 8) | b[3] as usize;
        let fscod = (b[4] >> 6) as usize;
        let code2 = ((b[4] >> 4) & 0x03) as usize;
        let acmod = ((b[4] >> 1) & 0x07) as usize;
        let lfeon = (b[4] & 0x01) as u16;
        let (sample_rate, blocks) = if fscod == 3 {
            if code2 > 2 {
                return None;
            }
            (EAC3_SAMPLE_RATE2[code2], 6)
        } else {
            (AC3_SAMPLE_RATE[fscod], EAC3_BLOCKS[code2])
        };
        return Some(AudioFrameInfo {
            kind: AudioFrameKind::Eac3,
            frame_len: (frmsiz + 1) * 2,
            samples_per_frame: blocks * 256,
            sample_rate,
            channels: AC3_NFCHANS[acmod] + lfeon,
            bit_rate: None,
        });
    }
    None
}

/// Read one bit at absolute bit offset `bit` (MSB-first) from `b`.
fn read_bit(b: &[u8], bit: usize) -> Option<u8> {
    b.get(bit / 8).map(|byte| (byte >> (7 - (bit % 8))) & 1)
}

/// ISO/IEC 11172-3 §2.4.2.3 bitrate table (kbit/s) for `ID = 1`,
/// indexed `[layer_index][bitrate_index]` with layer_index 0 = Layer
/// I, 1 = Layer II, 2 = Layer III. Index 0 is free format, 15
/// forbidden.
const MPEG1_BITRATE_KBPS: [[u16; 16]; 3] = [
    [
        0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0,
    ],
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0,
    ],
    [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
    ],
];

/// ISO/IEC 13818-3 §2.4.2.3 bitrate table (kbit/s) for `ID = 0`
/// (lower sampling frequencies): Layer I column, then the shared
/// Layer II / III column.
const MPEG2_BITRATE_KBPS: [[u16; 16]; 2] = [
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0,
    ],
    [
        0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
    ],
];

/// 11172-3 §2.4.2.3 `sampling_frequency` table for `ID = 1` (Hz);
/// index 3 reserved.
const MPEG1_SAMPLE_RATE: [u32; 3] = [44_100, 48_000, 32_000];

/// 13818-3 §2.4.2.3 `sampling_frequency` table for `ID = 0` (Hz).
const MPEG2_SAMPLE_RATE: [u32; 3] = [22_050, 24_000, 16_000];

/// Parse an MPEG-1 / MPEG-2 (ISO/IEC 11172-3 / 13818-3) audio frame
/// header — the 32-bit `header()` of §2.4.1.3. Needs 4 bytes. Returns
/// `None` for a missing 12-bit syncword, a reserved layer / sampling
/// frequency, the forbidden bitrate index, or free format (whose frame
/// length the header cannot size). The 11-bit-sync "MPEG-2.5"
/// extension is not part of either staged standard and is rejected.
pub fn parse_mpeg_audio_header(b: &[u8]) -> Option<AudioFrameInfo> {
    if b.len() < 4 || b[0] != 0xFF || (b[1] & 0xF0) != 0xF0 {
        return None;
    }
    let id = (b[1] >> 3) & 1; // 1 = 11172-3, 0 = 13818-3 LSF
    let layer_code = (b[1] >> 1) & 0x03; // '11' I, '10' II, '01' III
    let bitrate_index = (b[2] >> 4) as usize;
    let sf_index = ((b[2] >> 2) & 0x03) as usize;
    let padding = ((b[2] >> 1) & 1) as usize;
    let mode = (b[3] >> 6) & 0x03; // '11' single_channel
    if layer_code == 0 || bitrate_index == 0 || bitrate_index == 15 || sf_index == 3 {
        return None;
    }
    let layer_index = (3 - layer_code) as usize; // 0 = I, 1 = II, 2 = III
    let (bitrate_kbps, sample_rate) = if id == 1 {
        (
            MPEG1_BITRATE_KBPS[layer_index][bitrate_index] as u32,
            MPEG1_SAMPLE_RATE[sf_index],
        )
    } else {
        let col = if layer_index == 0 { 0 } else { 1 };
        (
            MPEG2_BITRATE_KBPS[col][bitrate_index] as u32,
            MPEG2_SAMPLE_RATE[sf_index],
        )
    };
    let bitrate = bitrate_kbps * 1000;
    let (frame_len, samples, kind) = match layer_index {
        // Layer I: slots of 4 bytes, 12 × bitrate / fs slots (+ padding).
        0 => (
            (12 * bitrate / sample_rate) as usize * 4 + padding * 4,
            384,
            AudioFrameKind::MpegLayer1,
        ),
        // Layer II: 144 × bitrate / fs bytes (+ padding), 1152 samples.
        1 => (
            (144 * bitrate / sample_rate) as usize + padding,
            1152,
            AudioFrameKind::MpegLayer2,
        ),
        // Layer III: 144 (ID = 1, 1152 samples) or 72 (13818-3 §2.4.3.2
        // lower-sampling-frequency, 576 samples) × bitrate / fs.
        _ => {
            let (slots_per_frame, samples) = if id == 1 { (144, 1152) } else { (72, 576) };
            (
                (slots_per_frame * bitrate / sample_rate) as usize + padding,
                samples,
                AudioFrameKind::MpegLayer3,
            )
        }
    };
    Some(AudioFrameInfo {
        kind,
        frame_len,
        samples_per_frame: samples,
        sample_rate,
        channels: if mode == 0b11 { 1 } else { 2 },
        bit_rate: Some(bitrate),
    })
}

/// ISO/IEC 13818-7 Table 35 — sampling frequency per
/// `sampling_frequency_index` (0x0..=0xB; 0xC..=0xF reserved).
const ADTS_SAMPLE_RATE: [u32; 12] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
];

/// ISO/IEC 13818-7 Table 42 — number of speakers per
/// `channel_configuration` 1..=7 (index 0 = PCE-defined → unknown).
const ADTS_CHANNELS: [u16; 8] = [0, 1, 2, 3, 4, 5, 6, 8];

/// Samples per channel per `raw_data_block()` (13818-7 — the 1024-line
/// AAC frame).
const AAC_SAMPLES_PER_BLOCK: u32 = 1024;

/// Parse an ADTS frame header (ISO/IEC 13818-7 §6.2 Tables 8 + 9).
/// Needs 7 bytes. Returns `None` for a missing 12-bit syncword, a
/// reserved `sampling_frequency_index`, or a `frame_length` shorter
/// than the header itself.
pub fn parse_adts_header(b: &[u8]) -> Option<AudioFrameInfo> {
    if b.len() < 7 || b[0] != 0xFF || (b[1] & 0xF0) != 0xF0 {
        return None;
    }
    // Table 8: syncword(12) ID(1) layer(2) protection_absent(1) |
    // profile(2) sampling_frequency_index(4) private_bit(1)
    // channel_configuration(3) original/copy(1) home(1)
    // Table 9: copyright_identification_bit(1)
    // copyright_identification_start(1) frame_length(13)
    // adts_buffer_fullness(11) number_of_raw_data_blocks_in_frame(2)
    let layer = (b[1] >> 1) & 0x03;
    if layer != 0 {
        // ADTS carries AAC only; a non-zero layer is an MPEG-1 audio
        // header that happens to share the 12-bit syncword.
        return None;
    }
    let protection_absent = b[1] & 1;
    let sf_index = ((b[2] >> 2) & 0x0F) as usize;
    if sf_index >= ADTS_SAMPLE_RATE.len() {
        return None;
    }
    let channel_configuration = (((b[2] & 0x01) << 2) | (b[3] >> 6)) as usize;
    let frame_length =
        (((b[3] & 0x03) as usize) << 11) | ((b[4] as usize) << 3) | ((b[5] >> 5) as usize);
    let raw_blocks = (b[6] & 0x03) as u32;
    let header_len = if protection_absent == 1 { 7 } else { 9 };
    if frame_length < header_len {
        return None;
    }
    Some(AudioFrameInfo {
        kind: AudioFrameKind::AacAdts,
        frame_len: frame_length,
        samples_per_frame: AAC_SAMPLES_PER_BLOCK * (raw_blocks + 1),
        sample_rate: ADTS_SAMPLE_RATE[sf_index],
        channels: ADTS_CHANNELS[channel_configuration],
        bit_rate: None,
    })
}

/// Which header parser an [`AudioFrameSplitter`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioSyntax {
    /// AC-3 or E-AC-3 (A/52 §5 / Annex E; both ride `0x0B77`).
    Ac3,
    /// MPEG-1/2 audio Layers I–III (11172-3 / 13818-3).
    MpegAudio,
    /// AAC in ADTS transport (13818-7 §6.2).
    AacAdts,
}

impl AudioSyntax {
    /// Parse one frame header of this syntax at the head of `b`.
    pub fn parse(self, b: &[u8]) -> Option<AudioFrameInfo> {
        match self {
            AudioSyntax::Ac3 => parse_ac3_frame(b),
            AudioSyntax::MpegAudio => parse_mpeg_audio_header(b),
            AudioSyntax::AacAdts => parse_adts_header(b),
        }
    }

    /// Number of bytes [`Self::parse`] needs to see before it can size
    /// a frame.
    fn header_len(self) -> usize {
        match self {
            AudioSyntax::Ac3 => 8,
            AudioSyntax::MpegAudio => 4,
            AudioSyntax::AacAdts => 7,
        }
    }
}

/// One access unit cut out of a PES payload by [`AudioFrameSplitter`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioFrame {
    /// The frame's bytes, syncword through the byte before the next
    /// syncword.
    pub data: Vec<u8>,
    /// Presentation time on the caller's timeline: the PES PTS for the
    /// first frame that commences in a payload, interpolated for the
    /// following ones (and for frames that complete a previous
    /// payload's tail). `None` only while no PTS has been seen yet.
    pub pts: Option<i64>,
    /// Header facts for this frame.
    pub info: AudioFrameInfo,
}

/// Per-stream splitter turning PES payloads into one audio access unit
/// per output, carrying partial frames across payload boundaries and
/// interpolating per-frame presentation times.
///
/// Timestamp rule (ISO/IEC 13818-1 §2.4.3.7 / §2.7.5): a PES PTS names
/// the presentation time of the first access unit that *commences* in
/// the packet. A frame whose bytes started in the previous payload is
/// the previous PTS's successor, so it is stamped from the previous
/// anchor; the first frame starting inside the new payload takes the
/// new PTS, and every following frame adds `samples_per_frame × 90 000
/// / fs` — computed from the anchor as `anchor + (k × samples × 90 000)
/// / fs` so a 44.1 kHz stream never accumulates rounding drift.
///
/// Leading bytes that do not parse as a frame header are discarded one
/// byte at a time until a header whose length lands on another valid
/// header (or on the end of the buffered data) is found — the classic
/// double-sync validation, so a stray `0xFFF` inside coded data cannot
/// re-frame the stream.
#[derive(Debug, Clone)]
pub struct AudioFrameSplitter {
    syntax: AudioSyntax,
    /// Bytes of a frame that started in an earlier payload and is not
    /// yet complete (plus any not-yet-validated prefix).
    residual: Vec<u8>,
    /// Presentation time of the frame at `residual[0]`, when known.
    residual_pts: Option<i64>,
    /// Timestamp anchor: the last PES PTS seen and how many frames
    /// have been stamped from it, plus the frame geometry used.
    anchor: Option<Anchor>,
    /// Bytes of leading garbage dropped so far (diagnostics).
    discarded: u64,
    /// Set once a complete, validated frame has been emitted.
    locked: bool,
}

#[derive(Debug, Clone, Copy)]
struct Anchor {
    pts: i64,
    frames_since: u32,
    samples_per_frame: u32,
    sample_rate: u32,
}

impl Anchor {
    fn stamp(&mut self) -> i64 {
        let k = self.frames_since as i128;
        self.frames_since += 1;
        if self.sample_rate == 0 {
            return self.pts;
        }
        let off = (k * self.samples_per_frame as i128 * 90_000) / self.sample_rate as i128;
        self.pts + off as i64
    }
}

impl AudioFrameSplitter {
    /// A splitter for one elementary stream of the given syntax.
    pub fn new(syntax: AudioSyntax) -> Self {
        Self {
            syntax,
            residual: Vec::new(),
            residual_pts: None,
            anchor: None,
            discarded: 0,
            locked: false,
        }
    }

    /// The syntax this splitter frames.
    pub fn syntax(&self) -> AudioSyntax {
        self.syntax
    }

    /// `true` once the splitter has framed at least one access unit —
    /// before that, a caller may prefer to pass payloads through whole
    /// (the stream may not be the syntax its signalling claims).
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Bytes buffered for a frame that has not completed yet.
    pub fn pending_bytes(&self) -> usize {
        self.residual.len()
    }

    /// Bytes dropped as unframeable leading garbage since creation.
    pub fn discarded_bytes(&self) -> u64 {
        self.discarded
    }

    /// Forget any buffered partial frame and the timestamp anchor —
    /// call after a byte-position jump (seek) when continuation bytes
    /// are no longer the previous frame's tail.
    pub fn reset(&mut self) {
        self.residual.clear();
        self.residual_pts = None;
        self.anchor = None;
    }

    /// [`Self::reset`] plus forgetting the lock, so the next payload is
    /// treated as a fresh stream start.
    pub fn unlock(&mut self) {
        self.reset();
        self.locked = false;
    }

    /// Feed one PES payload with its header PTS (90 kHz, already on the
    /// caller's timeline) and get back every complete access unit.
    pub fn push(&mut self, payload: &[u8], pes_pts: Option<i64>) -> Vec<AudioFrame> {
        let mut out = Vec::new();
        // Until the first frame is framed, a payload must *begin* with
        // a frame header (the PES-aligned start every conforming
        // muxer produces, §2.6.10 alignment_type '01' for audio) —
        // otherwise nothing is consumed and the caller may pass the
        // payload through whole. This keeps a stream that is not the
        // syntax its signalling claims from being re-cut on a chance
        // syncword.
        if !self.locked && self.residual.is_empty() && self.syntax.parse(payload).is_none() {
            return out;
        }
        let carried = self.residual.len();
        let mut buf = std::mem::take(&mut self.residual);
        buf.extend_from_slice(payload);
        // Frames that commence at or after `carried` are "new" in this
        // payload: the first of them takes `pes_pts`.
        let mut new_pts_pending = pes_pts;
        let mut pos = 0usize;
        let hdr = self.syntax.header_len();
        loop {
            if buf.len() - pos < hdr {
                break;
            }
            let Some(info) = self.syntax.parse(&buf[pos..]) else {
                // Not a frame start: drop one byte and re-sync. A
                // residual we believed was a frame tail turned out not
                // to be one; its PTS is void.
                pos += 1;
                self.discarded += 1;
                self.residual_pts = None;
                continue;
            };
            if info.frame_len < hdr {
                pos += 1;
                self.discarded += 1;
                continue;
            }
            let end = pos + info.frame_len;
            if end > buf.len() {
                // Partial frame: keep for the next payload. If it
                // commences in this payload it owns the pending PES PTS
                // (or an interpolated stamp) — record that now.
                let pts = if pos >= carried {
                    self.take_stamp(&mut new_pts_pending, &info)
                } else {
                    self.residual_pts
                };
                self.residual = buf.split_off(pos);
                self.residual_pts = pts;
                return out;
            }
            // Double-sync validation: when another header fits after
            // this frame it must parse too, else this was a false sync.
            if buf.len() - end >= hdr && self.syntax.parse(&buf[end..]).is_none() {
                pos += 1;
                self.discarded += 1;
                self.residual_pts = None;
                continue;
            }
            let pts = if pos < carried {
                // Completes the frame carried in from the previous
                // payload: that frame's stamp was fixed when buffered.
                let p = self.residual_pts.take();
                if p.is_none() {
                    // No stamp was recorded (anchor unknown then);
                    // interpolate from whatever anchor exists now.
                    self.interpolate(&info)
                } else {
                    p
                }
            } else {
                self.take_stamp(&mut new_pts_pending, &info)
            };
            self.locked = true;
            out.push(AudioFrame {
                data: buf[pos..end].to_vec(),
                pts,
                info,
            });
            pos = end;
        }
        // Whatever is left is shorter than a header: carry it over. It
        // commences in this payload (or is an unverifiable tail).
        if pos < buf.len() {
            let pts = if pos >= carried {
                self.take_stamp(&mut new_pts_pending, &self.syntax_geometry_guess())
            } else {
                self.residual_pts
            };
            self.residual = buf.split_off(pos);
            self.residual_pts = pts;
        } else {
            self.residual.clear();
            self.residual_pts = None;
        }
        out
    }

    /// Stamp a frame that commences in the current payload: the first
    /// such frame takes the PES PTS (re-anchoring), later ones
    /// interpolate.
    fn take_stamp(&mut self, pending: &mut Option<i64>, info: &AudioFrameInfo) -> Option<i64> {
        if let Some(p) = pending.take() {
            let mut a = Anchor {
                pts: p,
                frames_since: 0,
                samples_per_frame: info.samples_per_frame,
                sample_rate: info.sample_rate,
            };
            let s = a.stamp();
            self.anchor = Some(a);
            return Some(s);
        }
        self.interpolate(info)
    }

    fn interpolate(&mut self, info: &AudioFrameInfo) -> Option<i64> {
        let a = self.anchor.as_mut()?;
        if info.sample_rate != 0 {
            a.samples_per_frame = info.samples_per_frame;
            a.sample_rate = info.sample_rate;
        }
        Some(a.stamp())
    }

    /// Geometry to interpolate with when the frame header has not been
    /// seen yet (sub-header residual): the anchor's own.
    fn syntax_geometry_guess(&self) -> AudioFrameInfo {
        let (spf, sr) = self
            .anchor
            .map(|a| (a.samples_per_frame, a.sample_rate))
            .unwrap_or((0, 0));
        AudioFrameInfo {
            kind: match self.syntax {
                AudioSyntax::Ac3 => AudioFrameKind::Ac3,
                AudioSyntax::MpegAudio => AudioFrameKind::MpegLayer2,
                AudioSyntax::AacAdts => AudioFrameKind::AacAdts,
            },
            frame_len: 0,
            samples_per_frame: spf,
            sample_rate: sr,
            channels: 0,
            bit_rate: None,
        }
    }

    /// Drain a buffered partial frame at end of stream as-is (the
    /// decoder decides whether a truncated frame is usable). Returns
    /// `None` when nothing is buffered or the buffer never parsed as a
    /// frame start.
    pub fn flush(&mut self) -> Option<AudioFrame> {
        if self.residual.is_empty() {
            return None;
        }
        let info = self.syntax.parse(&self.residual)?;
        let data = std::mem::take(&mut self.residual);
        let pts = self.residual_pts.take();
        Some(AudioFrame { data, pts, info })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an AC-3 syncframe header for the given fscod / frmsizecod /
    /// acmod / lfeon, padded with zeros to the Table 5.18 length.
    fn ac3_frame(fscod: u8, frmsizecod: u8, acmod: u8, lfeon: u8, fill: u8) -> Vec<u8> {
        let words = match fscod {
            0 => AC3_FRAME_WORDS_48K[frmsizecod as usize],
            1 => AC3_FRAME_WORDS_44K[frmsizecod as usize],
            _ => AC3_FRAME_WORDS_32K[frmsizecod as usize],
        } as usize;
        let mut f = vec![fill; words * 2];
        f[0] = 0x0B;
        f[1] = 0x77;
        f[2] = 0;
        f[3] = 0;
        f[4] = (fscod << 6) | frmsizecod;
        // bsid = 8, bsmod = 0 → byte 5 = 0b01000_000
        f[5] = 8 << 3;
        // byte 6: acmod(3) then conditional fields then lfeon.
        let mut bits: Vec<u8> = Vec::new();
        for i in (0..3).rev() {
            bits.push((acmod >> i) & 1);
        }
        if (acmod & 1) != 0 && acmod != 1 {
            bits.extend([0, 0]);
        }
        if (acmod & 4) != 0 {
            bits.extend([0, 0]);
        }
        if acmod == 2 {
            bits.extend([0, 0]);
        }
        bits.push(lfeon);
        while bits.len() < 16 {
            bits.push(0);
        }
        f[6] = bits[..8].iter().fold(0, |acc, b| (acc << 1) | b);
        f[7] = bits[8..16].iter().fold(0, |acc, b| (acc << 1) | b);
        f
    }

    #[test]
    fn ac3_header_sizes_frame_per_table_5_18() {
        // 48 kHz, 192 kbit/s (frmsizecod 20) → 384 words = 768 bytes.
        let f = ac3_frame(0, 20, 2, 0, 0xAA);
        let i = parse_ac3_frame(&f).unwrap();
        assert_eq!(i.kind, AudioFrameKind::Ac3);
        assert_eq!(i.frame_len, 768);
        assert_eq!(i.sample_rate, 48_000);
        assert_eq!(i.channels, 2);
        assert_eq!(i.bit_rate, Some(192_000));
        assert_eq!(i.samples_per_frame, 1536);
        assert_eq!(i.duration_90k(), 2880);
        // 44.1 kHz odd code → +1 word (Table 5.18 second row of a pair).
        let f = ac3_frame(1, 21, 7, 1, 0);
        let i = parse_ac3_frame(&f).unwrap();
        assert_eq!(i.frame_len, 418 * 2);
        assert_eq!(i.channels, 6);
        // 32 kHz column.
        let f = ac3_frame(2, 0, 1, 0, 0);
        assert_eq!(parse_ac3_frame(&f).unwrap().frame_len, 96 * 2);
    }

    #[test]
    fn ac3_rejects_reserved_codes_and_bad_sync() {
        let mut f = ac3_frame(0, 20, 2, 0, 0);
        f[4] = (3 << 6) | 20; // fscod '11' reserved
        assert!(parse_ac3_frame(&f).is_none());
        let mut f = ac3_frame(0, 20, 2, 0, 0);
        f[4] = 38; // frmsizecod past the table
        assert!(parse_ac3_frame(&f).is_none());
        let mut f = ac3_frame(0, 20, 2, 0, 0);
        f[1] = 0x78;
        assert!(parse_ac3_frame(&f).is_none());
        let mut f = ac3_frame(0, 20, 2, 0, 0);
        f[5] = 9 << 3; // bsid 9: neither AC-3 (≤8) nor E-AC-3 (11..16)
        assert!(parse_ac3_frame(&f).is_none());
    }

    #[test]
    fn eac3_header_decodes_frmsiz_blocks_and_fscod2() {
        // strmtyp 0, substreamid 0, frmsiz 0x1FF (512 words), fscod 0,
        // numblkscod 3 (6 blocks), acmod 7, lfeon 1, bsid 16.
        let b = [
            0x0B,
            0x77,
            0x01,
            0xFF,
            (3 << 4) | (7 << 1) | 1, // fscod 0
            16 << 3,
            0,
        ];
        let i = parse_ac3_frame(&b).unwrap();
        assert_eq!(i.kind, AudioFrameKind::Eac3);
        assert_eq!(i.frame_len, 1024);
        assert_eq!(i.samples_per_frame, 1536);
        assert_eq!(i.sample_rate, 48_000);
        assert_eq!(i.channels, 6);
        // fscod '11' + fscod2 '01' → 22.05 kHz, 6 blocks implied;
        // numblkscod 0 variant at 44.1 kHz → 256 samples.
        let b2 = [
            0x0B,
            0x77,
            0x00,
            0x7F,
            (3 << 6) | (1 << 4) | (2 << 1),
            16 << 3,
            0,
        ];
        let i = parse_ac3_frame(&b2).unwrap();
        assert_eq!(i.sample_rate, 22_050);
        assert_eq!(i.samples_per_frame, 1536);
        assert_eq!(i.frame_len, 256);
        let b3 = [0x0B, 0x77, 0x00, 0x7F, (1 << 6) | (2 << 1), 16 << 3, 0];
        let i = parse_ac3_frame(&b3).unwrap();
        assert_eq!(i.sample_rate, 44_100);
        assert_eq!(i.samples_per_frame, 256);
    }

    /// MPEG audio header bytes for (ID, layer_code, bitrate_index,
    /// sf_index, padding, mode).
    fn mpa_header(id: u8, layer: u8, br: u8, sf: u8, pad: u8, mode: u8) -> [u8; 4] {
        [
            0xFF,
            0xF0 | (id << 3) | (layer << 1) | 1,
            (br << 4) | (sf << 2) | (pad << 1),
            mode << 6,
        ]
    }

    #[test]
    fn mpeg_audio_header_lengths_follow_the_padding_formula() {
        // Layer II, 48 kHz, 192 kbit/s (index 10) → 144 × 192000 / 48000 = 576.
        let i = parse_mpeg_audio_header(&mpa_header(1, 0b10, 10, 1, 0, 0)).unwrap();
        assert_eq!(i.kind, AudioFrameKind::MpegLayer2);
        assert_eq!(i.frame_len, 576);
        assert_eq!(i.samples_per_frame, 1152);
        assert_eq!(i.sample_rate, 48_000);
        assert_eq!(i.channels, 2);
        assert_eq!(i.bit_rate, Some(192_000));
        assert_eq!(i.duration_90k(), 2160);
        // Layer III, 44.1 kHz, 128 kbit/s (index 9), padding → 417 + 1.
        let i = parse_mpeg_audio_header(&mpa_header(1, 0b01, 9, 0, 1, 0b11)).unwrap();
        assert_eq!(i.kind, AudioFrameKind::MpegLayer3);
        assert_eq!(i.frame_len, 418);
        assert_eq!(i.channels, 1);
        assert_eq!(i.duration_90k(), 2351); // 1152 × 90000 / 44100 = 2351.02
        // Layer I, 32 kHz, 256 kbit/s (index 8) → 12 × 256000 / 32000 = 96 slots × 4.
        let i = parse_mpeg_audio_header(&mpa_header(1, 0b11, 8, 2, 0, 0)).unwrap();
        assert_eq!(i.kind, AudioFrameKind::MpegLayer1);
        assert_eq!(i.frame_len, 384);
        assert_eq!(i.samples_per_frame, 384);
        // 13818-3 LSF Layer III: ID 0, 24 kHz, 64 kbit/s (index 8) → 72 × 64000 / 24000 = 192, 576 samples.
        let i = parse_mpeg_audio_header(&mpa_header(0, 0b01, 8, 1, 0, 0)).unwrap();
        assert_eq!(i.frame_len, 192);
        assert_eq!(i.samples_per_frame, 576);
        assert_eq!(i.sample_rate, 24_000);
        // LSF Layer II keeps 1152 samples and the 144 constant: 22.05 kHz, 48 kbit/s (index 6).
        let i = parse_mpeg_audio_header(&mpa_header(0, 0b10, 6, 0, 0, 0)).unwrap();
        assert_eq!(i.frame_len, 144 * 48_000 / 22_050);
        assert_eq!(i.samples_per_frame, 1152);
    }

    #[test]
    fn mpeg_audio_header_rejects_reserved_and_free_format() {
        assert!(parse_mpeg_audio_header(&mpa_header(1, 0b00, 10, 1, 0, 0)).is_none()); // layer reserved
        assert!(parse_mpeg_audio_header(&mpa_header(1, 0b10, 0, 1, 0, 0)).is_none()); // free format
        assert!(parse_mpeg_audio_header(&mpa_header(1, 0b10, 15, 1, 0, 0)).is_none()); // forbidden
        assert!(parse_mpeg_audio_header(&mpa_header(1, 0b10, 10, 3, 0, 0)).is_none()); // fs reserved
        // 11-bit sync (MPEG-2.5) is outside the staged standards.
        let mut h = mpa_header(1, 0b10, 10, 1, 0, 0);
        h[1] &= 0xEF;
        assert!(parse_mpeg_audio_header(&h).is_none());
    }

    fn adts_header(sf: u8, chan: u8, len: usize, blocks: u8, prot_absent: u8) -> [u8; 7] {
        [
            0xFF,
            0xF0 | prot_absent,
            (1 << 6) | (sf << 2) | (chan >> 2),
            ((chan & 3) << 6) | ((len >> 11) as u8 & 0x03),
            (len >> 3) as u8,
            ((len & 7) as u8) << 5 | 0x1F,
            0xFC | blocks,
        ]
    }

    #[test]
    fn adts_header_reads_tables_35_42_and_frame_length() {
        let i = parse_adts_header(&adts_header(3, 2, 371, 0, 1)).unwrap();
        assert_eq!(i.kind, AudioFrameKind::AacAdts);
        assert_eq!(i.frame_len, 371);
        assert_eq!(i.sample_rate, 48_000);
        assert_eq!(i.channels, 2);
        assert_eq!(i.samples_per_frame, 1024);
        assert_eq!(i.duration_90k(), 1920);
        let i = parse_adts_header(&adts_header(4, 7, 1000, 1, 0)).unwrap();
        assert_eq!(i.sample_rate, 44_100);
        assert_eq!(i.channels, 8);
        assert_eq!(i.samples_per_frame, 2048);
        assert!(parse_adts_header(&adts_header(12, 2, 371, 0, 1)).is_none()); // reserved sf index
        assert!(parse_adts_header(&adts_header(3, 2, 6, 0, 1)).is_none()); // shorter than header
        // An MPEG-1 Layer II header shares the 12-bit sync but has layer != 0.
        assert!(parse_adts_header(&mpa_header(1, 0b10, 10, 1, 0, 0)).is_none());
    }

    #[test]
    fn splitter_cuts_three_ac3_frames_and_interpolates_pts() {
        let f = ac3_frame(0, 20, 2, 0, 0x11);
        let mut payload = f.clone();
        payload.extend_from_slice(&f);
        payload.extend_from_slice(&f);
        let mut s = AudioFrameSplitter::new(AudioSyntax::Ac3);
        let out = s.push(&payload, Some(90_000));
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].pts, Some(90_000));
        assert_eq!(out[1].pts, Some(92_880));
        assert_eq!(out[2].pts, Some(95_760));
        assert!(out.iter().all(|p| p.data == f));
        assert_eq!(s.discarded_bytes(), 0);
        assert!(s.flush().is_none());
    }

    #[test]
    fn splitter_carries_a_partial_frame_across_payloads() {
        let f = ac3_frame(0, 20, 2, 0, 0x22);
        // Payload A: frame 0 + first 100 bytes of frame 1 (PTS 1000).
        // Payload B: rest of frame 1 + frame 2 (PTS 1000 + 2 × 2880).
        let mut a = f.clone();
        a.extend_from_slice(&f[..100]);
        let mut b = f[100..].to_vec();
        b.extend_from_slice(&f);
        let mut s = AudioFrameSplitter::new(AudioSyntax::Ac3);
        let out_a = s.push(&a, Some(1000));
        assert_eq!(out_a.len(), 1);
        assert_eq!(out_a[0].pts, Some(1000));
        let out_b = s.push(&b, Some(1000 + 2 * 2880));
        assert_eq!(out_b.len(), 2);
        // Frame 1 commenced in payload A → interpolated from A's PTS.
        assert_eq!(out_b[0].pts, Some(3880));
        assert_eq!(out_b[0].data, f);
        // Frame 2 is the first to commence in payload B → B's PTS.
        assert_eq!(out_b[1].pts, Some(6760));
    }

    #[test]
    fn splitter_pts_less_payload_interpolates_from_last_anchor() {
        let f = ac3_frame(0, 20, 2, 0, 0x33);
        let mut s = AudioFrameSplitter::new(AudioSyntax::Ac3);
        let out = s.push(&f, Some(500));
        assert_eq!(out[0].pts, Some(500));
        let out = s.push(&f, None);
        assert_eq!(out[0].pts, Some(3380));
        let out = s.push(&f, None);
        assert_eq!(out[0].pts, Some(6260));
    }

    #[test]
    fn splitter_skips_leading_garbage_with_double_sync_check() {
        let f = ac3_frame(0, 20, 2, 0, 0x44);
        // A fake syncword inside the garbage whose frame length does
        // not land on another header must be rejected.
        let mut payload = vec![0x00, 0x0B, 0x77, 0x00, 0x00, 0x14, 0x40, 0x00];
        payload.extend_from_slice(&f);
        payload.extend_from_slice(&f);
        let mut s = AudioFrameSplitter::new(AudioSyntax::Ac3);
        // Unlocked: a payload that does not begin with a header is not
        // consumed at all.
        assert!(s.push(&payload, Some(0)).is_empty());
        assert!(!s.is_locked());
        assert_eq!(s.pending_bytes(), 0);
        // Locked by an aligned frame, later garbage is skipped.
        assert_eq!(s.push(&f, Some(0)).len(), 1);
        let out = s.push(&payload, None);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].data, f);
        assert_eq!(s.discarded_bytes(), 8);
    }

    #[test]
    fn splitter_mpeg_audio_and_sub_header_tail() {
        let h = mpa_header(1, 0b10, 10, 1, 0, 0);
        let mut f = vec![0x55; 576];
        f[..4].copy_from_slice(&h);
        let mut payload = f.clone();
        payload.extend_from_slice(&f);
        payload.extend_from_slice(&f[..2]); // 2-byte tail, shorter than a header
        let mut s = AudioFrameSplitter::new(AudioSyntax::MpegAudio);
        let out = s.push(&payload, Some(0));
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].pts, Some(2160));
        let mut rest = f[2..].to_vec();
        rest.extend_from_slice(&f);
        let out = s.push(&rest, Some(3 * 2160 + 7));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].pts, Some(2 * 2160));
        assert_eq!(out[1].pts, Some(3 * 2160 + 7));
        assert_eq!(out[0].data, f);
    }

    #[test]
    fn splitter_reset_drops_residual() {
        let f = ac3_frame(0, 20, 2, 0, 0x66);
        let mut s = AudioFrameSplitter::new(AudioSyntax::Ac3);
        s.push(&f[..300], Some(10));
        s.reset();
        let out = s.push(&f, Some(20));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pts, Some(20));
    }

    #[test]
    fn splitter_flush_returns_truncated_tail_frame() {
        let f = ac3_frame(0, 20, 2, 0, 0x77);
        let mut s = AudioFrameSplitter::new(AudioSyntax::Ac3);
        let out = s.push(&f[..500], Some(10));
        assert!(out.is_empty());
        let tail = s.flush().unwrap();
        assert_eq!(tail.data.len(), 500);
        assert_eq!(tail.pts, Some(10));
        assert!(s.flush().is_none());
    }
}
