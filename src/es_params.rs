//! Minimal video elementary-stream header readers — just enough of the
//! first access unit to fill a stream's picture size, chroma format and
//! frame rate when the container signalling (ISO/IEC 13818-1 §2.6
//! descriptors) does not carry them.
//!
//! * H.264 / AVC: `seq_parameter_set_data()` (ITU-T H.264 §7.3.2.1.1)
//!   up to `frame_cropping` and the VUI `timing_info` (Annex E.1.1),
//!   after the §7.3.1 emulation-prevention strip; size per equations
//!   7-13..7-24 (`PicWidthInMbs`, `FrameHeightInMbs`, `CropUnitX/Y`),
//!   `SubWidthC/SubHeightC` per Table 6-1, Exp-Golomb per §9.1 / §9.1.1.
//! * MPEG-1 / MPEG-2 video: `sequence_header()` (H.262 §6.2.2.1 /
//!   11172-2 §2.4.2.3) + `sequence_extension()` (H.262 §6.2.2.3):
//!   12-bit sizes extended by the 2-bit size extensions, `frame_rate_code`
//!   via Table 6-4 scaled by `(frame_rate_extension_n + 1) ÷
//!   (frame_rate_extension_d + 1)`, `chroma_format` per Table 6-5.

/// Picture facts lifted from a video elementary stream's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct VideoEsParams {
    pub width: u32,
    pub height: u32,
    /// Frame rate as `num / den`, when coded.
    pub frame_rate: Option<(u32, u32)>,
    /// Chroma format: 0 monochrome, 1 4:2:0, 2 4:2:2, 3 4:4:4.
    pub chroma_format: u8,
    /// Luma bit depth.
    pub bit_depth: u8,
    /// `true` when the MPEG-1/2 stream carried a `sequence_extension`
    /// (H.262) — `false` means ISO/IEC 11172-2.
    pub mpeg2: bool,
}

/// Iterate Annex-B NAL units / start-code-delimited units: yields the
/// bytes after each `00 00 01` prefix up to the next prefix.
fn start_code_units(es: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= es.len() {
        if es[i] == 0 && es[i + 1] == 0 && es[i + 2] == 1 {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let n = starts.len();
    (0..n).map(move |k| {
        let s = starts[k];
        // A unit runs to the next prefix; a `zero_byte` of a 4-byte
        // start code stays attached to its tail, which the header
        // readers never reach.
        let e = if k + 1 < n {
            starts[k + 1] - 3
        } else {
            es.len()
        };
        &es[s..e]
    })
}

/// MSB-first bit reader over an RBSP.
struct Bits<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn u(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.b.get(self.pos / 8)?;
            v = (v << 1) | ((byte >> (7 - (self.pos % 8))) & 1) as u32;
            self.pos += 1;
        }
        Some(v)
    }
    /// ue(v), §9.1.
    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0u32;
        while self.u(1)? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        let suffix = self.u(zeros)?;
        Some(((1u64 << zeros) - 1 + suffix as u64).min(u32::MAX as u64) as u32)
    }
    /// se(v), §9.1.1 / Table 9-3.
    fn se(&mut self) -> Option<i32> {
        let k = self.ue()? as i64;
        Some(if k % 2 == 1 {
            ((k + 1) / 2) as i32
        } else {
            -(k / 2) as i32
        })
    }
}

/// §7.3.1: drop every `emulation_prevention_three_byte` (the `03` of a
/// `00 00 03` triple).
fn nal_to_rbsp(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    for &b in nal {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out
}

/// Profiles whose SPS carries the chroma / bit-depth / scaling block
/// (§7.3.2.1.1 `if( profile_idc = = 100 | | … )`).
const HIGH_PROFILES: [u32; 13] = [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135];

/// §7.3.2.1.1.1 scaling_list(): consume the delta_scale run.
fn skip_scaling_list(r: &mut Bits<'_>, size: usize) -> Option<()> {
    let mut last = 8i32;
    let mut next = 8i32;
    for _ in 0..size {
        if next != 0 {
            let delta = r.se()?;
            next = (last + delta + 256) % 256;
        }
        last = if next == 0 { last } else { next };
    }
    Some(())
}

/// Parse an H.264 SPS RBSP (NAL header byte stripped).
pub(crate) fn parse_h264_sps(rbsp: &[u8]) -> Option<VideoEsParams> {
    let mut r = Bits::new(rbsp);
    let profile_idc = r.u(8)?;
    r.u(8)?; // constraint flags + reserved_zero_2bits
    r.u(8)?; // level_idc
    r.ue()?; // seq_parameter_set_id
    let mut chroma_format_idc = 1u32;
    let mut separate_colour_plane = 0u32;
    let mut bit_depth_luma = 8u32;
    if HIGH_PROFILES.contains(&profile_idc) {
        chroma_format_idc = r.ue()?;
        if chroma_format_idc > 3 {
            return None;
        }
        if chroma_format_idc == 3 {
            separate_colour_plane = r.u(1)?;
        }
        bit_depth_luma = 8 + r.ue()?;
        r.ue()?; // bit_depth_chroma_minus8
        r.u(1)?; // qpprime_y_zero_transform_bypass_flag
        if r.u(1)? == 1 {
            let lists = if chroma_format_idc != 3 { 8 } else { 12 };
            for i in 0..lists {
                if r.u(1)? == 1 {
                    skip_scaling_list(&mut r, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    r.ue()?; // log2_max_frame_num_minus4
    let poc_type = r.ue()?;
    if poc_type == 0 {
        r.ue()?;
    } else if poc_type == 1 {
        r.u(1)?;
        r.se()?;
        r.se()?;
        let n = r.ue()?;
        if n > 255 {
            return None;
        }
        for _ in 0..n {
            r.se()?;
        }
    }
    r.ue()?; // max_num_ref_frames
    r.u(1)?; // gaps_in_frame_num_value_allowed_flag
    let pic_width_in_mbs = r.ue()? as u64 + 1;
    let pic_height_in_map_units = r.ue()? as u64 + 1;
    let frame_mbs_only = r.u(1)? as u64;
    if frame_mbs_only == 0 {
        r.u(1)?; // mb_adaptive_frame_field_flag
    }
    r.u(1)?; // direct_8x8_inference_flag
    let (mut cl, mut cr, mut ct, mut cb) = (0u64, 0u64, 0u64, 0u64);
    if r.u(1)? == 1 {
        cl = r.ue()? as u64;
        cr = r.ue()? as u64;
        ct = r.ue()? as u64;
        cb = r.ue()? as u64;
    }
    // ChromaArrayType (§7.4.2.1.1) and Table 6-1.
    let chroma_array_type = if separate_colour_plane == 1 {
        0
    } else {
        chroma_format_idc
    };
    let (sub_w, sub_h) = match chroma_array_type {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let (crop_x, crop_y) = if chroma_array_type == 0 {
        (1, 2 - frame_mbs_only)
    } else {
        (sub_w, sub_h * (2 - frame_mbs_only))
    };
    let frame_height_in_mbs = (2 - frame_mbs_only) * pic_height_in_map_units;
    let width = (pic_width_in_mbs * 16).checked_sub(crop_x * (cl + cr))?;
    let height = (frame_height_in_mbs * 16).checked_sub(crop_y * (ct + cb))?;
    let mut frame_rate = None;
    if r.u(1)? == 1 {
        frame_rate = parse_vui_timing(&mut r);
    }
    Some(VideoEsParams {
        width: u32::try_from(width).ok()?,
        height: u32::try_from(height).ok()?,
        frame_rate,
        chroma_format: chroma_format_idc as u8,
        bit_depth: bit_depth_luma as u8,
        mpeg2: false,
    })
}

/// Annex E.1.1 vui_parameters() up to timing_info. The frame rate is
/// `time_scale ÷ (2 × num_units_in_tick)` — the Table E-6 frame-picture
/// divisor of 2 (`pic_struct_present_flag = 0`, `field_pic_flag = 0`).
fn parse_vui_timing(r: &mut Bits<'_>) -> Option<(u32, u32)> {
    if r.u(1)? == 1 {
        let idc = r.u(8)?;
        if idc == 255 {
            // Extended_SAR
            r.u(16)?;
            r.u(16)?;
        }
    }
    if r.u(1)? == 1 {
        r.u(1)?; // overscan_appropriate_flag
    }
    if r.u(1)? == 1 {
        r.u(3)?;
        r.u(1)?;
        if r.u(1)? == 1 {
            r.u(24)?;
        }
    }
    if r.u(1)? == 1 {
        r.ue()?;
        r.ue()?;
    }
    if r.u(1)? == 1 {
        let units = r.u(32)?;
        let scale = r.u(32)?;
        if units == 0 || scale == 0 {
            return None;
        }
        let (n, d) = (scale as u64, 2 * units as u64);
        let g = gcd(n, d);
        return Some(((n / g) as u32, (d / g) as u32));
    }
    None
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a.max(1)
}

/// Find the first SPS (`nal_unit_type` 7) in an Annex-B H.264 byte
/// stream and parse it.
pub(crate) fn h264_params(es: &[u8]) -> Option<VideoEsParams> {
    for nal in start_code_units(es) {
        if nal.first().is_some_and(|h| h & 0x1F == 7)
            && let Some(p) = parse_h264_sps(&nal_to_rbsp(&nal[1..]))
        {
            return Some(p);
        }
    }
    None
}

/// H.262 Table 6-4 frame_rate_value (also ISO/IEC 11172-2 picture_rate).
const FRAME_RATES: [(u32, u32); 9] = [
    (0, 0),
    (24_000, 1001),
    (24, 1),
    (25, 1),
    (30_000, 1001),
    (30, 1),
    (50, 1),
    (60_000, 1001),
    (60, 1),
];

/// Parse the first MPEG-1/2 `sequence_header()` (`00 00 01 B3`) and,
/// when it directly follows, the `sequence_extension()` (`00 00 01 B5`,
/// extension_start_code_identifier `0001`).
pub(crate) fn mpeg12_params(es: &[u8]) -> Option<VideoEsParams> {
    let mut units = start_code_units(es).skip_while(|u| u.first() != Some(&0xB3));
    let sh = units.next()?;
    if sh.len() < 8 {
        return None;
    }
    let mut r = Bits::new(&sh[1..]);
    let mut width = r.u(12)?;
    let mut height = r.u(12)?;
    r.u(4)?; // aspect_ratio_information
    let frc = r.u(4)? as usize;
    let mut frame_rate = FRAME_RATES.get(frc).copied().filter(|f| f.1 != 0);
    let mut chroma_format = 1u8;
    let mut mpeg2 = false;
    // The sequence_extension, when present, is the next start code
    // after the header (§6.2.2: `if (nextbits() == extension_start_code)`).
    if let Some(ext) = units.next()
        && ext.first() == Some(&0xB5)
        && ext.len() >= 7
        && ext[1] >> 4 == 1
    {
        let mut r = Bits::new(&ext[1..]);
        r.u(4)?; // extension_start_code_identifier
        r.u(8)?; // profile_and_level_indication
        r.u(1)?; // progressive_sequence
        chroma_format = r.u(2)? as u8;
        width |= r.u(2)? << 12;
        height |= r.u(2)? << 12;
        r.u(12)?; // bit_rate_extension
        r.u(1)?; // marker_bit
        r.u(8)?; // vbv_buffer_size_extension
        r.u(1)?; // low_delay
        let n = r.u(2)? + 1;
        let d = r.u(5)? + 1;
        frame_rate = frame_rate.map(|(fn_, fd)| {
            let (num, den) = (fn_ as u64 * n as u64, fd as u64 * d as u64);
            let g = gcd(num, den);
            ((num / g) as u32, (den / g) as u32)
        });
        mpeg2 = true;
    }
    if width == 0 || height == 0 {
        return None;
    }
    Some(VideoEsParams {
        width,
        height,
        frame_rate,
        chroma_format,
        bit_depth: 8,
        mpeg2,
    })
}

/// Fill the empty picture fields of a video [`oxideav_core::CodecParameters`]
/// from elementary-stream headers (container signalling wins).
#[cfg(feature = "registry")]
pub(crate) fn apply_video(params: &mut oxideav_core::CodecParameters, v: &VideoEsParams) {
    use oxideav_core::PixelFormat;
    if params.width.is_none() {
        params.width = Some(v.width);
    }
    if params.height.is_none() {
        params.height = Some(v.height);
    }
    if params.frame_rate.is_none()
        && let Some((n, d)) = v.frame_rate
    {
        params.frame_rate = Some(oxideav_core::Rational::new(n as i64, d as i64));
    }
    if params.pixel_format.is_none() {
        params.pixel_format = match (v.chroma_format, v.bit_depth) {
            (0, 8) => Some(PixelFormat::Gray8),
            (1, 8) => Some(PixelFormat::Yuv420P),
            (2, 8) => Some(PixelFormat::Yuv422P),
            (3, 8) => Some(PixelFormat::Yuv444P),
            (1, 10) => Some(PixelFormat::Yuv420P10Le),
            (2, 10) => Some(PixelFormat::Yuv422P10Le),
            (3, 10) => Some(PixelFormat::Yuv444P10Le),
            _ => None,
        };
    }
}

/// Fill the empty audio fields of a [`oxideav_core::CodecParameters`]
/// from the first frame header, and refine the codec id where the
/// container's `stream_type` / `stream_id` cannot tell the layers (or
/// AC-3 from E-AC-3) apart.
#[cfg(feature = "registry")]
pub(crate) fn apply_audio(
    params: &mut oxideav_core::CodecParameters,
    a: &crate::audio_frame::AudioFrameInfo,
) {
    use crate::audio_frame::AudioFrameKind as K;
    let id = params.codec_id.as_str();
    let refined = match (id, a.kind) {
        ("mp1" | "mp2" | "mp3", K::MpegLayer1) => Some("mp1"),
        ("mp1" | "mp2" | "mp3", K::MpegLayer2) => Some("mp2"),
        ("mp1" | "mp2" | "mp3", K::MpegLayer3) => Some("mp3"),
        ("ac3" | "eac3", K::Ac3) => Some("ac3"),
        ("ac3" | "eac3", K::Eac3) => Some("eac3"),
        _ => None,
    };
    if let Some(r) = refined
        && r != id
    {
        params.codec_id = oxideav_core::CodecId::new(r);
    }
    if params.sample_rate.is_none() && a.sample_rate != 0 {
        params.sample_rate = Some(a.sample_rate);
    }
    if params.channels.is_none() && a.channels != 0 {
        params.channels = Some(a.channels);
    }
    if params.bit_rate.is_none()
        && let Some(b) = a.bit_rate
    {
        params.bit_rate = Some(b as u64);
    }
}

/// Which audio framing a codec id is split with, if any.
#[cfg(feature = "registry")]
pub(crate) fn audio_syntax_for(codec_id: &str) -> Option<crate::audio_frame::AudioSyntax> {
    use crate::audio_frame::AudioSyntax;
    match codec_id {
        "mp1" | "mp2" | "mp3" => Some(AudioSyntax::MpegAudio),
        "ac3" | "eac3" => Some(AudioSyntax::Ac3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MSB-first bit writer for synthesising RBSPs.
    struct W(Vec<u8>, usize);
    impl W {
        fn new() -> Self {
            W(Vec::new(), 0)
        }
        fn u(&mut self, n: u32, v: u64) {
            for i in (0..n).rev() {
                if self.1.is_multiple_of(8) {
                    self.0.push(0);
                }
                let bit = ((v >> i) & 1) as u8;
                let last = self.0.len() - 1;
                self.0[last] |= bit << (7 - (self.1 % 8));
                self.1 += 1;
            }
        }
        fn ue(&mut self, v: u64) {
            let x = v + 1;
            let len = 64 - x.leading_zeros();
            self.u(len - 1, 0);
            self.u(len, x);
        }
    }

    fn sps_1080p_high() -> Vec<u8> {
        let mut w = W::new();
        w.u(8, 100); // High
        w.u(8, 0);
        w.u(8, 40);
        w.ue(0); // sps id
        w.ue(1); // chroma 4:2:0
        w.ue(0);
        w.ue(0);
        w.u(1, 0);
        w.u(1, 0); // no scaling matrix
        w.ue(0); // log2_max_frame_num_minus4
        w.ue(0); // poc type 0
        w.ue(2);
        w.ue(4); // max_num_ref_frames
        w.u(1, 0);
        w.ue(119); // 120 MBs = 1920
        w.ue(67); // 68 MBs = 1088
        w.u(1, 1); // frame_mbs_only
        w.u(1, 1);
        w.u(1, 1); // cropping
        w.ue(0);
        w.ue(0);
        w.ue(0);
        w.ue(4); // 4 × CropUnitY(2) = 8 → 1080
        w.u(1, 1); // vui
        w.u(1, 0);
        w.u(1, 0);
        w.u(1, 0);
        w.u(1, 0);
        w.u(1, 1); // timing
        w.u(32, 1);
        w.u(32, 48);
        w.u(1, 1);
        w.0
    }

    #[test]
    fn h264_sps_size_crop_and_timing() {
        let p = parse_h264_sps(&sps_1080p_high()).unwrap();
        assert_eq!((p.width, p.height), (1920, 1080));
        assert_eq!(p.frame_rate, Some((24, 1)));
        assert_eq!(p.chroma_format, 1);
        assert_eq!(p.bit_depth, 8);
    }

    #[test]
    fn h264_params_finds_sps_behind_aud_and_strips_emulation_prevention() {
        let mut es = vec![0, 0, 0, 1, 0x09, 0xF0, 0, 0, 1, 0x67];
        // Insert an emulation-prevention byte: write the RBSP through
        // the §7.3.1 escaping rule.
        let rbsp = sps_1080p_high();
        let mut zeros = 0;
        for b in rbsp {
            if zeros >= 2 && b <= 3 {
                es.push(3);
                zeros = 0;
            }
            zeros = if b == 0 { zeros + 1 } else { 0 };
            es.push(b);
        }
        let p = h264_params(&es).unwrap();
        assert_eq!((p.width, p.height), (1920, 1080));
    }

    #[test]
    fn h264_field_coded_height_doubles_map_units() {
        let mut w = W::new();
        w.u(8, 77); // Main: no chroma block
        w.u(8, 0);
        w.u(8, 40);
        w.ue(0); // sps id
        w.ue(0); // log2_max_frame_num_minus4
        w.ue(0); // poc type 0
        w.ue(2); // log2_max_pic_order_cnt_lsb_minus4
        w.ue(4); // max_num_ref_frames
        w.u(1, 0);
        w.ue(119);
        w.ue(33); // 34 map units → 68 MBs as fields
        w.u(1, 0); // frame_mbs_only = 0
        w.u(1, 1); // mbaff
        w.u(1, 1);
        w.u(1, 1);
        w.ue(0);
        w.ue(0);
        w.ue(0);
        w.ue(2); // CropUnitY = 2 × 2 = 4 → 8 rows
        w.u(1, 0);
        let p = parse_h264_sps(&w.0).unwrap();
        assert_eq!((p.width, p.height), (1920, 1080));
        assert_eq!(p.frame_rate, None);
    }

    #[test]
    fn mpeg2_sequence_header_and_extension() {
        // 320x180, frame_rate_code 3 (25), sequence_extension 4:2:2.
        let mut es = vec![0, 0, 1, 0xB3];
        let mut w = W::new();
        w.u(12, 320);
        w.u(12, 180);
        w.u(4, 1);
        w.u(4, 3);
        w.u(18, 2500);
        w.u(1, 1);
        w.u(10, 112);
        w.u(1, 0);
        w.u(1, 0);
        w.u(1, 0);
        es.extend_from_slice(&w.0);
        es.extend_from_slice(&[0, 0, 1, 0xB5]);
        let mut w = W::new();
        w.u(4, 1);
        w.u(8, 0x85);
        w.u(1, 1);
        w.u(2, 2);
        w.u(2, 0);
        w.u(2, 0);
        w.u(12, 0);
        w.u(1, 1);
        w.u(8, 0);
        w.u(1, 0);
        w.u(2, 0);
        w.u(5, 0);
        es.extend_from_slice(&w.0);
        let p = mpeg12_params(&es).unwrap();
        assert_eq!((p.width, p.height), (320, 180));
        assert_eq!(p.frame_rate, Some((25, 1)));
        assert_eq!(p.chroma_format, 2);
        assert!(p.mpeg2);
        // MPEG-1: same header without the extension.
        let p = mpeg12_params(&es[..12]).unwrap();
        assert!(!p.mpeg2);
        assert_eq!(p.chroma_format, 1);
    }
}
