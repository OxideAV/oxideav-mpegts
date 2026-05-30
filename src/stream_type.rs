//! `stream_type` byte → richer enum, scoped to BD-relevant values.
//!
//! Values are per ISO/IEC 13818-1 Table 2-29 plus the HDMV-extended
//! range BD-ROM Part 3 §5 uses (`0x80..=0xFF`).

/// One elementary-stream codec class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// `0x02` ISO/IEC 13818-2 (MPEG-2 video).
    Mpeg2Video,
    /// `0x1B` ITU-T H.264 / ISO/IEC 14496-10 (AVC).
    AvcVideo,
    /// `0x24` ITU-T H.265 / ISO/IEC 23008-2 (HEVC).
    HevcVideo,
    /// `0xEA` SMPTE VC-1 (Microsoft Windows Media Video 9).
    Vc1Video,
    /// `0x80` Linear PCM audio (BD: big-endian, BD-ROM Part 3 §5.4).
    LpcmAudio,
    /// `0x81` Dolby AC-3.
    Ac3Audio,
    /// `0x82` DTS.
    DtsAudio,
    /// `0x83` Dolby TrueHD.
    TruehdAudio,
    /// `0x84` Dolby Digital Plus (E-AC-3).
    EAc3Audio,
    /// `0x85` DTS-HD High Resolution.
    DtsHdAudio,
    /// `0x86` DTS-HD Master Audio.
    DtsHdMaAudio,
    /// `0xA1` E-AC-3 secondary audio.
    EAc3SecondaryAudio,
    /// `0xA2` DTS-HD secondary audio.
    DtsHdSecondaryAudio,
    /// `0x90` HDMV Presentation Graphic Stream (PGS) subtitles.
    PgsSubtitle,
    /// `0x91` HDMV Interactive Graphics Stream (IGS).
    IgsInteractive,
    /// `0x92` HDMV Text Subtitle Stream (TextST).
    TextSubtitle,
    /// Any other value — kept as the raw byte for diagnostics.
    Other(u8),
}

impl StreamType {
    /// Map a raw `stream_type` byte to the enum.
    pub fn from_raw(b: u8) -> Self {
        match b {
            0x02 => Self::Mpeg2Video,
            0x1B => Self::AvcVideo,
            0x24 => Self::HevcVideo,
            0xEA => Self::Vc1Video,
            0x80 => Self::LpcmAudio,
            0x81 => Self::Ac3Audio,
            0x82 => Self::DtsAudio,
            0x83 => Self::TruehdAudio,
            0x84 => Self::EAc3Audio,
            0x85 => Self::DtsHdAudio,
            0x86 => Self::DtsHdMaAudio,
            0xA1 => Self::EAc3SecondaryAudio,
            0xA2 => Self::DtsHdSecondaryAudio,
            0x90 => Self::PgsSubtitle,
            0x91 => Self::IgsInteractive,
            0x92 => Self::TextSubtitle,
            other => Self::Other(other),
        }
    }

    /// Inverse of [`Self::from_raw`].
    pub fn as_raw(self) -> u8 {
        match self {
            Self::Mpeg2Video => 0x02,
            Self::AvcVideo => 0x1B,
            Self::HevcVideo => 0x24,
            Self::Vc1Video => 0xEA,
            Self::LpcmAudio => 0x80,
            Self::Ac3Audio => 0x81,
            Self::DtsAudio => 0x82,
            Self::TruehdAudio => 0x83,
            Self::EAc3Audio => 0x84,
            Self::DtsHdAudio => 0x85,
            Self::DtsHdMaAudio => 0x86,
            Self::EAc3SecondaryAudio => 0xA1,
            Self::DtsHdSecondaryAudio => 0xA2,
            Self::PgsSubtitle => 0x90,
            Self::IgsInteractive => 0x91,
            Self::TextSubtitle => 0x92,
            Self::Other(b) => b,
        }
    }

    /// `true` when the stream carries primary video.
    pub fn is_video(self) -> bool {
        matches!(
            self,
            Self::Mpeg2Video | Self::AvcVideo | Self::HevcVideo | Self::Vc1Video
        )
    }

    /// `true` when the stream carries audio (primary or secondary).
    pub fn is_audio(self) -> bool {
        matches!(
            self,
            Self::LpcmAudio
                | Self::Ac3Audio
                | Self::DtsAudio
                | Self::TruehdAudio
                | Self::EAc3Audio
                | Self::DtsHdAudio
                | Self::DtsHdMaAudio
                | Self::EAc3SecondaryAudio
                | Self::DtsHdSecondaryAudio
        )
    }

    /// `true` when the stream carries subtitles or interactive graphics.
    pub fn is_subtitle(self) -> bool {
        matches!(
            self,
            Self::PgsSubtitle | Self::IgsInteractive | Self::TextSubtitle
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_types() {
        for raw in [0x02u8, 0x1B, 0x24, 0xEA, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x90, 0x91, 0x92, 0xA1, 0xA2] {
            assert_eq!(StreamType::from_raw(raw).as_raw(), raw);
        }
    }

    #[test]
    fn unknown_types_pass_through() {
        let s = StreamType::from_raw(0x77);
        assert_eq!(s, StreamType::Other(0x77));
        assert_eq!(s.as_raw(), 0x77);
        assert!(!s.is_video() && !s.is_audio() && !s.is_subtitle());
    }

    #[test]
    fn classification() {
        assert!(StreamType::AvcVideo.is_video());
        assert!(StreamType::Ac3Audio.is_audio());
        assert!(StreamType::PgsSubtitle.is_subtitle());
    }
}
