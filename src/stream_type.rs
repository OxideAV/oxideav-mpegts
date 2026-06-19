//! `stream_type` byte → richer enum.
//!
//! The base assignments come from ISO/IEC 13818-1 Table 2-29 (the
//! "Stream type assignments" table; the same content later editions
//! renumber as Table 2-34) plus the H.264 / SVC / MVC / HEVC values
//! added by subsequent amendments. The crate additionally recognises
//! the HDMV-extended range (`0x80..=0xFF`) that BD-ROM Part 3 §5 uses
//! for Blu-ray elementary streams, since this demuxer's primary input
//! is `.m2ts` payload.
//!
//! Every value the enum doesn't name is preserved as [`StreamType::Other`]
//! so callers never lose the raw byte.

/// One elementary-stream codec / payload class (`stream_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// `0x01` ISO/IEC 11172-2 video (MPEG-1 video).
    Mpeg1Video,
    /// `0x02` ITU-T H.262 | ISO/IEC 13818-2 video (MPEG-2 video), or an
    /// ISO/IEC 11172-2 constrained-parameter video stream.
    Mpeg2Video,
    /// `0x03` ISO/IEC 11172-3 audio (MPEG-1 audio, e.g. MP1/MP2/MP3).
    Mpeg1Audio,
    /// `0x04` ISO/IEC 13818-3 audio (MPEG-2 audio).
    Mpeg2Audio,
    /// `0x05` ITU-T H.222.0 | ISO/IEC 13818-1 `private_sections`.
    PrivateSections,
    /// `0x06` ITU-T H.222.0 | ISO/IEC 13818-1 PES packets carrying
    /// private data (the carrier DVB uses for subtitles / teletext /
    /// AC-3 / DTS — disambiguated by the stream's descriptors).
    PrivatePes,
    /// `0x07` ISO/IEC 13522 MHEG.
    Mheg,
    /// `0x08` ITU-T H.222.0 | ISO/IEC 13818-1 Annex A DSM-CC.
    DsmCc,
    /// `0x09` ITU-T H.222.1.
    H2221,
    /// `0x0A` ISO/IEC 13818-6 type A (DSM-CC multiprotocol encapsulation).
    Dsmcc13818_6TypeA,
    /// `0x0B` ISO/IEC 13818-6 type B (DSM-CC U-N messages).
    Dsmcc13818_6TypeB,
    /// `0x0C` ISO/IEC 13818-6 type C (DSM-CC stream descriptors).
    Dsmcc13818_6TypeC,
    /// `0x0D` ISO/IEC 13818-6 type D (DSM-CC sections, any type).
    Dsmcc13818_6TypeD,
    /// `0x0E` ITU-T H.222.0 | ISO/IEC 13818-1 auxiliary.
    Auxiliary,
    /// `0x0F` ISO/IEC 13818-7 audio with ADTS transport syntax (AAC-ADTS).
    AacAdts,
    /// `0x10` ISO/IEC 14496-2 visual (MPEG-4 part 2 video).
    Mpeg4Visual,
    /// `0x11` ISO/IEC 14496-3 audio with the LATM transport syntax
    /// (MPEG-4 audio / AAC-LATM).
    AacLatm,
    /// `0x12` ISO/IEC 14496-1 SL-packetized / FlexMux stream carried in
    /// PES packets.
    Mpeg4SlPes,
    /// `0x13` ISO/IEC 14496-1 SL-packetized / FlexMux stream carried in
    /// ISO/IEC 14496 sections.
    Mpeg4SlSections,
    /// `0x14` ISO/IEC 13818-6 Synchronized Download Protocol.
    SyncDownloadProtocol,
    /// `0x15` Metadata carried in PES packets.
    MetadataPes,
    /// `0x16` Metadata carried in metadata sections.
    MetadataSections,
    /// `0x17` Metadata carried in ISO/IEC 13818-6 data carousel.
    MetadataDataCarousel,
    /// `0x18` Metadata carried in ISO/IEC 13818-6 object carousel.
    MetadataObjectCarousel,
    /// `0x19` Metadata carried in ISO/IEC 13818-6 Synchronized Download
    /// Protocol.
    MetadataSyncDownload,
    /// `0x1A` IPMP stream (ISO/IEC 13818-11, MPEG-2 IPMP).
    Ipmp,
    /// `0x1B` ITU-T H.264 | ISO/IEC 14496-10 video (AVC).
    AvcVideo,
    /// `0x1C` ISO/IEC 14496-3 audio, no additional transport syntax
    /// (raw MPEG-4 audio).
    Mpeg4AudioRaw,
    /// `0x1D` ISO/IEC 14496-17 text (MPEG-4 timed text).
    Mpeg4Text,
    /// `0x1E` Auxiliary video stream (ISO/IEC 23002-3).
    AuxiliaryVideo,
    /// `0x1F` SVC video sub-bitstream of an AVC stream (Annex G).
    SvcVideo,
    /// `0x20` MVC video sub-bitstream of an AVC stream (Annex H).
    MvcVideo,
    /// `0x21` JPEG 2000 video (ITU-T T.800 | ISO/IEC 15444-1).
    Jpeg2000Video,
    /// `0x22` Additional view of a stereoscopic MPEG-2 video stream.
    Mpeg2StereoView,
    /// `0x23` Additional view of a stereoscopic AVC video stream.
    AvcStereoView,
    /// `0x24` ITU-T H.265 | ISO/IEC 23008-2 video (HEVC).
    HevcVideo,
    /// `0x25` HEVC temporal video subset (Annex A tiers/levels).
    HevcTemporalSubset,
    /// `0x26` MVCD video sub-bitstream of an AVC stream.
    MvcdVideo,
    /// `0x42` Chinese AVS video (GB/T 20090.2 / AVS1-P2).
    AvsVideo,
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
            0x01 => Self::Mpeg1Video,
            0x02 => Self::Mpeg2Video,
            0x03 => Self::Mpeg1Audio,
            0x04 => Self::Mpeg2Audio,
            0x05 => Self::PrivateSections,
            0x06 => Self::PrivatePes,
            0x07 => Self::Mheg,
            0x08 => Self::DsmCc,
            0x09 => Self::H2221,
            0x0A => Self::Dsmcc13818_6TypeA,
            0x0B => Self::Dsmcc13818_6TypeB,
            0x0C => Self::Dsmcc13818_6TypeC,
            0x0D => Self::Dsmcc13818_6TypeD,
            0x0E => Self::Auxiliary,
            0x0F => Self::AacAdts,
            0x10 => Self::Mpeg4Visual,
            0x11 => Self::AacLatm,
            0x12 => Self::Mpeg4SlPes,
            0x13 => Self::Mpeg4SlSections,
            0x14 => Self::SyncDownloadProtocol,
            0x15 => Self::MetadataPes,
            0x16 => Self::MetadataSections,
            0x17 => Self::MetadataDataCarousel,
            0x18 => Self::MetadataObjectCarousel,
            0x19 => Self::MetadataSyncDownload,
            0x1A => Self::Ipmp,
            0x1B => Self::AvcVideo,
            0x1C => Self::Mpeg4AudioRaw,
            0x1D => Self::Mpeg4Text,
            0x1E => Self::AuxiliaryVideo,
            0x1F => Self::SvcVideo,
            0x20 => Self::MvcVideo,
            0x21 => Self::Jpeg2000Video,
            0x22 => Self::Mpeg2StereoView,
            0x23 => Self::AvcStereoView,
            0x24 => Self::HevcVideo,
            0x25 => Self::HevcTemporalSubset,
            0x26 => Self::MvcdVideo,
            0x42 => Self::AvsVideo,
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
            Self::Mpeg1Video => 0x01,
            Self::Mpeg2Video => 0x02,
            Self::Mpeg1Audio => 0x03,
            Self::Mpeg2Audio => 0x04,
            Self::PrivateSections => 0x05,
            Self::PrivatePes => 0x06,
            Self::Mheg => 0x07,
            Self::DsmCc => 0x08,
            Self::H2221 => 0x09,
            Self::Dsmcc13818_6TypeA => 0x0A,
            Self::Dsmcc13818_6TypeB => 0x0B,
            Self::Dsmcc13818_6TypeC => 0x0C,
            Self::Dsmcc13818_6TypeD => 0x0D,
            Self::Auxiliary => 0x0E,
            Self::AacAdts => 0x0F,
            Self::Mpeg4Visual => 0x10,
            Self::AacLatm => 0x11,
            Self::Mpeg4SlPes => 0x12,
            Self::Mpeg4SlSections => 0x13,
            Self::SyncDownloadProtocol => 0x14,
            Self::MetadataPes => 0x15,
            Self::MetadataSections => 0x16,
            Self::MetadataDataCarousel => 0x17,
            Self::MetadataObjectCarousel => 0x18,
            Self::MetadataSyncDownload => 0x19,
            Self::Ipmp => 0x1A,
            Self::AvcVideo => 0x1B,
            Self::Mpeg4AudioRaw => 0x1C,
            Self::Mpeg4Text => 0x1D,
            Self::AuxiliaryVideo => 0x1E,
            Self::SvcVideo => 0x1F,
            Self::MvcVideo => 0x20,
            Self::Jpeg2000Video => 0x21,
            Self::Mpeg2StereoView => 0x22,
            Self::AvcStereoView => 0x23,
            Self::HevcVideo => 0x24,
            Self::HevcTemporalSubset => 0x25,
            Self::MvcdVideo => 0x26,
            Self::AvsVideo => 0x42,
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

    /// `true` when the stream carries video.
    pub fn is_video(self) -> bool {
        matches!(
            self,
            Self::Mpeg1Video
                | Self::Mpeg2Video
                | Self::Mpeg4Visual
                | Self::AvcVideo
                | Self::AuxiliaryVideo
                | Self::SvcVideo
                | Self::MvcVideo
                | Self::Jpeg2000Video
                | Self::Mpeg2StereoView
                | Self::AvcStereoView
                | Self::HevcVideo
                | Self::HevcTemporalSubset
                | Self::MvcdVideo
                | Self::AvsVideo
                | Self::Vc1Video
        )
    }

    /// `true` when the stream carries audio (primary or secondary).
    pub fn is_audio(self) -> bool {
        matches!(
            self,
            Self::Mpeg1Audio
                | Self::Mpeg2Audio
                | Self::AacAdts
                | Self::AacLatm
                | Self::Mpeg4AudioRaw
                | Self::LpcmAudio
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

    /// `true` when the stream carries subtitles, captions, or interactive
    /// graphics (HDMV PGS / IGS / TextST and MPEG-4 timed text).
    pub fn is_subtitle(self) -> bool {
        matches!(
            self,
            Self::PgsSubtitle | Self::IgsInteractive | Self::TextSubtitle | Self::Mpeg4Text
        )
    }

    /// `true` when the stream is a metadata payload (the `0x15..=0x19`
    /// metadata carriers).
    pub fn is_metadata(self) -> bool {
        matches!(
            self,
            Self::MetadataPes
                | Self::MetadataSections
                | Self::MetadataDataCarousel
                | Self::MetadataObjectCarousel
                | Self::MetadataSyncDownload
        )
    }

    /// `true` when the value is one that, per ISO/IEC 13818-1 §2.4.4.10,
    /// requires reading the stream's descriptors to identify the actual
    /// codec — i.e. `private_sections` (`0x05`) and the private-data PES
    /// carrier (`0x06`) DVB layers AC-3 / DTS / subtitling / teletext on.
    pub fn is_private(self) -> bool {
        matches!(self, Self::PrivateSections | Self::PrivatePes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_named_types() {
        for raw in [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x42, 0xEA, 0x80, 0x81,
            0x82, 0x83, 0x84, 0x85, 0x86, 0x90, 0x91, 0x92, 0xA1, 0xA2,
        ] {
            assert_eq!(
                StreamType::from_raw(raw).as_raw(),
                raw,
                "round-trip failed for 0x{raw:02X}"
            );
            // None of the named bytes should collapse into Other.
            assert!(
                !matches!(StreamType::from_raw(raw), StreamType::Other(_)),
                "0x{raw:02X} unexpectedly mapped to Other"
            );
        }
    }

    #[test]
    fn reserved_range_passes_through_as_other() {
        // 0x27..=0x41 and 0x43..=0x7F are reserved; surface the raw byte.
        for raw in [0x27u8, 0x30, 0x41, 0x43, 0x77, 0x7F] {
            let s = StreamType::from_raw(raw);
            assert_eq!(s, StreamType::Other(raw));
            assert_eq!(s.as_raw(), raw);
            assert!(!s.is_video() && !s.is_audio() && !s.is_subtitle());
        }
    }

    #[test]
    fn classification_video() {
        for s in [
            StreamType::Mpeg1Video,
            StreamType::Mpeg2Video,
            StreamType::Mpeg4Visual,
            StreamType::AvcVideo,
            StreamType::SvcVideo,
            StreamType::MvcVideo,
            StreamType::Jpeg2000Video,
            StreamType::HevcVideo,
            StreamType::AvsVideo,
            StreamType::Vc1Video,
        ] {
            assert!(s.is_video(), "{s:?} should be video");
            assert!(!s.is_audio() && !s.is_subtitle());
        }
    }

    #[test]
    fn classification_audio() {
        for s in [
            StreamType::Mpeg1Audio,
            StreamType::Mpeg2Audio,
            StreamType::AacAdts,
            StreamType::AacLatm,
            StreamType::Mpeg4AudioRaw,
            StreamType::Ac3Audio,
            StreamType::DtsAudio,
            StreamType::EAc3Audio,
            StreamType::DtsHdMaAudio,
        ] {
            assert!(s.is_audio(), "{s:?} should be audio");
            assert!(!s.is_video() && !s.is_subtitle());
        }
    }

    #[test]
    fn classification_subtitle_and_text() {
        for s in [
            StreamType::PgsSubtitle,
            StreamType::IgsInteractive,
            StreamType::TextSubtitle,
            StreamType::Mpeg4Text,
        ] {
            assert!(s.is_subtitle(), "{s:?} should be subtitle/text");
        }
    }

    #[test]
    fn classification_metadata_and_private() {
        assert!(StreamType::MetadataPes.is_metadata());
        assert!(StreamType::MetadataObjectCarousel.is_metadata());
        assert!(!StreamType::AvcVideo.is_metadata());
        assert!(StreamType::PrivateSections.is_private());
        assert!(StreamType::PrivatePes.is_private());
        assert!(!StreamType::Ac3Audio.is_private());
    }
}
