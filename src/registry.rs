//! Wiring into `oxideav-core`'s container registry. The Demuxer
//! factory + probe + extension hooks land here so a downstream
//! `RuntimeContext` populated by `oxideav-meta::register_all` ends
//! up with a working `"mpegts"` container.

use oxideav_core::{ContainerRegistry, RuntimeContext};

/// Install the MPEG-TS Demuxer factory + probe + file extensions on
/// a [`ContainerRegistry`].
///
/// Mirrors the shape every sibling container crate exposes
/// ([`oxideav_mkv::register_containers`], etc.) so the populate
/// helpers in `oxideav-meta` can call it through one uniform entry
/// point.
pub fn register_containers(reg: &mut ContainerRegistry) {
    reg.register_demuxer("mpegts", crate::demuxer::open);
    reg.register_probe("mpegts", crate::demuxer::probe);
    // Conventional file extensions for an MPEG-TS payload.
    reg.register_extension("ts", "mpegts");
    reg.register_extension("m2ts", "mpegts");
    reg.register_extension("mts", "mpegts");
}

/// Install the MPEG-TS container into a [`RuntimeContext`].
///
/// Convenience wrapper around [`register_containers`] matching the
/// uniform `register(&mut RuntimeContext)` entry point every sibling
/// crate exposes. Also wired into the `oxideav_meta::register_all`
/// fan-out via the [`oxideav_core::register!`] macro below.
pub fn register(ctx: &mut RuntimeContext) {
    register_containers(&mut ctx.containers);
}

