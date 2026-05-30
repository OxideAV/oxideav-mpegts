//! Wiring into `oxideav-core`'s container registry. Stub.

#[cfg(feature = "registry")]
use oxideav_core::RuntimeContext;

/// Register the MPEG-TS container declaration in the runtime
/// context. Stub — to be filled by a downstream pass that wires
/// the actual demuxer factory.
#[cfg(feature = "registry")]
pub fn register(_ctx: &mut RuntimeContext) {
    // TODO: hook the demuxer factory once `oxideav-mpegts::pes` and
    // `psi` land. For now this is a placeholder so the workspace's
    // `populate_container_registry` doesn't crash on us.
}
