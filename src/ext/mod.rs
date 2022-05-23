/// This module extends data structures defined in this crate but outside of
/// this module. The purpose is to
/// 1. Expose the required `blst` APIs which are not available, and try to
/// avoid downstream dependency on `blst`
/// 2. Define some useful crypto primitives like hash-to-curve etc.


/// Minimum ikm size in bytes.
pub const MIN_IKM_LENGTH_BYTES: usize = 32;

/// Key generation based on `blst` APIs.
pub mod key_gen;