//! This module implements hash_to_curve, hash_to_field and related
//! hashing primitives for use with BLS signatures.

mod expand_msg;
pub use self::expand_msg::{
    ExpandMessage, ExpandMessageState, ExpandMsgXmd, ExpandMsgXof, InitExpandMessage,
};

use crate::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

/// Enables a byte string to be hashed into one or more field elements for a given curve.
///
/// Implements [section 5 of `draft-irtf-cfrg-hash-to-curve-12`][hash_to_field].
///
/// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5
pub trait HashToField: Sized {
    /// The length of the data used to produce an individual field element.
    ///
    /// This must be set to `m * L = m * ceil((ceil(log2(p)) + k) / 8)`, where `p` is the
    /// characteristic of `Self`, `m` is the extension degree of `Self`, and `k` is the
    /// security parameter.
    type InputLength: ArrayLength<u8>;

    /// Interprets the given output keying material as a big endian integer, and reduces
    /// it into a field element.
    fn from_okm(okm: &GenericArray<u8, Self::InputLength>) -> Self;

    /// Hashes a byte string of arbitrary length into one or more elements of `Self`,
    /// using [`ExpandMessage`] variant `X`.
    ///
    /// Implements [section 5.3 of `draft-irtf-cfrg-hash-to-curve-12`][hash_to_field].
    ///
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.3
    fn hash_to_field<X: ExpandMessage>(message: &[u8], dst: &[u8], output: &mut [Self]) {
        let len_per_elm = Self::InputLength::to_usize();
        let len_in_bytes = output.len() * len_per_elm;
        let mut expander = X::init_expand(message, dst, len_in_bytes);

        let mut buf = GenericArray::<u8, Self::InputLength>::default();
        output.iter_mut().for_each(|item| {
            expander.read_into(&mut buf[..]);
            *item = Self::from_okm(&buf);
        });
    }
}
