use blst::blst_scalar;
use group::prime::PrimeCurveAffine;

use crate::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

/// Minimum ikm size in bytes.
pub const MIN_IKM_LENGTH_BYTES: usize = 32;

/// Computes a secret key from an IKM, as defined by
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
pub fn generate_sk<T>(ikm: T, key_info: T) -> Option<Scalar>
where
    T: AsRef<[u8]>,
{
    use core::convert::TryInto;
    let ikm = ikm.as_ref();
    if ikm.len() < MIN_IKM_LENGTH_BYTES {
        return None;
    }

    let key_info = key_info.as_ref();
    let mut out = blst::blst_scalar::default();
    unsafe {
        blst::blst_keygen(
            &mut out,
            ikm.as_ptr(),
            ikm.len(),
            key_info.as_ptr(),
            key_info.len(),
        )
    };

    out.try_into().ok()
}

/// Generate a public key in G1 from a secret key, as defined by
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.4>
pub fn sk_to_pk_in_g1(s: &Scalar) -> G1Projective {
    let mut pk = G1Affine::identity();
    let sc: blst_scalar = Scalar::into(*s);

    unsafe {
        blst::blst_sk_to_pk2_in_g1(std::ptr::null_mut(), pk.as_mut(), &sc);
    }

    pk.into()
}

/// Generate a public key in G2 from a secret key, as defined by
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.4>
pub fn sk_to_pk_in_g2(s: &Scalar) -> G2Projective {
    let mut pk = G2Affine::identity();
    let sc: blst_scalar = Scalar::into(*s);

    unsafe {
        blst::blst_sk_to_pk2_in_g2(std::ptr::null_mut(), pk.as_mut(), &sc);
    }

    pk.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::Group;

    #[test]
    fn test_generate_sk() {
        let ikm = [0u8; MIN_IKM_LENGTH_BYTES];
        let key_info = [];

        let sk = generate_sk(ikm.as_ref(), key_info.as_ref());
        let expected = [
            77, 18, 154, 25, 223, 134, 160, 245, 52, 91, 173, 76, 198, 242, 73, 236, 42, 129, 156,
            204, 51, 134, 137, 91, 235, 79, 125, 152, 179, 219, 98, 53,
        ];
        assert_eq!(sk.unwrap().to_bytes_be(), expected);
    }

    #[test]
    fn test_sk_to_pk_in_g1() {
        // secret key in big-endian format
        let sk = [
            77, 18, 154, 25, 223, 134, 160, 245, 52, 91, 173, 76, 198, 242, 73, 236, 42, 129, 156,
            204, 51, 134, 137, 91, 235, 79, 125, 152, 179, 219, 98, 53,
        ];
        let sk = Scalar::from_bytes_be(&sk).unwrap();
        let pk = sk_to_pk_in_g1(&sk);

        assert_eq!(1, pk.is_on_curve().unwrap_u8());
        assert_eq!(0, pk.is_identity().unwrap_u8());
    }

    #[test]
    fn test_sk_to_pk_in_g2() {
        // secret key in big-endian format
        let sk = [
            77, 18, 154, 25, 223, 134, 160, 245, 52, 91, 173, 76, 198, 242, 73, 236, 42, 129, 156,
            204, 51, 134, 137, 91, 235, 79, 125, 152, 179, 219, 98, 53,
        ];
        let sk = Scalar::from_bytes_be(&sk).unwrap();
        let pk = sk_to_pk_in_g2(&sk);

        assert_eq!(1, pk.is_on_curve().unwrap_u8());
        assert_eq!(0, pk.is_identity().unwrap_u8());
    }
}
