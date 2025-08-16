use crate::{Error, Result};
use aes::Aes128;
use cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use dryoc::{
    classic::{
        crypto_core::crypto_scalarmult,
        crypto_sign_ed25519::{
            crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
        },
    },
    constants::{CRYPTO_SCALARMULT_CURVE25519_BYTES, CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Signature(pub [u8; 64]);

pub type HmacSha256 = Hmac<Sha256>;

const CIPHER_MAC_SIZE: usize = 2;

pub fn cipher_mac(src: &[u8], key: &[u8]) -> Result<[u8; CIPHER_MAC_SIZE]> {
    let mut hmac = <HmacSha256 as hmac::Mac>::new_from_slice(key).unwrap();
    hmac.update(src);
    let mut res = [0u8; CIPHER_MAC_SIZE];
    res.copy_from_slice(&hmac.finalize().into_bytes()[..CIPHER_MAC_SIZE]);
    Ok(res)
}

pub fn aes_ecb_decrypt<'a>(dst: &'a mut [u8], src: &[u8], key: &[u8; 16]) -> Result<&'a [u8]> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);
    if src.len() % 16 != 0 {
        return Err(Error::ParseError);
    }
    for (in_block, out_block) in src.chunks_exact(16).zip(dst.chunks_exact_mut(16)) {
        cipher.decrypt_block_b2b(in_block.into(), out_block.into());
    }
    Ok(&dst[..src.len()])
}

pub fn ed25519_key_exchange(q: &mut [u8; 32], pk: &[u8; 32], sk: &[u8; 64]) -> Result<()> {
    let mut xpk = [0u8; CRYPTO_SCALARMULT_CURVE25519_BYTES];
    let mut xsk = [0u8; CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES];
    crypto_sign_ed25519_pk_to_curve25519(&mut xpk, &pk).map_err(|_| Error::VerifyError)?;
    crypto_sign_ed25519_sk_to_curve25519(&mut xsk, &sk);
    crypto_scalarmult(q, &xsk, &xpk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::ed25519_key_exchange;

    #[test]
    fn shared_secret() {
        let sk = [
            0x7f, 0x87, 0xfd, 0x4b, 0xb9, 0xf9, 0x61, 0x7c, 0xba, 0xe9, 0xf4, 0x1f, 0x27, 0x87,
            0x15, 0xef, 0x64, 0x82, 0x77, 0x9c, 0xfd, 0x74, 0xd0, 0x60, 0x59, 0x29, 0x9a, 0x57,
            0xef, 0xc2, 0xcf, 0xde, 0xb1, 0x53, 0xa0, 0x7a, 0xcb, 0xf7, 0x24, 0x36, 0x48, 0x58,
            0x1d, 0x9b, 0xa5, 0xf5, 0x6c, 0x5b, 0xf2, 0x7b, 0xf0, 0x23, 0xa7, 0x18, 0x1b, 0x53,
            0xc4, 0x34, 0x86, 0x32, 0x1f, 0xf3, 0xaa, 0x46,
        ];
        let other_pk = [
            0x7f, 0xe2, 0x13, 0xe5, 0x0b, 0x8a, 0xcb, 0x6a, 0x07, 0x88, 0x08, 0x5d, 0x73, 0xcc,
            0x3f, 0xf2, 0x88, 0xa4, 0xe0, 0x53, 0xc2, 0x92, 0xd2, 0x61, 0xc9, 0xa3, 0xea, 0xe8,
            0x3a, 0x14, 0xa3, 0xa8,
        ];
        let mut shared_secret = [0u8; 32];
        ed25519_key_exchange(&mut shared_secret, &other_pk, &sk).unwrap();
        assert_eq!(
            shared_secret,
            [
                0x73, 0xc8, 0x9b, 0xda, 0xcf, 0xa4, 0xc9, 0x87, 0x9a, 0xf9, 0x6a, 0xa4, 0x0e, 0xb5,
                0x77, 0xef, 0x5e, 0xca, 0x62, 0x35, 0xdf, 0x5e, 0xb7, 0x30, 0x31, 0xc5, 0x3c, 0x31,
                0x2f, 0x76, 0xc2, 0x68
            ]
        )
    }
}
