//! HKDF helpers shared across the msphf stack.

use blake3::Hasher;

/// Derive a 32-byte key using HKDF built from BLAKE3.
///
/// This follows the construction used throughout the City-G profile:
/// HKDF-Extract with the salt as the BLAKE3 key, followed by HKDF-Expand
/// where the PRK becomes the key for the expand step and a counter of 0x01
/// is appended to the info string.
pub fn hkdf_blake3(salt: &[u8; 32], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = Hasher::new_keyed(salt);
    extract.update(ikm);
    let prk = extract.finalize();

    let mut expand = Hasher::new_keyed(prk.as_bytes());
    expand.update(info);
    expand.update(&[1u8]);
    let okm = expand.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(okm.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MsphfError, hash::h_l};
    use serde::Serialize;

    #[test]
    fn hkdf_vector_hp_kek_matches_spec() -> Result<(), MsphfError> {
        let xk_hash = [0x11u8; 32];
        let hp_commit = [0x22u8; 32];
        let kem_ss = [0x33u8; 32];

        #[derive(Serialize)]
        struct KekSalt<'a> {
            #[serde(with = "serde_bytes")]
            xk_hash: &'a [u8; 32],
        }

        let salt = h_l("hp/kek/salt", &KekSalt { xk_hash: &xk_hash })?;

        let mut info = b"city-g|hp/kek/v1".to_vec();
        info.extend_from_slice(&hp_commit);

        let derived = hkdf_blake3(&salt, kem_ss.as_slice(), &info);
        assert_eq!(
            derived,
            hex_literal::hex!("bb67b4e885abfcd171b1be95b27f0dc86f303c19317c171d59e6d8b8e2b86657")
        );
        Ok(())
    }

    #[test]
    fn hkdf_vector_fs_epoch_matches_spec() -> Result<(), MsphfError> {
        let weid = [0x44u8; 32];
        let fs_ec: u64 = 0x0102_0304_0506_0708;
        let k_fs = [0x55u8; 32];

        #[derive(Serialize)]
        struct FsEpochSalt<'a> {
            #[serde(with = "serde_bytes")]
            weid: &'a [u8; 32],
            fs_ec: u64,
        }

        let epoch_salt = h_l("fs/epoch/salt", &FsEpochSalt { weid: &weid, fs_ec })?;
        let epoch_sk_salt = h_l("fs/epoch/sk_salt", &FsEpochSalt { weid: &weid, fs_ec })?;

        let tau = hkdf_blake3(&epoch_salt, &k_fs, b"city-g|fs/epoch/tau|v1");
        assert_eq!(
            tau,
            hex_literal::hex!("9b1f09bf75f12c042f7b0b967824220b8f839000ee6dcac0e72e1221c15d048f")
        );

        let epoch_sk = hkdf_blake3(&epoch_sk_salt, &k_fs, b"city-g|fs/epoch/sk|v1");
        assert_eq!(
            epoch_sk,
            hex_literal::hex!("9dbeb1b2f8445d61e6f7f9186cd84008fa338a71d002ffbab44aabb4bcc26b9a")
        );
        Ok(())
    }

    #[test]
    fn hp_kek_nonce_domain_separator_stable() -> Result<(), MsphfError> {
        #[derive(Serialize)]
        struct NonceCtx<'a> {
            #[serde(with = "serde_bytes")]
            xk_hash: &'a [u8; 32],
            #[serde(with = "serde_bytes")]
            hp_commit: &'a [u8; 32],
        }

        let xk_hash = [0xAAu8; 32];
        let hp_commit = [0xBBu8; 32];
        let derived = h_l(
            "hp/kek/nonce",
            &NonceCtx {
                xk_hash: &xk_hash,
                hp_commit: &hp_commit,
            },
        )?;
        assert_eq!(
            derived,
            hex_literal::hex!("3e292f176a4d936907ff598f49e47ca41e385661975059c46b96d7b117409424")
        );
        Ok(())
    }

    #[test]
    fn hp_nonce_domain_separator_stable() -> Result<(), MsphfError> {
        #[derive(Serialize)]
        struct NonceCtx<'a> {
            #[serde(with = "serde_bytes")]
            xk_hash: &'a [u8; 32],
            #[serde(with = "serde_bytes")]
            hp_commit: &'a [u8; 32],
        }

        let xk_hash = [0xAAu8; 32];
        let hp_commit = [0xBBu8; 32];
        let derived = h_l(
            "hp/nonce",
            &NonceCtx {
                xk_hash: &xk_hash,
                hp_commit: &hp_commit,
            },
        )?;
        assert_eq!(
            derived,
            hex_literal::hex!("877c755076d1f436280ec251c3ad22c24284e82877a3aff3dd19532fd6cc5d0d")
        );
        Ok(())
    }
}
