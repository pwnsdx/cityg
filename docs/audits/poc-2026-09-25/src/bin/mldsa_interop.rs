//! Finding H-05: the native backend of crates/cityg-pqc signs with
//! pqcrypto-dilithium 0.5.0 `dilithium5` (labelled "ML-DSA-65" on the wire),
//! the wasm32 backend verifies with FIPS 204 ML-DSA-87 (fips204 0.4.6).
//! Same key/signature sizes, mutually unverifiable signatures.
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "pqcrypto dilithium5: pk={} sk={} sig={} | fips204 ml-dsa-87: pk={} sk={} sig={}",
        dilithium5::public_key_bytes(),
        dilithium5::secret_key_bytes(),
        dilithium5::signature_bytes(),
        ml_dsa_87::PK_LEN,
        ml_dsa_87::SK_LEN,
        ml_dsa_87::SIG_LEN
    );
    let message = b"city-g interop probe";

    // Native signer -> wasm verifier.
    let (native_pk, native_sk) = dilithium5::keypair();
    let native_sig = dilithium5::detached_sign(message, &native_sk);
    let wasm_pk = ml_dsa_87::PublicKey::try_from_bytes(
        native_pk
            .as_bytes()
            .try_into()
            .map_err(|_| "public key length")?,
    )
    .map_err(|err| format!("fips204 public key: {err}"))?;
    let native_sig_arr: [u8; ml_dsa_87::SIG_LEN] = native_sig
        .as_bytes()
        .try_into()
        .map_err(|_| "signature length")?;
    println!(
        "fips204 ML-DSA-87 verifies a pqcrypto dilithium5 signature: {}",
        wasm_pk.verify(message, &native_sig_arr, &[])
    );

    // wasm signer -> native verifier.
    let (fips_pk, fips_sk) =
        ml_dsa_87::try_keygen().map_err(|err| format!("fips204 keygen: {err}"))?;
    let fips_sig = fips_sk
        .try_sign(message, &[])
        .map_err(|err| format!("fips204 sign: {err}"))?;
    let native_view_pk = dilithium5::PublicKey::from_bytes(&fips_pk.into_bytes())?;
    let native_view_sig = dilithium5::DetachedSignature::from_bytes(&fips_sig)?;
    println!(
        "pqcrypto dilithium5 verifies a fips204 ML-DSA-87 signature: {}",
        dilithium5::verify_detached_signature(&native_view_sig, message, &native_view_pk).is_ok()
    );
    Ok(())
}
