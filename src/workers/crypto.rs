//! WebCrypto host primitives backed by `ring`.

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64U};
use base64::Engine;
use boa_engine::{Context, JsError, JsNativeError, JsResult, JsString, JsValue};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::rsa;
use ring::signature::{
    self, EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
};
use serde::{Deserialize, Serialize};

fn throw(msg: impl Into<String>) -> JsError {
    JsNativeError::typ().with_message(msg.into()).into()
}

fn arg_str(args: &[JsValue], idx: usize, ctx: &mut Context) -> JsResult<String> {
    Ok(args.get(idx).cloned().unwrap_or_default().to_string(ctx)?.to_std_string_lossy())
}

fn b64_dec(s: &str) -> Result<Vec<u8>, JsError> {
    B64.decode(s).map_err(|e| throw(format!("invalid base64: {e}")))
}

fn b64u_dec(s: &str) -> Result<Vec<u8>, JsError> {
    B64U.decode(s.trim_end_matches('=')).map_err(|e| throw(format!("invalid base64url: {e}")))
}

/// `__cryptoRandom(len)` -> base64 random bytes.
pub fn host_crypto_random(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let len = args.first().cloned().unwrap_or_default().to_u32(ctx)? as usize;
    if len > 65536 {
        return Err(throw("QuotaExceededError: getRandomValues length > 65536"));
    }
    let mut buf = vec![0u8; len];
    SystemRandom::new().fill(&mut buf).map_err(|_| throw("rng failed"))?;
    Ok(JsString::from(B64.encode(&buf)).into())
}

/// `__cryptoDigest(alg, data_b64)` -> base64 digest.
pub fn host_crypto_digest(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let alg = arg_str(args, 0, ctx)?.to_ascii_uppercase();
    let data = b64_dec(&arg_str(args, 1, ctx)?)?;
    let d_alg = match alg.as_str() {
        "SHA-1" => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        "SHA-256" => &digest::SHA256,
        "SHA-384" => &digest::SHA384,
        "SHA-512" => &digest::SHA512,
        _ => return Err(throw(format!("NotSupportedError: unsupported digest algorithm '{alg}'"))),
    };
    let out = digest::digest(d_alg, &data);
    Ok(JsString::from(B64.encode(out.as_ref())).into())
}

#[derive(Deserialize)]
struct SignReq {
    alg: String,
    hash: Option<String>,
    curve: Option<String>,
    key_format: String,
    key_b64: String,
    data_b64: String,
}

#[derive(Deserialize)]
struct VerifyReq {
    alg: String,
    hash: Option<String>,
    curve: Option<String>,
    key_format: String,
    key_b64: String,
    sig_b64: String,
    data_b64: String,
}

#[derive(Deserialize)]
struct AeadReq {
    key_b64: String,
    iv_b64: String,
    aad_b64: Option<String>,
    data_b64: String,
}

#[derive(Deserialize, Serialize)]
struct EcJwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
    #[serde(default)]
    d: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct RsaJwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + body.len());
    out.push(tag);
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

fn der_uint(bytes: &[u8]) -> Vec<u8> {
    let trimmed = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &[0u8],
    };
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(trimmed);
    der_tlv(0x02, &body)
}

fn read_der_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), JsError> {
    if data.len() < 2 {
        return Err(throw("invalid DER"));
    }
    let tag = data[0];
    let (len, hdr) = if data[1] < 0x80 {
        (data[1] as usize, 2)
    } else {
        let n = (data[1] & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(throw("invalid DER length"));
        }
        let mut l = 0usize;
        for &b in &data[2..2 + n] {
            l = (l << 8) | (b as usize);
        }
        (l, 2 + n)
    };
    if data.len() < hdr + len {
        return Err(throw("truncated DER"));
    }
    Ok((tag, &data[hdr..hdr + len], &data[hdr + len..]))
}

/// Extract inner BIT STRING payload from SubjectPublicKeyInfo DER.
fn spki_to_bitstring(spki: &[u8]) -> Result<Vec<u8>, JsError> {
    let (tag, body, _) = read_der_tlv(spki)?;
    if tag != 0x30 {
        return Err(throw("SPKI is not a SEQUENCE"));
    }
    let (_, _, rest) = read_der_tlv(body)?; // AlgorithmIdentifier
    let (bs_tag, bs_body, _) = read_der_tlv(rest)?;
    if bs_tag != 0x03 || bs_body.is_empty() {
        return Err(throw("SPKI missing BIT STRING"));
    }
    Ok(bs_body[1..].to_vec()) // skip unused-bits byte
}

fn rsa_jwk_to_pkcs1_pub(jwk_json: &[u8]) -> Result<Vec<u8>, JsError> {
    let jwk: RsaJwk = serde_json::from_slice(jwk_json).map_err(|e| throw(format!("bad RSA JWK: {e}")))?;
    if jwk.kty != "RSA" {
        return Err(throw("expected RSA JWK"));
    }
    let n = b64u_dec(&jwk.n)?;
    let e = b64u_dec(&jwk.e)?;
    let mut inner = der_uint(&n);
    inner.extend_from_slice(&der_uint(&e));
    Ok(der_tlv(0x30, &inner))
}

fn ec_jwk_to_uncompressed(jwk_json: &[u8], expected_curve: &str) -> Result<Vec<u8>, JsError> {
    let jwk: EcJwk = serde_json::from_slice(jwk_json).map_err(|e| throw(format!("bad EC JWK: {e}")))?;
    if jwk.kty != "EC" || jwk.crv != expected_curve {
        return Err(throw(format!("EC JWK curve mismatch: expected {expected_curve}")));
    }
    let coord_len = match expected_curve {
        "P-256" => 32,
        "P-384" => 48,
        _ => return Err(throw("unsupported EC curve")),
    };
    let x = b64u_dec(&jwk.x)?;
    let y = b64u_dec(&jwk.y)?;
    if x.len() != coord_len || y.len() != coord_len {
        return Err(throw("invalid EC JWK coordinate length"));
    }
    let mut out = Vec::with_capacity(1 + coord_len * 2);
    out.push(0x04);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Ok(out)
}

pub fn host_crypto_sign(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let req: SignReq = serde_json::from_str(&arg_str(args, 0, ctx)?).map_err(|e| throw(e.to_string()))?;
    let key_bytes = b64_dec(&req.key_b64)?;
    let data = b64_dec(&req.data_b64)?;
    let rng = SystemRandom::new();

    let sig: Vec<u8> = match req.alg.to_ascii_uppercase().as_str() {
        "HMAC" => {
            let hash = req.hash.as_deref().unwrap_or("SHA-256").to_ascii_uppercase();
            let halg = match hash.as_str() {
                "SHA-256" => hmac::HMAC_SHA256,
                "SHA-384" => hmac::HMAC_SHA384,
                "SHA-512" => hmac::HMAC_SHA512,
                _ => return Err(throw(format!("unsupported HMAC hash '{hash}'"))),
            };
            let k = hmac::Key::new(halg, &key_bytes);
            hmac::sign(&k, &data).as_ref().to_vec()
        }
        "ECDSA" => {
            let curve = req.curve.as_deref().unwrap_or("P-256");
            if req.key_format != "pkcs8" {
                return Err(throw("ECDSA signing requires pkcs8 key"));
            }
            let sal = match curve {
                "P-256" => &ECDSA_P256_SHA256_FIXED_SIGNING,
                "P-384" => &ECDSA_P384_SHA384_FIXED_SIGNING,
                _ => return Err(throw(format!("unsupported ECDSA curve '{curve}'"))),
            };
            let kp = EcdsaKeyPair::from_pkcs8(sal, &key_bytes, &rng)
                .map_err(|e| throw(format!("invalid ECDSA pkcs8 key: {e}")))?;
            kp.sign(&rng, &data).map_err(|_| throw("ECDSA sign failed"))?.as_ref().to_vec()
        }
        "RSASSA-PKCS1-V1_5" => {
            if req.key_format != "pkcs8" {
                return Err(throw("RSA signing requires pkcs8 key"));
            }
            let hash = req.hash.as_deref().unwrap_or("SHA-256").to_ascii_uppercase();
            let pad: &'static dyn signature::RsaEncoding = match hash.as_str() {
                "SHA-256" => &signature::RSA_PKCS1_SHA256,
                "SHA-384" => &signature::RSA_PKCS1_SHA384,
                "SHA-512" => &signature::RSA_PKCS1_SHA512,
                _ => return Err(throw(format!("unsupported RSA hash '{hash}'"))),
            };
            let kp = rsa::KeyPair::from_pkcs8(&key_bytes)
                .map_err(|e| throw(format!("invalid RSA pkcs8 key: {e}")))?;
            let mut out = vec![0u8; kp.public().modulus_len()];
            kp.sign(pad, &rng, &data, &mut out).map_err(|_| throw("RSA sign failed"))?;
            out
        }
        other => return Err(throw(format!("unsupported sign algorithm '{other}'"))),
    };

    Ok(JsString::from(B64.encode(&sig)).into())
}

pub fn host_crypto_verify(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let req: VerifyReq = serde_json::from_str(&arg_str(args, 0, ctx)?).map_err(|e| throw(e.to_string()))?;
    let key_bytes = b64_dec(&req.key_b64)?;
    let sig = b64_dec(&req.sig_b64)?;
    let data = b64_dec(&req.data_b64)?;

    let ok = match req.alg.to_ascii_uppercase().as_str() {
        "HMAC" => {
            let hash = req.hash.as_deref().unwrap_or("SHA-256").to_ascii_uppercase();
            let halg = match hash.as_str() {
                "SHA-256" => hmac::HMAC_SHA256,
                "SHA-384" => hmac::HMAC_SHA384,
                "SHA-512" => hmac::HMAC_SHA512,
                _ => return Err(throw(format!("unsupported HMAC hash '{hash}'"))),
            };
            let k = hmac::Key::new(halg, &key_bytes);
            hmac::verify(&k, &data, &sig).is_ok()
        }
        "ECDSA" => {
            let curve = req.curve.as_deref().unwrap_or("P-256");
            let valg: &'static dyn signature::VerificationAlgorithm = match curve {
                "P-256" => &ECDSA_P256_SHA256_FIXED,
                "P-384" => &ECDSA_P384_SHA384_FIXED,
                _ => return Err(throw(format!("unsupported ECDSA curve '{curve}'"))),
            };
            let pub_bytes = match req.key_format.as_str() {
                "spki" => spki_to_bitstring(&key_bytes)?,
                "raw" => key_bytes,
                "jwk" => ec_jwk_to_uncompressed(&key_bytes, curve)?,
                "pkcs8" => {
                    let sal = if curve == "P-256" {
                        &ECDSA_P256_SHA256_FIXED_SIGNING
                    } else {
                        &ECDSA_P384_SHA384_FIXED_SIGNING
                    };
                    let kp = EcdsaKeyPair::from_pkcs8(sal, &key_bytes, &SystemRandom::new())
                        .map_err(|e| throw(format!("invalid ECDSA pkcs8 key: {e}")))?;
                    kp.public_key().as_ref().to_vec()
                }
                _ => return Err(throw("unsupported ECDSA key format")),
            };
            UnparsedPublicKey::new(valg, &pub_bytes).verify(&data, &sig).is_ok()
        }
        "RSASSA-PKCS1-V1_5" => {
            let hash = req.hash.as_deref().unwrap_or("SHA-256").to_ascii_uppercase();
            let valg: &'static dyn signature::VerificationAlgorithm = match hash.as_str() {
                "SHA-256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "SHA-384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                "SHA-512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                _ => return Err(throw(format!("unsupported RSA hash '{hash}'"))),
            };
            let pub_bytes = match req.key_format.as_str() {
                "spki" => spki_to_bitstring(&key_bytes)?,
                "jwk" => rsa_jwk_to_pkcs1_pub(&key_bytes)?,
                "pkcs8" => {
                    let kp = rsa::KeyPair::from_pkcs8(&key_bytes)
                        .map_err(|e| throw(format!("invalid RSA pkcs8 key: {e}")))?;
                    kp.public_key().as_ref().to_vec()
                }
                _ => return Err(throw("unsupported RSA key format")),
            };
            UnparsedPublicKey::new(valg, &pub_bytes).verify(&data, &sig).is_ok()
        }
        other => return Err(throw(format!("unsupported verify algorithm '{other}'"))),
    };

    Ok(JsValue::from(ok))
}

pub fn host_crypto_encrypt(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let req: AeadReq = serde_json::from_str(&arg_str(args, 0, ctx)?).map_err(|e| throw(e.to_string()))?;
    let key_bytes = b64_dec(&req.key_b64)?;
    let iv_bytes = b64_dec(&req.iv_b64)?;
    let aad_bytes = req.aad_b64.as_deref().map(b64_dec).transpose()?.unwrap_or_default();
    let mut in_out = b64_dec(&req.data_b64)?;

    let alg = match key_bytes.len() {
        16 => &aead::AES_128_GCM,
        32 => &aead::AES_256_GCM,
        _ => return Err(throw("AES-GCM key must be 128 or 256 bits")),
    };
    let unbound = UnboundKey::new(alg, &key_bytes).map_err(|_| throw("invalid AES key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&iv_bytes).map_err(|_| throw("AES-GCM IV must be 12 bytes"))?;
    key.seal_in_place_append_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
        .map_err(|_| throw("AES-GCM encrypt failed"))?;
    Ok(JsString::from(B64.encode(&in_out)).into())
}

pub fn host_crypto_decrypt(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let req: AeadReq = serde_json::from_str(&arg_str(args, 0, ctx)?).map_err(|e| throw(e.to_string()))?;
    let key_bytes = b64_dec(&req.key_b64)?;
    let iv_bytes = b64_dec(&req.iv_b64)?;
    let aad_bytes = req.aad_b64.as_deref().map(b64_dec).transpose()?.unwrap_or_default();
    let mut in_out = b64_dec(&req.data_b64)?;

    let alg = match key_bytes.len() {
        16 => &aead::AES_128_GCM,
        32 => &aead::AES_256_GCM,
        _ => return Err(throw("AES-GCM key must be 128 or 256 bits")),
    };
    let unbound = UnboundKey::new(alg, &key_bytes).map_err(|_| throw("invalid AES key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&iv_bytes).map_err(|_| throw("AES-GCM IV must be 12 bytes"))?;
    let plain = key
        .open_in_place(nonce, Aad::from(&aad_bytes), &mut in_out)
        .map_err(|_| throw("OperationError: AES-GCM decryption failed"))?;
    Ok(JsString::from(B64.encode(plain)).into())
}

/// `__cryptoGenerateEc(curve)` -> `{ pkcs8_b64, spki_raw_b64 }` (for ECDSA P-256/P-384).
pub fn host_crypto_generate_ec(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let curve = arg_str(args, 0, ctx)?;
    let sal = match curve.as_str() {
        "P-256" => &ECDSA_P256_SHA256_FIXED_SIGNING,
        "P-384" => &ECDSA_P384_SHA384_FIXED_SIGNING,
        _ => return Err(throw(format!("unsupported EC curve '{curve}'"))),
    };
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(sal, &rng).map_err(|_| throw("EC keygen failed"))?;
    let kp = EcdsaKeyPair::from_pkcs8(sal, pkcs8.as_ref(), &rng).map_err(|_| throw("EC keygen parse failed"))?;
    let out = serde_json::json!({
        "pkcs8_b64": B64.encode(pkcs8.as_ref()),
        "raw_pub_b64": B64.encode(kp.public_key().as_ref()),
    });
    Ok(JsString::from(out.to_string()).into())
}

#[derive(Deserialize)]
struct DeriveBitsCall {
    alg: String,
    hash: String,
    key_b64: String,
    salt_b64: String,
    iterations: u32,
    length_bits: usize,
}

/// `__cryptoDeriveBits(json)` -> base64 derived key bytes (PBKDF2).
pub fn host_crypto_derive_bits(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let call: DeriveBitsCall = serde_json::from_str(&arg_str(args, 0, ctx)?).map_err(|e| throw(e.to_string()))?;
    if !call.alg.eq_ignore_ascii_case("PBKDF2") {
        return Err(throw(format!("unsupported deriveBits algorithm '{}'", call.alg)));
    }
    let iters = std::num::NonZeroU32::new(call.iterations)
        .ok_or_else(|| throw("PBKDF2 iterations must be >= 1"))?;
    if call.length_bits == 0 || call.length_bits % 8 != 0 || call.length_bits > 65536 {
        return Err(throw("deriveBits length must be a positive multiple of 8 (max 65536 bits)"));
    }
    let alg = match call.hash.to_ascii_uppercase().as_str() {
        "SHA-256" => ring::pbkdf2::PBKDF2_HMAC_SHA256,
        "SHA-384" => ring::pbkdf2::PBKDF2_HMAC_SHA384,
        "SHA-512" => ring::pbkdf2::PBKDF2_HMAC_SHA512,
        other => return Err(throw(format!("unsupported PBKDF2 hash '{other}'"))),
    };
    let key = b64_dec(&call.key_b64)?;
    let salt = b64_dec(&call.salt_b64)?;
    let mut out = vec![0u8; call.length_bits / 8];
    ring::pbkdf2::derive(alg, iters, &salt, &key, &mut out);
    Ok(JsString::from(B64.encode(&out)).into())
}
