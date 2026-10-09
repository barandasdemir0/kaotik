//! WebAssembly (tarayıcı / Node / Deno) bağlamaları.
//! Derleme: `wasm-pack build --target web -- --features wasm` (veya `cargo build --target wasm32-unknown-unknown --features wasm --lib`).
//! JS tarafında tüm anahtar/veri parametreleri `Uint8Array`'dir.
#![cfg(feature = "wasm")]

use crate::hybrid::{self, HybridKemPublicKey, HybridKemSecretKey, HybridSigningKey, HybridVerifyingKey};
use crate::ratchet::{PrekeyBundle, Session};
use wasm_bindgen::prelude::*;

fn js<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn key32(k: &[u8]) -> Result<[u8; 32], JsError> {
    k.try_into().map_err(|_| JsError::new("key must be 32 bytes"))
}

/// Gizli + açık anahtar çifti.
#[wasm_bindgen]
pub struct KeyPair {
    secret: Vec<u8>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key() -> Result<Vec<u8>, JsError> {
    Ok(hybrid::generate_key().map_err(js)?.to_vec())
}

#[wasm_bindgen]
pub fn seal(key: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    hybrid::seal(&key32(key)?, msg, aad).map_err(js)
}

#[wasm_bindgen]
pub fn open(key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(hybrid::open(&key32(key)?, sealed, aad).map_err(js)?.to_vec())
}

#[wasm_bindgen(js_name = hashPassword)]
pub fn hash_password(password: &str) -> Result<String, JsError> {
    crate::passhash::hash_password(password).map_err(js)
}

#[wasm_bindgen(js_name = verifyPassword)]
pub fn verify_password(password: &str, phc: &str) -> bool {
    crate::passhash::verify_password(password, phc)
}

#[wasm_bindgen(js_name = kemKeypair)]
pub fn kem_keypair() -> Result<KeyPair, JsError> {
    let sk = HybridKemSecretKey::generate().map_err(js)?;
    Ok(KeyPair { public: sk.public_key().to_bytes(), secret: sk.to_bytes().to_vec() })
}

#[wasm_bindgen(js_name = sealTo)]
pub fn seal_to(public_key: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    hybrid::seal_to(&HybridKemPublicKey::from_bytes(public_key).map_err(js)?, msg, aad).map_err(js)
}

#[wasm_bindgen(js_name = openFrom)]
pub fn open_from(secret_key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk = HybridKemSecretKey::from_bytes(secret_key).map_err(js)?;
    Ok(hybrid::open_from(&sk, sealed, aad).map_err(js)?.to_vec())
}

#[wasm_bindgen(js_name = signKeypair)]
pub fn sign_keypair() -> Result<KeyPair, JsError> {
    let sk = HybridSigningKey::generate().map_err(js)?;
    Ok(KeyPair { public: sk.verifying_key().to_bytes(), secret: sk.to_bytes().to_vec() })
}

#[wasm_bindgen]
pub fn sign(secret_key: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, JsError> {
    HybridSigningKey::from_bytes(secret_key).map_err(js)?.sign(msg, ctx).map_err(js)
}

#[wasm_bindgen]
pub fn verify(public_key: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    HybridVerifyingKey::from_bytes(public_key).map(|vk| vk.verify(msg, ctx, sig)).unwrap_or(false)
}

/// İmzalı ön anahtar paketi üretir: `public` sunucuya, `secret` cihazda saklanır.
#[wasm_bindgen(js_name = prekeyBundle)]
pub fn prekey_bundle(identity_secret: &[u8]) -> Result<KeyPair, JsError> {
    let id = HybridSigningKey::from_bytes(identity_secret).map_err(js)?;
    let (bundle, sk) = PrekeyBundle::new(&id).map_err(js)?;
    Ok(KeyPair { public: bundle.to_bytes(), secret: sk.to_bytes().to_vec() })
}

/// Double Ratchet sohbet oturumu.
#[wasm_bindgen]
pub struct RatchetSession {
    inner: Session,
    handshake: Vec<u8>,
}

#[wasm_bindgen]
impl RatchetSession {
    /// Başlatan taraf. `handshake` alanı karşı tarafa gönderilmelidir.
    pub fn initiate(identity_secret: &[u8], bundle: &[u8]) -> Result<RatchetSession, JsError> {
        let id = HybridSigningKey::from_bytes(identity_secret).map_err(js)?;
        let b = PrekeyBundle::from_bytes(bundle).map_err(js)?;
        let (inner, handshake) = Session::initiate(&id, &b).map_err(js)?;
        Ok(Self { inner, handshake })
    }

    /// Yanıtlayan taraf. `handshake` alanı başlatanın kimlik (doğrulama) anahtarını döndürür.
    pub fn respond(identity_secret: &[u8], prekey_secret: &[u8], init: &[u8]) -> Result<RatchetSession, JsError> {
        let id = HybridSigningKey::from_bytes(identity_secret).map_err(js)?;
        let pk = HybridKemSecretKey::from_bytes(prekey_secret).map_err(js)?;
        let (inner, peer) = Session::respond(&id, &pk, init).map_err(js)?;
        Ok(Self { inner, handshake: peer.to_bytes() })
    }

    #[wasm_bindgen(getter)]
    pub fn handshake(&self) -> Vec<u8> {
        self.handshake.clone()
    }

    pub fn encrypt(&mut self, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.encrypt(msg, aad).map_err(js)
    }

    pub fn decrypt(&mut self, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.inner.decrypt(msg, aad).map_err(js)?.to_vec())
    }

    #[wasm_bindgen(js_name = export)]
    pub fn export_state(&self, storage_key: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.export(&key32(storage_key)?).map_err(js)
    }

    #[wasm_bindgen(js_name = import)]
    pub fn import_state(storage_key: &[u8], blob: &[u8]) -> Result<RatchetSession, JsError> {
        let inner = Session::import(&key32(storage_key)?, blob).map_err(js)?;
        Ok(Self { inner, handshake: Vec::new() })
    }
}

/// Grup gönderici (Sender Keys).
#[wasm_bindgen]
pub struct GroupSender(crate::group::GroupSender);

#[wasm_bindgen]
impl GroupSender {
    #[wasm_bindgen(constructor)]
    pub fn new(group_id: &[u8]) -> Result<GroupSender, JsError> {
        Ok(Self(crate::group::GroupSender::new(group_id).map_err(js)?))
    }
    /// Gizli: her üyeye birebir `RatchetSession` ile şifreleyip gönderin.
    pub fn distribution(&self) -> Vec<u8> {
        self.0.distribution().to_vec()
    }
    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.encrypt(msg).map_err(js)
    }
    #[wasm_bindgen(js_name = export)]
    pub fn export_state(&self, storage_key: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.export(&key32(storage_key)?).map_err(js)
    }
    #[wasm_bindgen(js_name = import)]
    pub fn import_state(storage_key: &[u8], blob: &[u8]) -> Result<GroupSender, JsError> {
        Ok(Self(crate::group::GroupSender::import(&key32(storage_key)?, blob).map_err(js)?))
    }
}

/// Bir grup üyesinin mesajlarını çözen alıcı.
#[wasm_bindgen]
pub struct GroupReceiver(crate::group::GroupReceiver);

#[wasm_bindgen]
impl GroupReceiver {
    #[wasm_bindgen(constructor)]
    pub fn new(distribution: &[u8]) -> Result<GroupReceiver, JsError> {
        Ok(Self(crate::group::GroupReceiver::from_distribution(distribution).map_err(js)?))
    }
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.0.decrypt(msg).map_err(js)?.to_vec())
    }
    #[wasm_bindgen(js_name = export)]
    pub fn export_state(&self, storage_key: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0.export(&key32(storage_key)?).map_err(js)
    }
    #[wasm_bindgen(js_name = import)]
    pub fn import_state(storage_key: &[u8], blob: &[u8]) -> Result<GroupReceiver, JsError> {
        Ok(Self(crate::group::GroupReceiver::import(&key32(storage_key)?, blob).map_err(js)?))
    }
}
