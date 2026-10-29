//! Grup sohbeti: **Sender Keys** (Signal/WhatsApp grup modeli), kuantum sonrası imzalarla.
//!
//! - Her üye kendi `GroupSender`'ını oluşturur ve `distribution()` çıktısını diğer her üyeye
//!   **birebir ratchet oturumu üzerinden** (`ratchet::Session::encrypt`) gönderir.
//! - Mesajlar tek kez şifrelenir, herkese aynı şifreli metin yayınlanır (O(1) gönderim).
//! - Zincir anahtarı her mesajda ileri sarılır → **ileri gizlilik**.
//! - Her mesaj göndericinin hibrit imzasıyla (Ed25519 + ML-DSA-87) imzalanır → grup üyeleri
//!   bile birbirinin adına mesaj üretemez.
//! - Üye çıkarıldığında kalan herkes `GroupSender::new` ile **yeni** anahtar üretip dağıtmalıdır
//!   (çıkarılan üyenin gelecekteki mesajları okumasını engeller).
//!
//! Sınır: MLS (RFC 9420) gibi otomatik ele geçirme sonrası iyileşme yoktur; düzenli
//! (ör. haftalık veya N mesajda bir) yeniden anahtarlama önerilir.
use crate::error::{Error, Result};
use crate::hybrid::{self, derive_subkey, HybridSigningKey, HybridVerifyingKey, SIGNATURE_LEN, SIGN_PUBLIC_LEN, SIGN_SECRET_LEN};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const CHAIN_ID_LEN: usize = 16;
const CTX_GROUP: &[u8] = b"kaotik-group-msg";
/// Tek mesajda ileri sarılabilecek en fazla adım.
pub const MAX_SKIP: u32 = 2000;
const MAX_CACHED: usize = 2000;

fn err() -> Error {
    Error::Crypto("Decryption failed".into())
}

fn step(ck: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    (derive_subkey(ck, b"group-mk", &[]), derive_subkey(ck, b"group-ck", &[]))
}

fn msg_aad(group_id: &[u8], chain_id: &[u8], iteration: u32) -> Vec<u8> {
    [&(group_id.len() as u32).to_be_bytes()[..], group_id, chain_id, &iteration.to_be_bytes()].concat()
}

/// Gönderen tarafı (kendi zinciri).
pub struct GroupSender {
    group_id: Vec<u8>,
    chain_id: [u8; CHAIN_ID_LEN],
    iteration: u32,
    ck: Zeroizing<[u8; 32]>,
    signer: HybridSigningKey,
}

impl GroupSender {
    pub fn new(group_id: &[u8]) -> Result<Self> {
        let mut chain_id = [0u8; CHAIN_ID_LEN];
        crate::crypto::random_bytes(&mut chain_id)?;
        Ok(Self {
            group_id: group_id.to_vec(),
            chain_id,
            iteration: 0,
            ck: hybrid::generate_key()?,
            signer: HybridSigningKey::generate()?,
        })
    }

    /// Diğer üyelere (birebir şifreli kanaldan!) gönderilecek dağıtım mesajı. Gizlidir.
    pub fn distribution(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::new());
        v.push(VERSION);
        v.extend_from_slice(&(self.group_id.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.group_id);
        v.extend_from_slice(&self.chain_id);
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.ck[..]);
        v.extend_from_slice(&self.signer.verifying_key().to_bytes());
        v
    }

    /// Mesajı şifreler ve imzalar: `ver || chain_id || iteration || seal || imza`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (mk, next) = step(&self.ck);
        let it = self.iteration;
        self.ck = next;
        self.iteration = self.iteration.checked_add(1).ok_or_else(err)?;
        let aad = msg_aad(&self.group_id, &self.chain_id, it);
        let body = hybrid::seal(&mk, plaintext, &aad)?;
        let mut out = Vec::with_capacity(1 + CHAIN_ID_LEN + 4 + body.len() + SIGNATURE_LEN);
        out.push(VERSION);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&it.to_be_bytes());
        out.extend_from_slice(&body);
        let sig = self.signer.sign(&[&self.group_id[..], &out].concat(), CTX_GROUP)?;
        out.extend_from_slice(&sig);
        Ok(out)
    }

    pub fn export(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>> {
        let raw = [&self.distribution()[..], &self.signer.to_bytes()].concat();
        let raw = Zeroizing::new(raw);
        hybrid::seal(storage_key, &raw, b"kaotik-group-sender")
    }

    pub fn import(storage_key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let raw = hybrid::open(storage_key, blob, b"kaotik-group-sender")?;
        if raw.len() < SIGN_SECRET_LEN {
            return Err(err());
        }
        let (dist, sk) = raw.split_at(raw.len() - SIGN_SECRET_LEN);
        let r = GroupReceiver::from_distribution(dist)?;
        Ok(Self {
            group_id: r.group_id.clone(),
            chain_id: r.chain_id,
            iteration: r.iteration,
            ck: r.ck.clone(),
            signer: HybridSigningKey::from_bytes(sk)?,
        })
    }
}

/// Bir üyenin zincirini takip eden alıcı tarafı.
#[derive(Clone)]
pub struct GroupReceiver {
    group_id: Vec<u8>,
    chain_id: [u8; CHAIN_ID_LEN],
    iteration: u32,
    ck: Zeroizing<[u8; 32]>,
    vk: HybridVerifyingKey,
    cached: Vec<(u32, Zeroizing<[u8; 32]>)>,
}

impl GroupReceiver {
    pub fn from_distribution(d: &[u8]) -> Result<Self> {
        let bad = || Error::Format("Invalid group distribution message".into());
        if d.len() < 5 || d[0] != VERSION {
            return Err(bad());
        }
        let gl = u32::from_be_bytes(d[1..5].try_into().expect("4")) as usize;
        if d.len() != 5 + gl + CHAIN_ID_LEN + 4 + 32 + SIGN_PUBLIC_LEN {
            return Err(bad());
        }
        let mut p = 5;
        let group_id = d[p..p + gl].to_vec();
        p += gl;
        let chain_id: [u8; CHAIN_ID_LEN] = d[p..p + CHAIN_ID_LEN].try_into().expect("16");
        p += CHAIN_ID_LEN;
        let iteration = u32::from_be_bytes(d[p..p + 4].try_into().expect("4"));
        p += 4;
        let mut ck = Zeroizing::new([0u8; 32]);
        ck.copy_from_slice(&d[p..p + 32]);
        p += 32;
        let vk = HybridVerifyingKey::from_bytes(&d[p..])?;
        Ok(Self { group_id, chain_id, iteration, ck, vk, cached: Vec::new() })
    }

    pub fn export(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::new());
        v.push(VERSION);
        v.extend_from_slice(&(self.group_id.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.group_id);
        v.extend_from_slice(&self.chain_id);
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.ck[..]);
        v.extend_from_slice(&self.vk.to_bytes());
        for (n, mk) in &self.cached {
            v.extend_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&mk[..]);
        }
        hybrid::seal(storage_key, &v, b"kaotik-group-receiver")
    }

    pub fn import(storage_key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let raw = hybrid::open(storage_key, blob, b"kaotik-group-receiver")?;
        if raw.len() < 5 {
            return Err(err());
        }
        let gl = u32::from_be_bytes(raw[1..5].try_into().expect("4")) as usize;
        let base = 5 + gl + CHAIN_ID_LEN + 4 + 32 + SIGN_PUBLIC_LEN;
        if raw.len() < base || (raw.len() - base) % 36 != 0 || (raw.len() - base) / 36 > MAX_CACHED {
            return Err(err());
        }
        let mut r = Self::from_distribution(&raw[..base])?;
        for c in raw[base..].chunks(36) {
            let mut mk = Zeroizing::new([0u8; 32]);
            mk.copy_from_slice(&c[4..]);
            r.cached.push((u32::from_be_bytes(c[..4].try_into().expect("4")), mk));
        }
        Ok(r)
    }

    /// Göndericinin imza anahtarı (kimliğe bağlamak için uygulama bunu kullanabilir).
    pub fn sender_key(&self) -> &HybridVerifyingKey {
        &self.vk
    }

    /// İmzayı doğrular, mesajı çözer. Hata durumunda alıcı durumu değişmez.
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let min = 1 + CHAIN_ID_LEN + 4 + hybrid::SEAL_OVERHEAD + SIGNATURE_LEN;
        if msg.len() < min || msg[0] != VERSION || msg[1..1 + CHAIN_ID_LEN] != self.chain_id {
            return Err(err());
        }
        let (signed, sig) = msg.split_at(msg.len() - SIGNATURE_LEN);
        if !self.vk.verify(&[&self.group_id[..], signed].concat(), CTX_GROUP, sig) {
            return Err(err());
        }
        let it = u32::from_be_bytes(signed[1 + CHAIN_ID_LEN..5 + CHAIN_ID_LEN].try_into().expect("4"));
        let body = &signed[5 + CHAIN_ID_LEN..];
        let aad = msg_aad(&self.group_id, &self.chain_id, it);

        let mut s = self.clone();
        let mk = if it < s.iteration {
            let i = s.cached.iter().position(|(n, _)| *n == it).ok_or_else(err)?;
            s.cached.remove(i).1
        } else {
            if it - s.iteration > MAX_SKIP {
                return Err(err());
            }
            while s.iteration < it {
                let (mk, next) = step(&s.ck);
                s.cached.push((s.iteration, mk));
                s.ck = next;
                s.iteration += 1;
            }
            let (mk, next) = step(&s.ck);
            s.ck = next;
            s.iteration += 1;
            if s.cached.len() > MAX_CACHED {
                let excess = s.cached.len() - MAX_CACHED;
                s.cached.drain(..excess);
            }
            mk
        };
        let pt = hybrid::open(&mk, body, &aad)?;
        *self = s;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_roundtrip_out_of_order_and_forgery() {
        let mut alice = GroupSender::new(b"aile").unwrap();
        let dist = alice.distribution();
        let mut bob = GroupReceiver::from_distribution(&dist).unwrap();
        let mut carol = GroupReceiver::from_distribution(&dist).unwrap();
        let m0 = alice.encrypt(b"selam").unwrap();
        let m1 = alice.encrypt(b"nasilsiniz").unwrap();
        assert_eq!(&bob.decrypt(&m1).unwrap()[..], b"nasilsiniz");
        assert_eq!(&bob.decrypt(&m0).unwrap()[..], b"selam");
        assert!(bob.decrypt(&m0).is_err()); // replay
        assert_eq!(&carol.decrypt(&m0).unwrap()[..], b"selam");

        // Carol zincir anahtarını bilse de Alice adına imza atamaz.
        let mut forged = m1.clone();
        let n = forged.len();
        forged[n - 1] ^= 1;
        assert!(carol.decrypt(&forged).is_err());
        assert_eq!(&carol.decrypt(&m1).unwrap()[..], b"nasilsiniz");

        // Kalıcı saklama
        let m3 = alice.encrypt(b"gecikmeli").unwrap();
        let m4 = alice.encrypt(b"once").unwrap();
        assert_eq!(&carol.decrypt(&m4).unwrap()[..], b"once");
        let k2 = hybrid::generate_key().unwrap();
        let mut carol2 = GroupReceiver::import(&k2, &carol.export(&k2).unwrap()).unwrap();
        assert_eq!(&carol2.decrypt(&m3).unwrap()[..], b"gecikmeli");
        let key = hybrid::generate_key().unwrap();
        let mut alice2 = GroupSender::import(&key, &alice.export(&key).unwrap()).unwrap();
        let m2 = alice2.encrypt(b"geri geldim").unwrap();
        assert_eq!(&bob.decrypt(&m2).unwrap()[..], b"geri geldim");
        assert_eq!(&carol2.decrypt(&m2).unwrap()[..], b"geri geldim");

        // Yeniden anahtarlama: eski alıcı yeni zinciri okuyamaz.
        let mut rekeyed = GroupSender::new(b"aile").unwrap();
        assert!(bob.decrypt(&rekeyed.encrypt(b"yeni").unwrap()).is_err());
    }
}
