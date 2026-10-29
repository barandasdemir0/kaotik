//! Sohbet uygulamaları için kuantum sonrası **Double Ratchet** (KEM tabanlı).
//!
//! Signal'in Double Ratchet yapısında Diffie-Hellman adımı yerine hibrit KEM
//! (X25519 + ML-KEM-1024) kullanılır:
//!
//! - **İleri gizlilik:** Her mesaj kendi anahtarıyla şifrelenir; anahtar kullanıldıktan sonra silinir.
//!   Bugün cihaz ele geçirilse bile geçmiş mesajlar çözülemez.
//! - **Ele geçirme sonrası iyileşme:** Her konuşma turunda yeni KEM anahtar çifti üretilir ve kök
//!   anahtar taze bir ortak sırla karıştırılır; saldırgan bir sonraki turdan itibaren kör kalır.
//! - **Kimlik doğrulama:** Başlangıçta iki taraf da hibrit imzayla (Ed25519 + ML-DSA-87)
//!   kimliğini kanıtlar; tüm mesajlar iki kimliğe bağlı `ad` ile doğrulanır.
//! - **Sırasız teslim:** Atlanan mesaj anahtarları sınırlı sayıda saklanır.
//! - **Başlık şifreleme:** Tur/mesaj numaraları ve KEM anahtarları başlık anahtarlarıyla şifrelenir
//!   (Double Ratchet spesifikasyonu §4); ağ gözlemcisi mesajları turlara bağlayamaz.
//!
//! Akış:
//! 1. Alıcı (Bob) `PrekeyBundle::new` ile imzalı ön anahtarını sunucuya koyar, gizli kısmı saklar.
//! 2. Gönderen (Alice) `Session::initiate(kimliği, paket)` → `(oturum, init_mesajı)`.
//! 3. Bob `Session::respond(kimliği, ön_anahtar_gizli, init_mesajı)` → `(oturum, alice_kimliği)`.
//! 4. Her iki taraf `encrypt` / `decrypt`. Oturum durumu `export(storage_key)` ile şifreli saklanır.

use crate::error::{Error, Result};
use crate::hybrid::{
    self, derive_subkey, HybridKemPublicKey, HybridKemSecretKey, HybridSigningKey, HybridVerifyingKey,
    KEM_CIPHERTEXT_LEN, KEM_PUBLIC_LEN, KEM_SECRET_LEN, SIGNATURE_LEN, SIGN_PUBLIC_LEN,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 2;
/// Düz başlık: KEM açık anahtarı + KEM şifreli metni + pn + n.
const HEADER_LEN: usize = KEM_PUBLIC_LEN + KEM_CIPHERTEXT_LEN + 4 + 4;
const ENC_HEADER_LEN: usize = HEADER_LEN + hybrid::SEAL_OVERHEAD;
/// Tek seferde atlanabilecek en fazla mesaj (DoS sınırı).
pub const MAX_SKIP: u32 = 1000;
/// Saklanan atlanmış anahtar üst sınırı; aşılınca en eskiler silinir.
const MAX_SKIPPED_STORED: usize = 2000;
const CTX_PREKEY: &[u8] = b"kaotik-ratchet-prekey";
const CTX_INIT: &[u8] = b"kaotik-ratchet-init";

fn err() -> Error {
    Error::Crypto("Decryption failed".into())
}

/// Bob'un yayınladığı imzalı ön anahtar paketi (açık).
#[derive(Clone)]
pub struct PrekeyBundle {
    pub identity: HybridVerifyingKey,
    pub prekey: HybridKemPublicKey,
    pub signature: Vec<u8>,
}

impl PrekeyBundle {
    /// Yeni ön anahtar üretir ve kimlik anahtarıyla imzalar. Dönen gizli anahtarı Bob saklar.
    pub fn new(identity: &HybridSigningKey) -> Result<(Self, HybridKemSecretKey)> {
        let sk = HybridKemSecretKey::generate()?;
        let prekey = sk.public_key();
        let signature = identity.sign(&prekey.to_bytes(), CTX_PREKEY)?;
        Ok((Self { identity: identity.verifying_key(), prekey, signature }, sk))
    }

    pub fn verify(&self) -> bool {
        self.identity.verify(&self.prekey.to_bytes(), CTX_PREKEY, &self.signature)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.identity.to_bytes(), self.prekey.to_bytes(), self.signature.clone()].concat()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SIGN_PUBLIC_LEN + KEM_PUBLIC_LEN + SIGNATURE_LEN {
            return Err(Error::Format("Invalid prekey bundle".into()));
        }
        let (id, rest) = b.split_at(SIGN_PUBLIC_LEN);
        let (pk, sig) = rest.split_at(KEM_PUBLIC_LEN);
        Ok(Self {
            identity: HybridVerifyingKey::from_bytes(id)?,
            prekey: HybridKemPublicKey::from_bytes(pk)?,
            signature: sig.to_vec(),
        })
    }
}

/// Bir ratchet oturumunun tüm durumu. Gizli alanlar `Drop`'ta silinir.
#[derive(Clone)]
pub struct Session {
    ad: [u8; 32],
    root: Zeroizing<[u8; 32]>,
    my_sk: HybridKemSecretKey,
    peer_pk: Option<Vec<u8>>,
    send_ck: Option<Zeroizing<[u8; 32]>>,
    send_ct: Vec<u8>,
    send_n: u32,
    prev_n: u32,
    recv_ck: Option<Zeroizing<[u8; 32]>>,
    recv_n: u32,
    /// Başlık anahtarları (gönderme/alma, mevcut ve bir sonraki tur).
    hks: Option<Zeroizing<[u8; 32]>>,
    nhks: Zeroizing<[u8; 32]>,
    hkr: Option<Zeroizing<[u8; 32]>>,
    nhkr: Zeroizing<[u8; 32]>,
    /// Atlanmış mesaj anahtarları: (başlık anahtarı, mesaj no, mesaj anahtarı).
    skipped: Vec<(Zeroizing<[u8; 32]>, u32, Zeroizing<[u8; 32]>)>,
}

fn ad_for(initiator: &HybridVerifyingKey, responder: &HybridVerifyingKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(hybrid::SUITE);
    h.update(b"ratchet-ad");
    h.update(initiator.to_bytes());
    h.update(responder.to_bytes());
    h.finalize().into()
}

type Key = Zeroizing<[u8; 32]>;

/// Kök zinciri: (yeni kök, zincir anahtarı, sonraki başlık anahtarı) = HKDF-SHA512(salt = kök, ikm = KEM sırrı).
fn kdf_rk(root: &[u8; 32], ss: &[u8]) -> (Key, Key, Key) {
    let hk = Hkdf::<Sha512>::new(Some(root), ss);
    let mut okm = Zeroizing::new([0u8; 96]);
    hk.expand(b"kaotik-ratchet-root-v2", &mut okm[..]).expect("96 <= 255*64");
    (key32(&okm[..32]), key32(&okm[32..64]), key32(&okm[64..]))
}

/// Mesaj zinciri: (mesaj anahtarı, sonraki zincir anahtarı).
fn kdf_ck(ck: &[u8; 32]) -> (Key, Key) {
    (derive_subkey(ck, b"ratchet-mk", &[]), derive_subkey(ck, b"ratchet-ck", &[]))
}

/// Çözülmüş başlık: gönderenin güncel KEM açık anahtarı, KEM şifreli metni, önceki zincir uzunluğu, mesaj no.
struct Header {
    pk: Vec<u8>,
    ct: Vec<u8>,
    pn: u32,
    n: u32,
}

fn decode_header(h: &[u8]) -> Option<Header> {
    if h.len() != HEADER_LEN {
        return None;
    }
    let pk = h[..KEM_PUBLIC_LEN].to_vec();
    let ct = h[KEM_PUBLIC_LEN..KEM_PUBLIC_LEN + KEM_CIPHERTEXT_LEN].to_vec();
    let tail = &h[HEADER_LEN - 8..];
    Some(Header {
        pk,
        ct,
        pn: u32::from_be_bytes(tail[..4].try_into().ok()?),
        n: u32::from_be_bytes(tail[4..].try_into().ok()?),
    })
}

/// Kablo biçimi: `ver(1) || u32 enc_header_len || seal(HK, header) || seal(MK, body)`.
fn split_message(msg: &[u8]) -> Result<(&[u8], &[u8])> {
    if msg.len() < 5 || msg[0] != VERSION {
        return Err(err());
    }
    let len = u32::from_be_bytes(msg[1..5].try_into().expect("4")) as usize;
    if len != ENC_HEADER_LEN || msg.len() < 5 + len + hybrid::SEAL_OVERHEAD {
        return Err(err());
    }
    Ok(msg[5..].split_at(len))
}

impl Session {
    fn root0(ad: &[u8; 32]) -> Key {
        derive_subkey(ad, b"ratchet-root0", &[])
    }

    /// Alice: Bob'un paketini doğrular, oturumu başlatır. `init` mesajı Bob'a iletilmelidir.
    pub fn initiate(me: &HybridSigningKey, bundle: &PrekeyBundle) -> Result<(Self, Vec<u8>)> {
        if !bundle.verify() {
            return Err(Error::Crypto("Prekey signature invalid".into()));
        }
        let my_vk = me.verifying_key();
        let ad = ad_for(&my_vk, &bundle.identity);
        let my_sk = HybridKemSecretKey::generate()?;
        let my_pk = my_sk.public_key().to_bytes();
        let (ct, ss) = bundle.prekey.encapsulate()?;
        let (root, ck, nhk) = kdf_rk(&Self::root0(&ad), &ss[..]);
        let transcript = [&bundle.prekey.to_bytes()[..], &my_pk, &ct].concat();
        let sig = me.sign(&transcript, CTX_INIT)?;
        let init = [&[VERSION][..], &my_vk.to_bytes(), &my_pk, &ct, &sig].concat();
        let s = Self {
            ad,
            root,
            my_sk,
            peer_pk: Some(bundle.prekey.to_bytes()),
            send_ck: Some(ck),
            send_ct: ct,
            send_n: 0,
            prev_n: 0,
            recv_ck: None,
            recv_n: 0,
            hks: Some(derive_subkey(&ss[..], b"ratchet-hka", &[])),
            nhks: nhk,
            hkr: None,
            nhkr: derive_subkey(&ss[..], b"ratchet-nhkb", &[]),
            skipped: Vec::new(),
        };
        Ok((s, init))
    }

    /// Bob: Alice'in `init` mesajını doğrular. Dönen kimliği uygulama kendi rehberiyle
    /// karşılaştırmalıdır (güvenlik numarası / QR doğrulaması).
    pub fn respond(me: &HybridSigningKey, prekey: &HybridKemSecretKey, init: &[u8]) -> Result<(Self, HybridVerifyingKey)> {
        let need = 1 + SIGN_PUBLIC_LEN + KEM_PUBLIC_LEN + KEM_CIPHERTEXT_LEN + SIGNATURE_LEN;
        if init.len() != need || init[0] != VERSION {
            return Err(err());
        }
        let (vk_b, rest) = init[1..].split_at(SIGN_PUBLIC_LEN);
        let (peer_pk, rest) = rest.split_at(KEM_PUBLIC_LEN);
        let (ct, sig) = rest.split_at(KEM_CIPHERTEXT_LEN);
        let peer_vk = HybridVerifyingKey::from_bytes(vk_b)?;
        HybridKemPublicKey::from_bytes(peer_pk)?;
        let transcript = [&prekey.public_key().to_bytes()[..], peer_pk, ct].concat();
        if !peer_vk.verify(&transcript, CTX_INIT, sig) {
            return Err(Error::Crypto("Initiator signature invalid".into()));
        }
        let ad = ad_for(&peer_vk, &me.verifying_key());
        let ss = prekey.decapsulate(ct)?;
        let (root, ck, nhk) = kdf_rk(&Self::root0(&ad), &ss[..]);
        let s = Self {
            ad,
            root,
            my_sk: prekey.clone(),
            peer_pk: Some(peer_pk.to_vec()),
            send_ck: None,
            send_ct: Vec::new(),
            send_n: 0,
            prev_n: 0,
            recv_ck: Some(ck),
            recv_n: 0,
            hks: None,
            nhks: derive_subkey(&ss[..], b"ratchet-nhkb", &[]),
            hkr: Some(derive_subkey(&ss[..], b"ratchet-hka", &[])),
            nhkr: nhk,
            skipped: Vec::new(),
        };
        Ok((s, peer_vk))
    }

    fn ratchet_send(&mut self) -> Result<()> {
        let peer = HybridKemPublicKey::from_bytes(self.peer_pk.as_deref().ok_or_else(err)?)?;
        self.my_sk = HybridKemSecretKey::generate()?;
        let (ct, ss) = peer.encapsulate()?;
        let (root, ck, nhk) = kdf_rk(&self.root, &ss[..]);
        self.root = root;
        self.send_ck = Some(ck);
        self.send_ct = ct;
        self.prev_n = self.send_n;
        self.send_n = 0;
        self.hks = Some(std::mem::replace(&mut self.nhks, nhk));
        Ok(())
    }

    /// Mesajı şifreler. `aad` isteğe bağlı ek bağlam (ör. sohbet id). Başlık da şifrelenir:
    /// ağdaki gözlemci tur/mesaj numarasını veya KEM anahtarlarını göremez.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.send_ck.is_none() {
            self.ratchet_send()?;
        }
        let (mk, next) = kdf_ck(self.send_ck.as_ref().expect("set above"));
        self.send_ck = Some(next);
        let mut hdr = Zeroizing::new(Vec::with_capacity(HEADER_LEN));
        hdr.extend_from_slice(&self.my_sk.public_key().to_bytes());
        hdr.extend_from_slice(&self.send_ct);
        hdr.extend_from_slice(&self.prev_n.to_be_bytes());
        hdr.extend_from_slice(&self.send_n.to_be_bytes());
        self.send_n = self.send_n.checked_add(1).ok_or_else(err)?;
        let hks = self.hks.as_ref().ok_or_else(err)?;
        let enc_hdr = hybrid::seal(hks, &hdr, &[&self.ad[..], b"hdr"].concat())?;
        let body = hybrid::seal(&mk, plaintext, &[&self.ad[..], &enc_hdr, aad].concat())?;
        let mut out = Vec::with_capacity(5 + enc_hdr.len() + body.len());
        out.push(VERSION);
        out.extend_from_slice(&(enc_hdr.len() as u32).to_be_bytes());
        out.extend_from_slice(&enc_hdr);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Mesajı çözer. Başarısız olursa oturum durumu **değişmez**.
    pub fn decrypt(&mut self, msg: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut s = self.clone();
        let pt = s.decrypt_inner(msg, aad)?;
        *self = s;
        Ok(pt)
    }

    fn open_header(&self, hk: &[u8; 32], enc_hdr: &[u8]) -> Option<Header> {
        let raw = hybrid::open(hk, enc_hdr, &[&self.ad[..], b"hdr"].concat()).ok()?;
        decode_header(&raw)
    }

    fn decrypt_inner(&mut self, msg: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (enc_hdr, body) = split_message(msg)?;
        let full_aad = [&self.ad[..], enc_hdr, aad].concat();
        // 1) Atlanmış mesaj mı?
        for i in 0..self.skipped.len() {
            if let Some(h) = self.open_header(&self.skipped[i].0, enc_hdr) {
                if let Some(j) = self.skipped.iter().position(|(k, n, _)| k[..] == self.skipped[i].0[..] && *n == h.n) {
                    let (_, _, mk) = self.skipped.remove(j);
                    return hybrid::open(&mk, body, &full_aad);
                }
            }
        }
        // 2) Mevcut alma zinciri mi, yoksa yeni tur mu?
        let h = match self.hkr.as_ref().and_then(|k| self.open_header(k, enc_hdr)) {
            Some(h) => h,
            None => {
                let h = self.open_header(&self.nhkr, enc_hdr).ok_or_else(err)?;
                HybridKemPublicKey::from_bytes(&h.pk)?;
                self.skip_until(h.pn)?;
                let ss = self.my_sk.decapsulate(&h.ct)?;
                let (root, ck, nhk) = kdf_rk(&self.root, &ss[..]);
                self.root = root;
                self.recv_ck = Some(ck);
                self.recv_n = 0;
                self.peer_pk = Some(h.pk.clone());
                self.send_ck = None;
                self.hkr = Some(std::mem::replace(&mut self.nhkr, nhk));
                h
            }
        };
        self.skip_until(h.n)?;
        let (mk, next) = kdf_ck(self.recv_ck.as_ref().ok_or_else(err)?);
        self.recv_ck = Some(next);
        self.recv_n += 1;
        hybrid::open(&mk, body, &full_aad)
    }

    fn skip_until(&mut self, until: u32) -> Result<()> {
        let (Some(mut ck), Some(hk)) = (self.recv_ck.take(), self.hkr.clone()) else { return Ok(()) };
        if until < self.recv_n {
            self.recv_ck = Some(ck);
            return Ok(());
        }
        if until - self.recv_n > MAX_SKIP {
            return Err(err());
        }
        while self.recv_n < until {
            let (mk, next) = kdf_ck(&ck);
            self.skipped.push((hk.clone(), self.recv_n, mk));
            ck = next;
            self.recv_n += 1;
        }
        if self.skipped.len() > MAX_SKIPPED_STORED {
            let excess = self.skipped.len() - MAX_SKIPPED_STORED;
            self.skipped.drain(..excess);
        }
        self.recv_ck = Some(ck);
        Ok(())
    }

    // --- Kalıcı saklama ----------------------------------------------------------

    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::new());
        v.push(VERSION);
        v.extend_from_slice(&self.ad);
        v.extend_from_slice(&self.root[..]);
        v.extend_from_slice(&self.my_sk.to_bytes());
        put_opt(&mut v, self.peer_pk.as_deref());
        put_opt(&mut v, self.send_ck.as_ref().map(|k| &k[..]));
        put_opt(&mut v, Some(&self.send_ct));
        v.extend_from_slice(&self.send_n.to_be_bytes());
        v.extend_from_slice(&self.prev_n.to_be_bytes());
        put_opt(&mut v, self.recv_ck.as_ref().map(|k| &k[..]));
        v.extend_from_slice(&self.recv_n.to_be_bytes());
        put_opt(&mut v, self.hks.as_ref().map(|k| &k[..]));
        v.extend_from_slice(&self.nhks[..]);
        put_opt(&mut v, self.hkr.as_ref().map(|k| &k[..]));
        v.extend_from_slice(&self.nhkr[..]);
        v.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for (hk, n, mk) in &self.skipped {
            v.extend_from_slice(&hk[..]);
            v.extend_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&mk[..]);
        }
        v
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        if r.take(1)? != [VERSION] {
            return Err(err());
        }
        let ad: [u8; 32] = r.take(32)?.try_into().expect("32");
        let root = key32(r.take(32)?);
        let my_sk = HybridKemSecretKey::from_bytes(r.take(KEM_SECRET_LEN)?)?;
        let peer_pk = r.opt()?.map(<[u8]>::to_vec);
        let send_ck = r.opt()?.map(key32_checked).transpose()?;
        let send_ct = r.opt()?.unwrap_or_default().to_vec();
        let send_n = r.u32()?;
        let prev_n = r.u32()?;
        let recv_ck = r.opt()?.map(key32_checked).transpose()?;
        let recv_n = r.u32()?;
        let hks = r.opt()?.map(key32_checked).transpose()?;
        let nhks = key32(r.take(32)?);
        let hkr = r.opt()?.map(key32_checked).transpose()?;
        let nhkr = key32(r.take(32)?);
        let count = r.u32()? as usize;
        if count > MAX_SKIPPED_STORED {
            return Err(err());
        }
        let mut skipped = Vec::with_capacity(count);
        for _ in 0..count {
            let hk = key32(r.take(32)?);
            let n = r.u32()?;
            skipped.push((hk, n, key32(r.take(32)?)));
        }
        if !r.0.is_empty() {
            return Err(err());
        }
        Ok(Self {
            ad, root, my_sk, peer_pk, send_ck, send_ct, send_n, prev_n, recv_ck, recv_n,
            hks, nhks, hkr, nhkr, skipped,
        })
    }

    /// Oturum durumunu 32 baytlık depolama anahtarıyla şifreleyerek dışa aktarır.
    pub fn export(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>> {
        hybrid::seal(storage_key, &self.to_bytes(), b"kaotik-ratchet-state")
    }

    pub fn import(storage_key: &[u8; 32], blob: &[u8]) -> Result<Self> {
        let raw = hybrid::open(storage_key, blob, b"kaotik-ratchet-state")?;
        Self::from_bytes(&raw)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.ad.zeroize();
    }
}

fn key32(b: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(b);
    k
}

fn key32_checked(b: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if b.len() != 32 {
        return Err(err());
    }
    Ok(key32(b))
}

fn put_opt(v: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        None => v.extend_from_slice(&u32::MAX.to_be_bytes()),
        Some(d) => {
            v.extend_from_slice(&(d.len() as u32).to_be_bytes());
            v.extend_from_slice(d);
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(err());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn opt(&mut self) -> Result<Option<&'a [u8]>> {
        match self.u32()? {
            u32::MAX => Ok(None),
            n => self.take(n as usize).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let alice_id = HybridSigningKey::generate().unwrap();
        let bob_id = HybridSigningKey::generate().unwrap();
        let (bundle, prekey_sk) = PrekeyBundle::new(&bob_id).unwrap();
        let bundle = PrekeyBundle::from_bytes(&bundle.to_bytes()).unwrap();
        let (a, init) = Session::initiate(&alice_id, &bundle).unwrap();
        let (b, who) = Session::respond(&bob_id, &prekey_sk, &init).unwrap();
        assert!(who == alice_id.verifying_key());
        (a, b)
    }

    #[test]
    fn conversation_with_turns() {
        let (mut a, mut b) = pair();
        for round in 0..3 {
            let m1 = a.encrypt(format!("a{round}").as_bytes(), b"chat").unwrap();
            let m2 = a.encrypt(b"a-second", b"chat").unwrap();
            assert_eq!(&b.decrypt(&m1, b"chat").unwrap()[..], format!("a{round}").as_bytes());
            assert_eq!(&b.decrypt(&m2, b"chat").unwrap()[..], b"a-second");
            let r = b.encrypt(b"b-reply", b"chat").unwrap();
            assert_eq!(&a.decrypt(&r, b"chat").unwrap()[..], b"b-reply");
        }
    }

    #[test]
    fn out_of_order_and_replay() {
        let (mut a, mut b) = pair();
        let m: Vec<_> = (0..4).map(|i| a.encrypt(&[i], b"").unwrap()).collect();
        assert_eq!(&b.decrypt(&m[3], b"").unwrap()[..], &[3]);
        assert_eq!(&b.decrypt(&m[1], b"").unwrap()[..], &[1]);
        // Replay reddedilir (anahtar silindi)
        assert!(b.decrypt(&m[1], b"").is_err());
        let r = b.encrypt(b"x", b"").unwrap();
        a.decrypt(&r, b"").unwrap();
        let n = a.encrypt(b"new-turn", b"").unwrap();
        assert_eq!(&b.decrypt(&n, b"").unwrap()[..], b"new-turn");
        // Önceki turdan gecikmiş mesajlar hâlâ açılır
        assert_eq!(&b.decrypt(&m[0], b"").unwrap()[..], &[0]);
        assert_eq!(&b.decrypt(&m[2], b"").unwrap()[..], &[2]);
    }

    #[test]
    fn tamper_does_not_corrupt_state_and_export_import() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hi", b"").unwrap();
        let mut bad = m.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(b.decrypt(&bad, b"").is_err());
        assert!(b.decrypt(&m, b"other-aad").is_err());
        let key = hybrid::generate_key().unwrap();
        let blob = b.export(&key).unwrap();
        let mut b2 = Session::import(&key, &blob).unwrap();
        assert_eq!(&b2.decrypt(&m, b"").unwrap()[..], b"hi");
        let r = b2.encrypt(b"back", b"").unwrap();
        assert_eq!(&a.decrypt(&r, b"").unwrap()[..], b"back");
        assert!(Session::import(&hybrid::generate_key().unwrap(), &blob).is_err());
    }

    #[test]
    fn headers_are_encrypted() {
        let (mut a, mut b) = pair();
        let m1 = a.encrypt(b"x", b"").unwrap();
        let m2 = a.encrypt(b"x", b"").unwrap();
        let my_pk = a.my_sk.public_key().to_bytes();
        // Açık anahtar veya sayaç düz metin olarak görünmemeli.
        assert!(!m1.windows(64).any(|w| w == &my_pk[..64]));
        assert_ne!(m1[5..40], m2[5..40]);
        b.decrypt(&m2, b"").unwrap();
        b.decrypt(&m1, b"").unwrap();
        // Rastgele (başka oturumun) mesajı açılamaz.
        let (mut c, _) = pair();
        assert!(b.decrypt(&c.encrypt(b"y", b"").unwrap(), b"").is_err());
    }

    #[test]
    fn long_out_of_order_across_turns() {
        let (mut a, mut b) = pair();
        let mut pending = Vec::new();
        for turn in 0..4u8 {
            for i in 0..3u8 {
                pending.push((a.encrypt(&[turn, i], b"").unwrap(), [turn, i]));
            }
            // Her turda yalnız son mesaj ulaşır, b cevap verir.
            let (m, p) = pending.pop().unwrap();
            assert_eq!(&b.decrypt(&m, b"").unwrap()[..], &p);
            let r = b.encrypt(b"ack", b"").unwrap();
            a.decrypt(&r, b"").unwrap();
        }
        for (m, p) in pending.iter().rev() {
            assert_eq!(&b.decrypt(m, b"").unwrap()[..], p);
        }
    }

    #[test]
    fn forged_bundle_and_init_rejected() {
        let bob_id = HybridSigningKey::generate().unwrap();
        let mallory = HybridSigningKey::generate().unwrap();
        let (mut bundle, prekey_sk) = PrekeyBundle::new(&bob_id).unwrap();
        bundle.identity = mallory.verifying_key();
        assert!(Session::initiate(&mallory, &bundle).is_err());
        let (bundle, _) = PrekeyBundle::new(&bob_id).unwrap();
        let (_, mut init) = Session::initiate(&mallory, &bundle).unwrap();
        // Farklı ön anahtar → imza transkripti uyuşmaz
        assert!(Session::respond(&bob_id, &prekey_sk, &init).is_err());
        let n = init.len();
        init[n - 1] ^= 1;
        assert!(Session::respond(&bob_id, &prekey_sk, &init).is_err());
    }
}
