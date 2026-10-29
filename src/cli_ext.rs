use kaotik::{crypto, decrypt_kaotik, encrypt_kaotik};
use zeroize::Zeroizing;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const CHAFF_MAGIC: &[u8; 5] = b"CHFF1";
const DEADMAN_MAGIC: &[u8; 4] = b"DMS1";
const PLAUSIBLE_MAGIC: &[u8; 4] = b"PDN1";
const ENTROPY_MAGIC: &[u8; 4] = b"ENP1";
const QCAN_MAGIC: &[u8; 4] = b"QCN1";
const STEGO_LEN_BYTES: usize = 8;
const MUTATION_STATE_FILE: &str = ".kaotik_mutation_state";

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn derive_seed(password: &str, salt: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(salt);
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

pub fn derive_context_password(
    password: &str,
    gps: Option<&str>,
    time_slot: Option<&str>,
    mutation_seed: Option<&[u8; 32]>,
) -> String {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    if let Some(g) = gps {
        h.update(b"|gps|");
        h.update(g.as_bytes());
    }
    if let Some(t) = time_slot {
        h.update(b"|time|");
        h.update(t.as_bytes());
    }
    if let Some(m) = mutation_seed {
        h.update(b"|mut|");
        h.update(m);
    }
    let d = h.finalize();
    let hex = format!("{:x}", d);
    format!("{}|CTX:{}A1!", password, &hex[..16])
}

pub fn read_mutation_seed(base_dir: &Path) -> Option<[u8; 32]> {
    let path = base_dir.join(MUTATION_STATE_FILE);
    let data = fs::read(path).ok()?;
    if data.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Some(out)
}

pub fn update_mutation_seed(base_dir: &Path, output_path: &str) -> Result<(), String> {
    let bytes = fs::read(output_path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let digest = h.finalize();
    fs::write(base_dir.join(MUTATION_STATE_FILE), digest).map_err(|e| e.to_string())
}

pub fn generate_honey_decoy(ciphertext: &[u8], password: &str, mode: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(mode.as_bytes());
    h.update(ciphertext);
    let seed = h.finalize();
    let mut body = String::new();
    body.push_str("=== SYSTEM MEMO (DECOY) ===\n");
    body.push_str("classification: internal\n");
    body.push_str("status: operational\n");
    body.push_str("notes:\n");
    for i in 0..8 {
        body.push_str(&format!("- node-{} token: {:02x}{:02x}{:02x}{:02x}\n", i + 1, seed[i], seed[8 + i], seed[16 + i], seed[24 + i]));
    }
    body.into_bytes()
}

fn make_tag(password: &str, idx: u32, data: &[u8], salt: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(salt);
    h.update(idx.to_le_bytes());
    h.update(data);
    let d = h.finalize();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&d[..16]);
    tag
}

#[allow(dead_code)]
fn chaff_pack_legacy(payload: &[u8], password: &str, fake_packets: u32) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    crypto::random_bytes(&mut salt).map_err(|e| e.to_string())?;

    let mut packets: Vec<(u32, Vec<u8>, [u8; 16])> = Vec::new();
    let chunk = 512usize;
    let real_count = payload.len().div_ceil(chunk) as u32;

    for (i, c) in payload.chunks(chunk).enumerate() {
        let idx = i as u32;
        let data = c.to_vec();
        let tag = make_tag(password, idx, &data, &salt);
        packets.push((idx, data, tag));
    }

    let mut seed = derive_seed(password, &salt);
    for i in 0..fake_packets {
        let idx = real_count + i;
        let fake_len = 32 + (splitmix64(&mut seed) as usize % chunk);
        let mut data = vec![0u8; fake_len];
        crypto::random_bytes(&mut data).map_err(|e| e.to_string())?;
        let mut tag = [0u8; 16];
        crypto::random_bytes(&mut tag).map_err(|e| e.to_string())?;
        packets.push((idx, data, tag));
    }

    for i in (1..packets.len()).rev() {
        let j = (splitmix64(&mut seed) as usize) % (i + 1);
        packets.swap(i, j);
    }

    let mut out = Vec::new();
    out.extend_from_slice(CHAFF_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&real_count.to_le_bytes());
    out.extend_from_slice(&(packets.len() as u32).to_le_bytes());
    for (idx, data, tag) in packets {
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&tag);
        out.extend_from_slice(&data);
    }
    Ok(out)
}

fn chaff_unpack_legacy(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 5 + 16 + 4 + 4 {
        return Err("Invalid chaff blob".into());
    }
    if &blob[..5] != CHAFF_MAGIC {
        return Err("Invalid chaff magic".into());
    }
    let mut off = 5usize;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blob[off..off + 16]);
    off += 16;
    let mut rc = [0u8; 4];
    rc.copy_from_slice(&blob[off..off + 4]);
    off += 4;
    let real_count = u32::from_le_bytes(rc);
    let mut tc = [0u8; 4];
    tc.copy_from_slice(&blob[off..off + 4]);
    off += 4;
    let total = u32::from_le_bytes(tc);

    let mut real: Vec<Option<Vec<u8>>> = vec![None; real_count as usize];
    for _ in 0..total {
        if off + 4 + 4 + 16 > blob.len() {
            return Err("Malformed chaff packet header".into());
        }
        let mut idxb = [0u8; 4];
        idxb.copy_from_slice(&blob[off..off + 4]);
        off += 4;
        let idx = u32::from_le_bytes(idxb);

        let mut lb = [0u8; 4];
        lb.copy_from_slice(&blob[off..off + 4]);
        off += 4;
        let len = u32::from_le_bytes(lb) as usize;

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&blob[off..off + 16]);
        off += 16;

        if off + len > blob.len() {
            return Err("Malformed chaff packet body".into());
        }
        let data = &blob[off..off + len];
        off += len;

        if idx < real_count {
            let expected = make_tag(password, idx, data, &salt);
            if expected == tag {
                real[idx as usize] = Some(data.to_vec());
            }
        }
    }

    if real.iter().any(|x| x.is_none()) {
        return Err("Unable to recover all real packets".into());
    }

    let mut out = Vec::new();
    for p in real {
        out.extend_from_slice(&p.expect("checked above"));
    }
    Ok(out)
}

#[allow(dead_code)]
fn deadman_wrap_legacy(payload: &[u8], expires_unix: u64, emergency_key: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DEADMAN_MAGIC);
    out.extend_from_slice(&expires_unix.to_le_bytes());
    if let Some(k) = emergency_key {
        let mut h = Sha256::new();
        h.update(k.as_bytes());
        let d = h.finalize();
        out.push(1);
        out.extend_from_slice(&d[..16]);
    } else {
        out.push(0);
        out.extend_from_slice(&[0u8; 16]);
    }
    out.extend_from_slice(payload);
    out
}

fn deadman_unwrap_legacy(blob: &[u8], emergency_key: Option<&str>) -> Result<Vec<u8>, String> {
    if blob.len() < 4 + 8 + 1 + 16 {
        return Err("Invalid dead-man blob".into());
    }
    if &blob[..4] != DEADMAN_MAGIC {
        return Ok(blob.to_vec());
    }
    let mut off = 4usize;
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&blob[off..off + 8]);
    off += 8;
    let expires = u64::from_le_bytes(ts);
    let has_emergency = blob[off];
    off += 1;
    let hash = &blob[off..off + 16];
    off += 16;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    if now <= expires {
        return Ok(blob[off..].to_vec());
    }

    if has_emergency == 1 {
        if let Some(key) = emergency_key {
            let mut h = Sha256::new();
            h.update(key.as_bytes());
            let d = h.finalize();
            if &d[..16] == hash {
                return Ok(blob[off..].to_vec());
            }
        }
    }

    Err("Dead-man switch active: data locked".into())
}

fn permuted_positions(len: usize, password: &str) -> Vec<usize> {
    let mut salt = [0u8; 16];
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    let d = h.finalize();
    salt.copy_from_slice(&d[..16]);
    let mut seed = derive_seed(password, &salt);
    let mut p: Vec<usize> = (0..len).collect();
    for i in (1..len).rev() {
        let j = (splitmix64(&mut seed) as usize) % (i + 1);
        p.swap(i, j);
    }
    p
}

#[allow(dead_code)]
fn stego_embed_legacy(carrier: &[u8], secret: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut payload = Vec::with_capacity(STEGO_LEN_BYTES + secret.len());
    payload.extend_from_slice(&(secret.len() as u64).to_le_bytes());
    payload.extend_from_slice(secret);

    let needed_bits = payload.len() * 8;
    if needed_bits > carrier.len() {
        return Err("Carrier file too small for payload".into());
    }

    let pos = permuted_positions(carrier.len(), password);
    let mut out = carrier.to_vec();
    for bit_idx in 0..needed_bits {
        let byte = payload[bit_idx / 8];
        let bit = (byte >> (bit_idx % 8)) & 1;
        let at = pos[bit_idx];
        out[at] = (out[at] & 0xFE) | bit;
    }
    Ok(out)
}

fn stego_extract_legacy(stego: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if stego.len() < STEGO_LEN_BYTES * 8 {
        return Err("Stego file too small".into());
    }
    let pos = permuted_positions(stego.len(), password);

    let mut len_bytes = [0u8; STEGO_LEN_BYTES];
    for bit_idx in 0..(STEGO_LEN_BYTES * 8) {
        let at = pos[bit_idx];
        let bit = stego[at] & 1;
        len_bytes[bit_idx / 8] |= bit << (bit_idx % 8);
    }
    let payload_len = u64::from_le_bytes(len_bytes) as usize;
    let needed_bits = payload_len
        .checked_add(STEGO_LEN_BYTES)
        .and_then(|n| n.checked_mul(8))
        .ok_or("Stego payload length invalid")?;
    if needed_bits > stego.len() {
        return Err("Stego payload length invalid".into());
    }

    let mut payload = vec![0u8; payload_len];
    for bit_idx in 0..(payload_len * 8) {
        let at = pos[(STEGO_LEN_BYTES * 8) + bit_idx];
        let bit = stego[at] & 1;
        payload[bit_idx / 8] |= bit << (bit_idx % 8);
    }
    Ok(payload)
}

fn runtime_entropy_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    h.update(now.as_secs().to_le_bytes());
    h.update(now.subsec_nanos().to_le_bytes());
    h.update(process::id().to_le_bytes());
    h.update(format!("{:?}", std::thread::current().id()).as_bytes());
    if let Ok(user) = std::env::var("USERNAME") {
        h.update(user.as_bytes());
    }
    if let Ok(host) = std::env::var("COMPUTERNAME") {
        h.update(host.as_bytes());
    }
    let p = (&h as *const Sha256 as usize).to_le_bytes();
    h.update(p);
    h.finalize().into()
}

fn xor_stream(input: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    for (i, b) in input.iter().enumerate() {
        out[i] = *b ^ key[i % key.len()];
    }
    out
}

#[allow(dead_code)]
fn entropy_poison_wrap_legacy(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 32];
    crypto::random_bytes(&mut salt).map_err(|e| e.to_string())?;
    let entropy = runtime_entropy_hash();
    let mut ticket = [0u8; 32];
    for i in 0..32 {
        ticket[i] = salt[i] ^ entropy[i];
    }
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(ticket);
    let key: [u8; 32] = h.finalize().into();
    let masked = xor_stream(payload, &key);
    let mut out = Vec::with_capacity(4 + 32 + masked.len());
    out.extend_from_slice(ENTROPY_MAGIC);
    out.extend_from_slice(&ticket);
    out.extend_from_slice(&masked);
    Ok(out)
}

fn entropy_poison_unwrap_legacy(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 4 + 32 {
        return Err("Invalid entropy-poison blob".into());
    }
    if &blob[..4] != ENTROPY_MAGIC {
        return Ok(blob.to_vec());
    }
    let ticket = &blob[4..36];
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(ticket);
    let key: [u8; 32] = h.finalize().into();
    Ok(xor_stream(&blob[36..], &key))
}

#[allow(dead_code)]
fn polymorphic_wrap_legacy(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 32];
    crypto::random_bytes(&mut salt).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(salt);
    let key: [u8; 32] = h.finalize().into();

    let mut r = [0u8; 2];
    crypto::random_bytes(&mut r).map_err(|e| e.to_string())?;
    let prefix = 64 + (r[0] as usize % 192);
    let suffix = 64 + (r[1] as usize % 192);
    let total = 32 + prefix + payload.len() + suffix;

    let mut out = vec![0u8; total];
    crypto::random_bytes(&mut out).map_err(|e| e.to_string())?;
    out[..32].copy_from_slice(&salt);
    let start = 32 + prefix;
    let end = start + payload.len();
    out[start..end].copy_from_slice(payload);

    let meta_pos = 40 + (key[0] as usize % 24);
    let mut meta = [0u8; 8];
    meta[..4].copy_from_slice(&(prefix as u32).to_le_bytes());
    meta[4..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    for i in 0..8 {
        out[meta_pos + i] = meta[i] ^ key[i];
    }

    let mut c = Sha256::new();
    c.update(password.as_bytes());
    c.update(payload);
    c.update(salt);
    let canary = c.finalize();
    for i in 0..8 {
        out[meta_pos + 8 + i] = canary[i] ^ key[8 + i];
    }
    Ok(out)
}

fn polymorphic_unwrap_legacy(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 32 + 64 {
        return Err("Invalid polymorphic blob".into());
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&blob[..32]);

    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(salt);
    let key: [u8; 32] = h.finalize().into();

    let meta_pos = 40 + (key[0] as usize % 24);
    if meta_pos + 16 > blob.len() {
        return Err("Invalid polymorphic metadata".into());
    }

    let mut meta = [0u8; 8];
    for i in 0..8 {
        meta[i] = blob[meta_pos + i] ^ key[i];
    }
    let mut pb = [0u8; 4];
    pb.copy_from_slice(&meta[..4]);
    let prefix = u32::from_le_bytes(pb) as usize;
    let mut lb = [0u8; 4];
    lb.copy_from_slice(&meta[4..]);
    let len = u32::from_le_bytes(lb) as usize;

    let start = 32 + prefix;
    let end = start.saturating_add(len);
    if end > blob.len() {
        return Err("Invalid polymorphic payload bounds".into());
    }
    let payload = blob[start..end].to_vec();

    let mut c = Sha256::new();
    c.update(password.as_bytes());
    c.update(&payload);
    c.update(salt);
    let canary = c.finalize();
    for i in 0..8 {
        let got = blob[meta_pos + 8 + i] ^ key[8 + i];
        if got != canary[i] {
            return Err("Invalid polymorphic canary".into());
        }
    }

    Ok(payload)
}

#[allow(dead_code)]
fn quantum_canary_wrap_legacy(payload: &[u8], password: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(b"|quantum-canary|");
    h.update(payload);
    let canary = h.finalize();
    let mut out = Vec::with_capacity(4 + 16 + payload.len());
    out.extend_from_slice(QCAN_MAGIC);
    out.extend_from_slice(&canary[..16]);
    out.extend_from_slice(payload);
    out
}

fn quantum_canary_unwrap_legacy(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 4 + 16 {
        return Err("Invalid quantum canary blob".into());
    }
    if &blob[..4] != QCAN_MAGIC {
        return Ok(blob.to_vec());
    }
    let tag = &blob[4..20];
    let payload = &blob[20..];
    let mut h = Sha256::new();
    h.update(password.as_bytes());
    h.update(b"|quantum-canary|");
    h.update(payload);
    let canary = h.finalize();
    if &canary[..16] != tag {
        return Err("Quantum canary tripped".into());
    }
    Ok(payload.to_vec())
}

#[allow(dead_code)]
fn plausible_create_legacy(
    decoy_plain: &[u8],
    hidden_plain: &[u8],
    decoy_password: &str,
    hidden_password: &str,
) -> Result<Vec<u8>, String> {
    let mut decoy_ct = Vec::new();
    encrypt_kaotik(Cursor::new(decoy_plain), &mut decoy_ct, decoy_password)
        .map_err(|e| e.to_string())?;
    let mut hidden_ct = Vec::new();
    encrypt_kaotik(Cursor::new(hidden_plain), &mut hidden_ct, hidden_password)
        .map_err(|e| e.to_string())?;

    let mut order = [0u8; 1];
    crypto::random_bytes(&mut order).map_err(|e| e.to_string())?;
    let (a, b) = if (order[0] & 1) == 0 {
        (decoy_ct, hidden_ct)
    } else {
        (hidden_ct, decoy_ct)
    };

    let mut out = Vec::new();
    out.extend_from_slice(PLAUSIBLE_MAGIC);
    out.extend_from_slice(&(a.len() as u32).to_le_bytes());
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(&a);
    out.extend_from_slice(&b);
    Ok(out)
}

fn plausible_open_legacy(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 4 + 4 + 4 {
        return Err("Invalid plausible container".into());
    }
    if &blob[..4] != PLAUSIBLE_MAGIC {
        return Err("Invalid plausible magic".into());
    }
    let mut a_len_b = [0u8; 4];
    a_len_b.copy_from_slice(&blob[4..8]);
    let a_len = u32::from_le_bytes(a_len_b) as usize;
    let mut b_len_b = [0u8; 4];
    b_len_b.copy_from_slice(&blob[8..12]);
    let b_len = u32::from_le_bytes(b_len_b) as usize;
    if blob.len() < 12 + a_len + b_len {
        return Err("Malformed plausible container".into());
    }
    let a = &blob[12..12 + a_len];
    let b = &blob[12 + a_len..12 + a_len + b_len];

    for part in [a, b] {
        let mut out = Vec::new();
        if decrypt_kaotik(Cursor::new(part), &mut out, password).is_ok() {
            return Ok(out);
        }
    }
    Err("No plausible layer matched the password".into())
}

// ---------------------------------------------------------------------------
// v2 katmanları: tüm parola kullanımları Argon2id (256 MiB) ana anahtarı + HKDF alt anahtarları üzerinden.
// Hiçbir katman parolayı hızlı hash (SHA-256) ile işlemez; bu sayede dış katmanlar parola tahmin
// oracle'ı olmaz ve Argon2 maliyeti atlatılamaz. Gizlilik/bütünlük AES-256-GCM (AAD) veya HMAC-SHA256 ile.
// Eski (v1) biçimler yalnızca okunur, geri uyumluluk için.
// ---------------------------------------------------------------------------

const CHAFF2_MAGIC: &[u8; 5] = b"CHFF2";
const DEADMAN2_MAGIC: &[u8; 4] = b"DMS2";
const ENTROPY2_MAGIC: &[u8; 4] = b"ENP2";
const QCAN2_MAGIC: &[u8; 4] = b"QCN2";
const SALT: usize = crypto::SALT_LEN;
const NONCE: usize = crypto::NONCE_LEN;
const TAG: usize = crypto::TAG_LEN;
const CHAFF_CHUNK: usize = 512;
const STEGO_SALT_BITS: usize = SALT * 8;
const PLAUSIBLE_BLOCK: usize = 4096;

fn e2s(e: kaotik::Error) -> String {
    e.to_string()
}

/// Parola + tuz → Argon2id ana anahtar → `info` bağlamına özel alt anahtar.
fn layer_key(password: &str, salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let master = Zeroizing::new(crypto::derive_key(password, salt, crypto::KDF_DEFAULT).map_err(e2s)?);
    Ok(Zeroizing::new(crypto::subkey(&master, info).map_err(e2s)?))
}

fn rand_array<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    crypto::random_bytes(&mut b).map_err(e2s)?;
    Ok(b)
}

/// Zarf: magic | salt | nonce | AES-GCM(payload, aad = magic|salt|nonce|extra).
fn seal(magic: &[u8], password: &str, info: &[u8], extra_aad: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let nonce: [u8; NONCE] = rand_array()?;
    let key = layer_key(password, &salt, info)?;
    let aad = [magic, &salt[..], &nonce[..], extra_aad].concat();
    let ct = crypto::aes_gcm_encrypt_aad(&key, &nonce, payload, &aad).map_err(e2s)?;
    Ok([&aad[..magic.len() + SALT + NONCE], &ct[..]].concat())
}

fn open(magic: &[u8], password: &str, info: &[u8], extra_aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    let hdr = magic.len() + SALT + NONCE;
    if blob.len() < hdr + TAG || &blob[..magic.len()] != magic {
        return Err("Invalid sealed layer".into());
    }
    let salt = &blob[magic.len()..magic.len() + SALT];
    let mut nonce = [0u8; NONCE];
    nonce.copy_from_slice(&blob[magic.len() + SALT..hdr]);
    let key = layer_key(password, salt, info)?;
    let aad = [&blob[..hdr], extra_aad].concat();
    crypto::aes_gcm_decrypt_aad(&key, &nonce, &blob[hdr..], &aad).map_err(|_| "Layer authentication failed".to_string())
}

/// Anahtarlı deterministik üreteç: HMAC-SHA256(key, sayaç) blokları (kriptografik PRF).
struct KeyedRng {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl KeyedRng {
    fn new(key: Zeroizing<[u8; 32]>) -> Self {
        KeyedRng { key, counter: 0, buf: [0u8; 32], pos: 32 }
    }
    fn next_u64(&mut self) -> u64 {
        if self.pos + 8 > 32 {
            self.buf = crypto::hmac_sha256(&self.key[..], &[&self.counter.to_le_bytes()]);
            self.counter += 1;
            self.pos = 0;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_le_bytes(b)
    }
    /// [0, n) aralığında yansız (rejection sampling) sayı.
    fn below(&mut self, n: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }
}

// --- Chaff & winnow -------------------------------------------------------
// Tüm paketler aynı boyutta (512 B), sahte paketler gerçek indeksleri taşır, etiketler HMAC-SHA256(Argon2 alt anahtarı).
// Böylece boyut, indeks veya etiket üzerinden gerçek/sahte ayrımı yapılamaz; etiket parola oracle'ı değildir.

pub fn chaff_pack(payload: &[u8], password: &str, fake_packets: u32) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let mac_key = layer_key(password, &salt, b"kaotik-chaff-v2-mac")?;

    let mut body = Zeroizing::new(Vec::with_capacity(8 + payload.len() + CHAFF_CHUNK));
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.extend_from_slice(payload);
    let padded_len = body.len().div_ceil(CHAFF_CHUNK) * CHAFF_CHUNK;
    let mut pad = vec![0u8; padded_len - body.len()];
    crypto::random_bytes(&mut pad).map_err(e2s)?;
    body.extend_from_slice(&pad);
    let real_count = (padded_len / CHAFF_CHUNK) as u32;

    let mut packets: Vec<(u32, Vec<u8>, [u8; 16])> = Vec::new();
    for (i, c) in body.chunks(CHAFF_CHUNK).enumerate() {
        let idx = i as u32;
        let full = crypto::hmac_sha256(&mac_key[..], &[&salt, &idx.to_le_bytes(), c]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full[..16]);
        packets.push((idx, c.to_vec(), tag));
    }
    let mut rng = KeyedRng::new(Zeroizing::new(rand_array()?));
    for _ in 0..fake_packets {
        let idx = rng.below(real_count as u64) as u32;
        let mut data = vec![0u8; CHAFF_CHUNK];
        crypto::random_bytes(&mut data).map_err(e2s)?;
        packets.push((idx, data, rand_array()?));
    }
    for i in (1..packets.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        packets.swap(i, j);
    }

    let mut out = Vec::new();
    out.extend_from_slice(CHAFF2_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&real_count.to_le_bytes());
    out.extend_from_slice(&(packets.len() as u32).to_le_bytes());
    for (idx, data, tag) in packets {
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&tag);
        out.extend_from_slice(&data);
    }
    Ok(out)
}

pub fn chaff_unpack(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() >= 5 && &blob[..5] == CHAFF_MAGIC {
        return chaff_unpack_legacy(blob, password);
    }
    let hdr = 5 + SALT + 8;
    if blob.len() < hdr || &blob[..5] != CHAFF2_MAGIC {
        return Err("Invalid chaff blob".into());
    }
    let salt = &blob[5..5 + SALT];
    let real_count = u32::from_le_bytes(blob[5 + SALT..5 + SALT + 4].try_into().unwrap()) as usize;
    let total = u32::from_le_bytes(blob[5 + SALT + 4..hdr].try_into().unwrap()) as usize;
    let pkt = 4 + 16 + CHAFF_CHUNK;
    if real_count == 0 || total < real_count || blob.len() != hdr + total * pkt {
        return Err("Malformed chaff blob".into());
    }
    let mac_key = layer_key(password, salt, b"kaotik-chaff-v2-mac")?;
    let mut real: Vec<Option<&[u8]>> = vec![None; real_count];
    for p in blob[hdr..].chunks(pkt) {
        let idx = u32::from_le_bytes(p[..4].try_into().unwrap());
        let tag = &p[4..20];
        let data = &p[20..];
        if (idx as usize) < real_count {
            let full = crypto::hmac_sha256(&mac_key[..], &[salt, &idx.to_le_bytes(), data]);
            if crypto::ct_eq(&full[..16], tag) {
                real[idx as usize] = Some(data);
            }
        }
    }
    let mut body = Zeroizing::new(Vec::with_capacity(real_count * CHAFF_CHUNK));
    for r in real {
        body.extend_from_slice(r.ok_or("Unable to recover all real packets")?);
    }
    let len = u64::from_le_bytes(body[..8].try_into().unwrap()) as usize;
    if len > body.len() - 8 {
        return Err("Malformed chaff payload".into());
    }
    Ok(body[8..8 + len].to_vec())
}

// --- Dead-man switch -----------------------------------------------------
// Veri rastgele bir veri anahtarıyla şifrelenir. Veri anahtarı iki yuvada saklanır:
// (1) parola yuvası — yalnızca son tarihe kadar kullanılır, (2) acil anahtar yuvası — her zaman.
// Son tarih AAD ile doğrulanır: değiştirilirse tüm yuvalar açılmaz.
// Not: Çevrimdışı bir dosyada zaman kilidi yerel saate dayanır; parola sahibinin saati geri alması
// engellenemez. Kriptografik olarak garanti edilen: son tarih değiştirilemez ve acil anahtar olmadan
// parola dışında bir yol yoktur.

fn deadman_slot(secret: &str, info: &[u8], aad: &[u8], data_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let nonce: [u8; NONCE] = rand_array()?;
    let k = layer_key(secret, &salt, info)?;
    let ct = crypto::aes_gcm_encrypt_aad(&k, &nonce, data_key, aad).map_err(e2s)?;
    Ok([&salt[..], &nonce[..], &ct[..]].concat())
}

fn deadman_slot_open(secret: &str, info: &[u8], aad: &[u8], slot: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let k = layer_key(secret, &slot[..SALT], info).ok()?;
    let nonce: [u8; NONCE] = slot[SALT..SALT + NONCE].try_into().ok()?;
    let pt = Zeroizing::new(crypto::aes_gcm_decrypt_aad(&k, &nonce, &slot[SALT + NONCE..], aad).ok()?);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(pt.get(..32)?);
    Some(out)
}

const DM_SLOT: usize = SALT + NONCE + 32 + TAG;

pub fn deadman_wrap(payload: &[u8], expires_unix: u64, password: &str, emergency_key: Option<&str>) -> Result<Vec<u8>, String> {
    let data_key = Zeroizing::new(rand_array::<32>()?);
    let flags = emergency_key.is_some() as u8;
    let mut hdr = Vec::new();
    hdr.extend_from_slice(DEADMAN2_MAGIC);
    hdr.extend_from_slice(&expires_unix.to_le_bytes());
    hdr.push(flags);
    let pw_slot = deadman_slot(password, b"kaotik-dms-v2-password", &hdr, &data_key)?;
    let em_slot = match emergency_key {
        Some(k) => deadman_slot(k, b"kaotik-dms-v2-emergency", &hdr, &data_key)?,
        None => {
            let mut r = vec![0u8; DM_SLOT];
            crypto::random_bytes(&mut r).map_err(e2s)?;
            r
        }
    };
    let nonce: [u8; NONCE] = rand_array()?;
    let ct = crypto::aes_gcm_encrypt_aad(&data_key, &nonce, payload, &hdr).map_err(e2s)?;
    Ok([&hdr[..], &pw_slot, &em_slot, &nonce[..], &ct].concat())
}

pub fn deadman_unwrap(blob: &[u8], password: Option<&str>, emergency_key: Option<&str>) -> Result<Vec<u8>, String> {
    if blob.len() >= 4 && &blob[..4] == DEADMAN_MAGIC {
        return deadman_unwrap_legacy(blob, emergency_key);
    }
    if blob.len() < 4 || &blob[..4] != DEADMAN2_MAGIC {
        return Ok(blob.to_vec());
    }
    let hdr_len = 4 + 8 + 1;
    if blob.len() < hdr_len + 2 * DM_SLOT + NONCE + TAG {
        return Err("Invalid dead-man blob".into());
    }
    let hdr = &blob[..hdr_len];
    let expires = u64::from_le_bytes(blob[4..12].try_into().unwrap());
    let has_emergency = blob[12] == 1;
    let pw_slot = &blob[hdr_len..hdr_len + DM_SLOT];
    let em_slot = &blob[hdr_len + DM_SLOT..hdr_len + 2 * DM_SLOT];
    let rest = &blob[hdr_len + 2 * DM_SLOT..];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();

    let mut data_key = None;
    if now <= expires {
        if let Some(p) = password {
            data_key = deadman_slot_open(p, b"kaotik-dms-v2-password", hdr, pw_slot);
        }
    }
    if data_key.is_none() && has_emergency {
        if let Some(k) = emergency_key {
            data_key = deadman_slot_open(k, b"kaotik-dms-v2-emergency", hdr, em_slot);
        }
    }
    let data_key = data_key.ok_or("Dead-man switch active: data locked")?;
    let nonce: [u8; NONCE] = rest[..NONCE].try_into().unwrap();
    crypto::aes_gcm_decrypt_aad(&data_key, &nonce, &rest[NONCE..], hdr).map_err(|_| "Dead-man payload authentication failed".to_string())
}

// --- Steganografi --------------------------------------------------------
// İlk 256 LSB rastgele tuzu taşır (rastgele bitlerden ayırt edilemez). Kalan bit konumları
// Argon2 alt anahtarıyla beslenen HMAC-PRF ile karıştırılır; gömülen veri AES-GCM ile şifrelenir.
// Çıkarılan ham bitler şifreli metin olduğundan uzunluk dahil hiçbir bilgi sızdırmaz.

fn stego_positions(len: usize, key: Zeroizing<[u8; 32]>) -> Vec<usize> {
    let mut p: Vec<usize> = (STEGO_SALT_BITS..len).collect();
    let mut rng = KeyedRng::new(key);
    for i in (1..p.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        p.swap(i, j);
    }
    p
}

fn stego_write_bits(out: &mut [u8], pos: &[usize], bytes: &[u8]) {
    for bit_idx in 0..bytes.len() * 8 {
        let bit = (bytes[bit_idx / 8] >> (bit_idx % 8)) & 1;
        out[pos[bit_idx]] = (out[pos[bit_idx]] & 0xFE) | bit;
    }
}

fn stego_read_bits(src: &[u8], pos: &[usize], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    for bit_idx in 0..n * 8 {
        out[bit_idx / 8] |= (src[pos[bit_idx]] & 1) << (bit_idx % 8);
    }
    out
}

pub fn stego_embed(carrier: &[u8], secret: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let nonce: [u8; NONCE] = rand_array()?;
    let master = Zeroizing::new(crypto::derive_key(password, &salt, crypto::KDF_DEFAULT).map_err(e2s)?);
    let pos_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-stego-v2-positions").map_err(e2s)?);
    let enc_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-stego-v2-aead").map_err(e2s)?);
    let len_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-stego-v2-len").map_err(e2s)?);

    let ct = crypto::aes_gcm_encrypt_aad(&enc_key, &nonce, secret, &salt).map_err(e2s)?;
    // Uzunluk, anahtar akışıyla maskelenir (şifreli metin uzunluğu dışarıdan görünmez).
    let mask = crypto::hmac_sha256(&len_key[..], &[b"len"]);
    let mut len_bytes = (ct.len() as u64).to_le_bytes();
    for i in 0..8 {
        len_bytes[i] ^= mask[i];
    }
    let payload = [&len_bytes[..], &nonce[..], &ct[..]].concat();
    if STEGO_SALT_BITS + payload.len() * 8 > carrier.len() {
        return Err("Carrier file too small for payload".into());
    }
    let mut out = carrier.to_vec();
    let salt_pos: Vec<usize> = (0..STEGO_SALT_BITS).collect();
    stego_write_bits(&mut out, &salt_pos, &salt);
    let pos = stego_positions(carrier.len(), pos_key);
    stego_write_bits(&mut out, &pos, &payload);
    Ok(out)
}

pub fn stego_extract(stego: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if stego.len() < STEGO_SALT_BITS + (STEGO_LEN_BYTES + NONCE + TAG) * 8 {
        return Err("Stego file too small".into());
    }
    let salt_pos: Vec<usize> = (0..STEGO_SALT_BITS).collect();
    let salt = stego_read_bits(stego, &salt_pos, SALT);
    let master = Zeroizing::new(crypto::derive_key(password, &salt, crypto::KDF_DEFAULT).map_err(e2s)?);
    let pos_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-stego-v2-positions").map_err(e2s)?);
    let enc_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-stego-v2-aead").map_err(e2s)?);
    let len_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-stego-v2-len").map_err(e2s)?);
    let pos = stego_positions(stego.len(), pos_key);

    let head = stego_read_bits(stego, &pos, STEGO_LEN_BYTES + NONCE);
    let mask = crypto::hmac_sha256(&len_key[..], &[b"len"]);
    let mut lb = [0u8; 8];
    for i in 0..8 {
        lb[i] = head[i] ^ mask[i];
    }
    let ct_len = u64::from_le_bytes(lb) as usize;
    let total = STEGO_LEN_BYTES + NONCE + ct_len;
    if ct_len >= TAG && total.checked_mul(8).is_some_and(|b| b <= pos.len()) {
        let payload = stego_read_bits(stego, &pos, total);
        let nonce: [u8; NONCE] = payload[8..8 + NONCE].try_into().unwrap();
        if let Ok(pt) = crypto::aes_gcm_decrypt_aad(&enc_key, &nonce, &payload[8 + NONCE..], &salt) {
            return Ok(pt);
        }
    }
    // Eski (v1) biçim: şifrelenmemiş, SHA-256 konumlu.
    stego_extract_legacy(stego, password).map_err(|_| "Stego extraction failed".to_string())
}

// --- Entropy poisoning ---------------------------------------------------
// Tuz = OS CSPRNG ⊕ çalışma zamanı ölçümü (CSPRNG tek başına yeterlidir; ölçüm yalnızca ek karıştırmadır).

pub fn entropy_poison_wrap(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let entropy = runtime_entropy_hash();
    let mut ticket: [u8; 32] = rand_array()?;
    for i in 0..32 {
        ticket[i] ^= entropy[i];
    }
    let sealed = seal(ENTROPY2_MAGIC, password, b"kaotik-entropy-v2", &ticket, payload)?;
    Ok([&sealed[..4], &ticket[..], &sealed[4..]].concat())
}

pub fn entropy_poison_unwrap(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() >= 4 && &blob[..4] == ENTROPY_MAGIC {
        return entropy_poison_unwrap_legacy(blob, password);
    }
    if blob.len() < 4 + 32 || &blob[..4] != ENTROPY2_MAGIC {
        return Ok(blob.to_vec());
    }
    let ticket = &blob[4..36];
    let inner = [&blob[..4], &blob[36..]].concat();
    open(ENTROPY2_MAGIC, password, b"kaotik-entropy-v2", ticket, &inner)
}

// --- Polimorfik sarmalama ------------------------------------------------
// Düzen: salt | nonce | AEAD_meta(prefix, ct_len) | rastgele önek | AEAD(payload) | rastgele sonek.
// Sabit imza yok; tüm baytlar rastgele/şifreli metinden ayırt edilemez.

const POLY_META_CT: usize = 8 + TAG;

pub fn polymorphic_wrap(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let nonce: [u8; NONCE] = rand_array()?;
    let master = Zeroizing::new(crypto::derive_key(password, &salt, crypto::KDF_DEFAULT).map_err(e2s)?);
    let meta_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-poly-v2-meta").map_err(e2s)?);
    let data_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-poly-v2-data").map_err(e2s)?);
    let r: [u8; 2] = rand_array()?;
    let prefix = 64 + (r[0] as usize % 192);
    let suffix = 64 + (r[1] as usize % 192);
    let aad = [&salt[..], &nonce[..]].concat();
    let data_ct = crypto::aes_gcm_encrypt_aad(&data_key, &nonce, payload, &aad).map_err(e2s)?;
    let mut meta = [0u8; 8];
    meta[..4].copy_from_slice(&(prefix as u32).to_le_bytes());
    meta[4..].copy_from_slice(&(data_ct.len() as u32).to_le_bytes());
    let meta_ct = crypto::aes_gcm_encrypt_aad(&meta_key, &nonce, &meta, &aad).map_err(e2s)?;
    let mut pre = vec![0u8; prefix];
    let mut suf = vec![0u8; suffix];
    crypto::random_bytes(&mut pre).map_err(e2s)?;
    crypto::random_bytes(&mut suf).map_err(e2s)?;
    Ok([&aad[..], &meta_ct, &pre, &data_ct, &suf].concat())
}

pub fn polymorphic_unwrap(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let head = SALT + NONCE + POLY_META_CT;
    if blob.len() >= head + TAG {
        let salt = &blob[..SALT];
        let nonce: [u8; NONCE] = blob[SALT..SALT + NONCE].try_into().unwrap();
        let aad = &blob[..SALT + NONCE];
        let master = Zeroizing::new(crypto::derive_key(password, salt, crypto::KDF_DEFAULT).map_err(e2s)?);
        let meta_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-poly-v2-meta").map_err(e2s)?);
        if let Ok(meta) = crypto::aes_gcm_decrypt_aad(&meta_key, &nonce, &blob[SALT + NONCE..head], aad) {
            let prefix = u32::from_le_bytes(meta[..4].try_into().unwrap()) as usize;
            let ct_len = u32::from_le_bytes(meta[4..8].try_into().unwrap()) as usize;
            let start = head + prefix;
            let end = start.checked_add(ct_len).ok_or("Invalid polymorphic bounds")?;
            if end > blob.len() {
                return Err("Invalid polymorphic payload bounds".into());
            }
            let data_key = Zeroizing::new(crypto::subkey(&master, b"kaotik-poly-v2-data").map_err(e2s)?);
            return crypto::aes_gcm_decrypt_aad(&data_key, &nonce, &blob[start..end], aad)
                .map_err(|_| "Invalid polymorphic payload".to_string());
        }
    }
    polymorphic_unwrap_legacy(blob, password)
}

// --- Bütünlük kanaryası --------------------------------------------------
// Kanarya = HMAC-SHA256(Argon2 alt anahtarı, payload). Herhangi bir bit değişimi tespit edilir.

pub fn quantum_canary_wrap(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let key = layer_key(password, &salt, b"kaotik-canary-v2")?;
    let tag = crypto::hmac_sha256(&key[..], &[QCAN2_MAGIC, &salt, payload]);
    Ok([&QCAN2_MAGIC[..], &salt, &tag, payload].concat())
}

pub fn quantum_canary_unwrap(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() >= 4 && &blob[..4] == QCAN_MAGIC {
        return quantum_canary_unwrap_legacy(blob, password);
    }
    if blob.len() < 4 || &blob[..4] != QCAN2_MAGIC {
        return Ok(blob.to_vec());
    }
    if blob.len() < 4 + SALT + 32 {
        return Err("Invalid quantum canary blob".into());
    }
    let salt = &blob[4..4 + SALT];
    let tag = &blob[4 + SALT..4 + SALT + 32];
    let payload = &blob[4 + SALT + 32..];
    let key = layer_key(password, salt, b"kaotik-canary-v2")?;
    let expected = crypto::hmac_sha256(&key[..], &[QCAN2_MAGIC, salt, payload]);
    if !crypto::ct_eq(&expected, tag) {
        return Err("Quantum canary tripped".into());
    }
    Ok(payload.to_vec())
}

// --- İnkâr edilebilir (plausible deniability) konteyner ------------------
// İki eşit boyutlu yuva; her biri salt | nonce | AES-GCM(len | veri | rastgele dolgu). Sihirli bayt,
// uzunluk alanı veya düz metin metaverisi yoktur: konteyner tamamen rastgele görünür ve gizli katmanın
// varlığı kanıtlanamaz (decoy parolası yalnızca kendi yuvasını açar; diğer yuva rastgele veriden ayırt edilemez).
// Açarken her iki yuva için de Argon2 çalıştırılır (zamanlama hangi yuvanın açıldığını sızdırmaz).

fn plausible_slot(plain: &[u8], password: &str, body_len: usize) -> Result<Vec<u8>, String> {
    let salt: [u8; SALT] = rand_array()?;
    let nonce: [u8; NONCE] = rand_array()?;
    let key = layer_key(password, &salt, b"kaotik-pdn-v2")?;
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    body.extend_from_slice(&(plain.len() as u64).to_le_bytes());
    body.extend_from_slice(plain);
    let mut pad = vec![0u8; body_len - body.len()];
    crypto::random_bytes(&mut pad).map_err(e2s)?;
    body.extend_from_slice(&pad);
    let ct = crypto::aes_gcm_encrypt_aad(&key, &nonce, &body, &salt).map_err(e2s)?;
    Ok([&salt[..], &nonce[..], &ct].concat())
}

pub fn plausible_create(
    decoy_plain: &[u8],
    hidden_plain: &[u8],
    decoy_password: &str,
    hidden_password: &str,
) -> Result<Vec<u8>, String> {
    kaotik::validate_password(decoy_password).map_err(e2s)?;
    kaotik::validate_password(hidden_password).map_err(e2s)?;
    if crypto::ct_eq(decoy_password.as_bytes(), hidden_password.as_bytes()) {
        return Err("Decoy and hidden passwords must differ".into());
    }
    let r: [u8; 1] = rand_array()?;
    let need = 8 + decoy_plain.len().max(hidden_plain.len());
    let body_len = (need.div_ceil(PLAUSIBLE_BLOCK) + (r[0] as usize % 4)) * PLAUSIBLE_BLOCK;
    let d = plausible_slot(decoy_plain, decoy_password, body_len)?;
    let h = plausible_slot(hidden_plain, hidden_password, body_len)?;
    let (a, b) = if (r[0] >> 7) == 0 { (d, h) } else { (h, d) };
    Ok([a, b].concat())
}

pub fn plausible_open(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if blob.len() >= 4 && &blob[..4] == PLAUSIBLE_MAGIC {
        return plausible_open_legacy(blob, password);
    }
    if !blob.len().is_multiple_of(2) || blob.len() < 2 * (SALT + NONCE + TAG + 8) {
        return Err("Invalid plausible container".into());
    }
    let half = blob.len() / 2;
    let mut found: Option<Vec<u8>> = None;
    for slot in [&blob[..half], &blob[half..]] {
        let salt = &slot[..SALT];
        let nonce: [u8; NONCE] = slot[SALT..SALT + NONCE].try_into().unwrap();
        let key = layer_key(password, salt, b"kaotik-pdn-v2")?;
        if let Ok(body) = crypto::aes_gcm_decrypt_aad(&key, &nonce, &slot[SALT + NONCE..], salt) {
            let body = Zeroizing::new(body);
            let len = u64::from_le_bytes(body[..8].try_into().unwrap()) as usize;
            if found.is_none() && len <= body.len() - 8 {
                found = Some(body[8..8 + len].to_vec());
            }
        }
    }
    found.ok_or_else(|| "No plausible layer matched the password".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "TestPassword123!@#";
    const PW2: &str = "HiddenPassword456$%^";

    #[test]
    fn chaff_roundtrip_uniform_packets_and_wrong_password() {
        let data: Vec<u8> = (0..1500u32).map(|i| i as u8).collect();
        let blob = chaff_pack(&data, PW, 10).unwrap();
        assert_eq!(chaff_unpack(&blob, PW).unwrap(), data);
        assert!(chaff_unpack(&blob, PW2).is_err());
        let total = u32::from_le_bytes(blob[5 + SALT + 4..5 + SALT + 8].try_into().unwrap()) as usize;
        assert_eq!(blob.len(), 5 + SALT + 8 + total * (4 + 16 + CHAFF_CHUNK));
    }

    #[test]
    fn deadman_password_emergency_and_tamper() {
        let far = u64::MAX;
        let blob = deadman_wrap(b"secret", far, PW, Some(PW2)).unwrap();
        assert_eq!(deadman_unwrap(&blob, Some(PW), None).unwrap(), b"secret");
        assert_eq!(deadman_unwrap(&blob, None, Some(PW2)).unwrap(), b"secret");
        let expired = deadman_wrap(b"secret", 1, PW, Some(PW2)).unwrap();
        assert!(deadman_unwrap(&expired, Some(PW), None).is_err());
        assert_eq!(deadman_unwrap(&expired, Some(PW), Some(PW2)).unwrap(), b"secret");
        // Son tarihi uzatma denemesi: AAD doğrulaması başarısız olmalı.
        let mut forged = expired.clone();
        forged[4..12].copy_from_slice(&far.to_le_bytes());
        assert!(deadman_unwrap(&forged, Some(PW), None).is_err());
    }

    #[test]
    fn stego_roundtrip_and_wrong_password() {
        let mut carrier = vec![0u8; 8192];
        crypto::random_bytes(&mut carrier).unwrap();
        let out = stego_embed(&carrier, b"hidden msg", PW).unwrap();
        assert_eq!(stego_extract(&out, PW).unwrap(), b"hidden msg");
        assert!(stego_extract(&out, PW2).map(|v| v != b"hidden msg").unwrap_or(true));
    }

    #[test]
    fn wrappers_roundtrip_and_detect_tamper() {
        let data = b"layered payload".to_vec();
        let e = entropy_poison_wrap(&data, PW).unwrap();
        assert_eq!(entropy_poison_unwrap(&e, PW).unwrap(), data);
        assert!(entropy_poison_unwrap(&e, PW2).is_err());

        let p = polymorphic_wrap(&data, PW).unwrap();
        assert_eq!(polymorphic_unwrap(&p, PW).unwrap(), data);
        assert!(polymorphic_unwrap(&p, PW2).is_err());

        let q = quantum_canary_wrap(&data, PW).unwrap();
        assert_eq!(quantum_canary_unwrap(&q, PW).unwrap(), data);
        let mut bad = q.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(quantum_canary_unwrap(&bad, PW).is_err());
    }

    #[test]
    fn plausible_both_layers_open_and_no_magic() {
        let c = plausible_create(b"decoy", b"the real secret", PW, PW2).unwrap();
        assert_ne!(&c[..4], PLAUSIBLE_MAGIC);
        assert_eq!(c.len() % 2, 0);
        assert_eq!(plausible_open(&c, PW).unwrap(), b"decoy");
        assert_eq!(plausible_open(&c, PW2).unwrap(), b"the real secret");
        assert!(plausible_open(&c, "WrongPassword789&*(").is_err());
    }
}
