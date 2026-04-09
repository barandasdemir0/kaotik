use kaotik::{crypto, decrypt_kaotik, encrypt_kaotik};
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

pub fn chaff_pack(payload: &[u8], password: &str, fake_packets: u32) -> Result<Vec<u8>, String> {
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

pub fn chaff_unpack(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn deadman_wrap(payload: &[u8], expires_unix: u64, emergency_key: Option<&str>) -> Vec<u8> {
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

pub fn deadman_unwrap(blob: &[u8], emergency_key: Option<&str>) -> Result<Vec<u8>, String> {
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

pub fn stego_embed(carrier: &[u8], secret: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn stego_extract(stego: &[u8], password: &str) -> Result<Vec<u8>, String> {
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
    let needed_bits = (STEGO_LEN_BYTES + payload_len) * 8;
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

pub fn entropy_poison_wrap(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn entropy_poison_unwrap(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn polymorphic_wrap(payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn polymorphic_unwrap(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn quantum_canary_wrap(payload: &[u8], password: &str) -> Vec<u8> {
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

pub fn quantum_canary_unwrap(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
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

pub fn plausible_create(
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

pub fn plausible_open(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
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
