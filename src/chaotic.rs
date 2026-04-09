// Çok katmanlı kaotik sistem: tam sayı tabanlı lojistik/henon/lorenz/rossler/tent/cubic benzeri
// durum geçişleri, çapraz bağlama, bayt permütasyonu ve S-box ile çalışır.
use crate::crypto;
use crate::error::Result;

const LAYERS: u32 = 8;
const WARMUP_ROUNDS: usize = 512;
const INNER_ROUNDS: usize = 8;

#[inline(always)]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

#[inline(always)]
fn logistic_step(x: u64, r: u64) -> u64 {
    let folded = ((x as u128 * (!x) as u128) >> 32) as u64;
    folded.wrapping_add(r).rotate_left(11) ^ 0xa0761d6478bd642f
}

#[inline(always)]
fn henon_step(x: u64, y: u64, a: u64, b: u64) -> (u64, u64) {
    let nx = y
        .wrapping_add(a.wrapping_mul(x.rotate_left(19)))
        .wrapping_add(0x9e3779b97f4a7c15);
    let ny = b
        .wrapping_mul(x ^ y.rotate_right(7))
        .wrapping_add(0x517cc1b727220a95);
    (nx, ny)
}

#[inline(always)]
fn lorenz_mix(x: u64, y: u64, z: u64, sigma: u64, rho: u64, beta: u64) -> (u64, u64, u64) {
    let nx = x.wrapping_add((y ^ z).rotate_left((sigma as u32 & 31) + 1));
    let ny = y.wrapping_add((x ^ rho).rotate_right((beta as u32 & 31) + 1));
    let nz = z.wrapping_add((x.wrapping_mul(y) ^ sigma).rotate_left((rho as u32 & 31) + 1));
    (nx, ny, nz)
}

#[inline(always)]
fn rossler_mix(x: u64, y: u64, z: u64, a: u64, b: u64, c: u64) -> (u64, u64, u64) {
    let nx = (x.wrapping_sub(y).wrapping_sub(z)).rotate_left((a as u32 & 31) + 1);
    let ny = x.wrapping_add(a.wrapping_mul(y)).rotate_right((b as u32 & 31) + 1);
    let nz = b
        .wrapping_add(z.wrapping_mul(x.wrapping_sub(c)))
        .rotate_left((c as u32 & 31) + 1);
    (nx, ny, nz)
}

#[inline(always)]
fn tent_step(x: u64, mu: u64) -> u64 {
    let threshold = mu | 1;
    if x < threshold {
        x.wrapping_shl(1) ^ mu.rotate_left(3)
    } else {
        (!x).wrapping_shl(1).wrapping_add(mu.rotate_right(5))
    }
}

#[inline(always)]
fn cubic_step(x: u64, r: u64) -> u64 {
    x.wrapping_mul(x)
        .wrapping_mul(x)
        .wrapping_add(r.rotate_left(13))
}

/// Önceki katman çıktısının hash'i (None = ilk katman). Avalanche etkisini artırır.
fn derive_extended_params(
    password: &str,
    salt: &[u8],
    layer: u32,
    prev_layer_hash: Option<&[u8; 32]>,
) -> [u64; 12] {
    use sha2::{Digest, Sha256};
    let mut seed = Sha256::new();
    seed.update(password.as_bytes());
    seed.update(layer.to_le_bytes());
    seed.update(salt);
    if let Some(prev) = prev_layer_hash {
        seed.update(prev);
    }
    let base = seed.finalize();

    let mut out = [0u64; 12];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut h = Sha256::new();
        h.update(base);
        h.update((i as u64).to_le_bytes());
        let d = h.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&d[..8]);
        *slot = u64::from_le_bytes(bytes) | 1;
    }

    out[0] ^= 0x243f6a8885a308d3;
    out[1] ^= 0x13198a2e03707344;
    out[2] ^= 0xa4093822299f31d0;
    out[3] ^= 0x082efa98ec4e6c89;
    out[4] ^= 0x452821e638d01377;
    out[5] ^= 0xbe5466cf34e90c6c;
    out[6] ^= 0xc0ac29b7c97c50dd;
    out[7] ^= 0x3f84d5b5b5470917;
    out[8] ^= 0x9216d5d98979fb1b;
    out[9] ^= 0xd1310ba698dfb5ac;
    out[10] ^= 0x2ffd72dbd01adfb7;
    out[11] ^= 0xb8e1afed6a267e96;
    out
}

fn chaotic_sequence_to_prk(sequence: &[u64], password: &str, salt: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut chaotic_bytes = Vec::with_capacity(sequence.len() * 8);
    for &v in sequence {
        chaotic_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut combined = chaotic_bytes;
    combined.extend_from_slice(salt);
    combined.extend_from_slice(password.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&combined);
    hasher.finalize().to_vec()
}

pub fn generate_chaotic_key_hkdf(
    chaotic_sequence: &[u64],
    password: &str,
    salt: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let prk = chaotic_sequence_to_prk(chaotic_sequence, password, salt);
    crypto::hkdf_expand(&prk, b"kaotik-key", length, Some(salt))
}

/// Hibrit kaotik dizi: tam sayı tabanlı 6 farklı durum geçişinin çapraz bağlanmış birleşimi.
fn generate_hybrid_sequence(
    password: &str,
    salt: &[u8],
    layer: u32,
    length: usize,
    prev_layer_hash: Option<&[u8; 32]>,
) -> Vec<u64> {
    let p = derive_extended_params(password, salt, layer, prev_layer_hash);
    let mut out = Vec::with_capacity(length);

    let mut seed = p[0] ^ p[5].rotate_left(7) ^ p[11].rotate_right(9);
    let mut x_log = splitmix64(&mut seed);
    let mut hx = splitmix64(&mut seed);
    let mut hy = splitmix64(&mut seed);
    let mut lx = splitmix64(&mut seed);
    let mut ly = splitmix64(&mut seed);
    let mut lz = splitmix64(&mut seed);
    let mut rx = splitmix64(&mut seed);
    let mut ry = splitmix64(&mut seed);
    let mut rz = splitmix64(&mut seed);
    let mut x_tent = splitmix64(&mut seed);
    let mut x_cubic = splitmix64(&mut seed);

    for _ in 0..WARMUP_ROUNDS {
        x_log = logistic_step(x_log, p[1]);
        (hx, hy) = henon_step(hx, hy, p[2], p[3]);
        (lx, ly, lz) = lorenz_mix(lx, ly, lz, p[4], p[5], p[6]);
        (rx, ry, rz) = rossler_mix(rx, ry, rz, p[7], p[8], p[9]);
        x_tent = tent_step(x_tent, p[10]);
        x_cubic = cubic_step(x_cubic, p[11]);
        seed ^= x_log ^ hx ^ hy ^ lx ^ ly ^ lz ^ rx ^ ry ^ rz ^ x_tent ^ x_cubic;
        let _ = splitmix64(&mut seed);
    }

    for _ in 0..length {
        for _ in 0..INNER_ROUNDS {
            x_log = logistic_step(x_log ^ seed, p[1]);
            (hx, hy) = henon_step(hx ^ x_log, hy ^ seed, p[2], p[3]);
            (lx, ly, lz) = lorenz_mix(lx ^ hy, ly ^ hx, lz ^ x_log, p[4], p[5], p[6]);
            (rx, ry, rz) = rossler_mix(rx ^ ly, ry ^ lz, rz ^ lx, p[7], p[8], p[9]);
            x_tent = tent_step(x_tent ^ rz, p[10]);
            x_cubic = cubic_step(x_cubic ^ rx, p[11]);
            seed ^= x_log
                .wrapping_add(hx)
                .wrapping_add(hy)
                .wrapping_add(lx)
                .wrapping_add(ly)
                .wrapping_add(lz)
                .wrapping_add(rx)
                .wrapping_add(ry)
                .wrapping_add(rz)
                .wrapping_add(x_tent)
                .wrapping_add(x_cubic);
            let _ = splitmix64(&mut seed);
        }
        let mut mixed = x_log
            ^ hx
            ^ hy
            ^ lx
            ^ ly
            ^ lz
            ^ rx
            ^ ry
            ^ rz
            ^ x_tent
            ^ x_cubic
            ^ seed;
        mixed ^= mixed.rotate_left((p[0] as u32 & 31) + 1);
        mixed = splitmix64(&mut mixed);
        out.push(mixed);
        seed ^= mixed;
    }

    out
}

/// S-box (256 byte) kaotik orbit ile türetilir: sbox[i] = permütasyon(i)
fn chaos_sbox(
    sequence: &[u64],
    password: &str,
    salt: &[u8],
    layer: u32,
    prev_layer_hash: Option<&[u8; 32]>,
) -> [u8; 256] {
    let mut idx_val: Vec<(u64, u8)> = (0..256).map(|i| (0_u64, i as u8)).collect();
    let p = derive_extended_params(password, salt, layer, prev_layer_hash);
    let seq_seed = if sequence.is_empty() { 0 } else { sequence[0] };
    let mut seed = p[0] ^ p[1] ^ seq_seed ^ ((layer as u64) << 48);

    for (i, entry) in idx_val.iter_mut().enumerate() {
        let seq_mix = if sequence.is_empty() {
            (i as u64).wrapping_mul(0x9e3779b97f4a7c15)
        } else {
            sequence[i % sequence.len()]
        };
        seed ^= seq_mix.rotate_left((p[2] as u32 & 31) + 1);
        let key = splitmix64(&mut seed) ^ p[i % p.len()];
        entry.0 = key;
    }

    idx_val.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut sbox = [0u8; 256];
    for (i, &(_, b)) in idx_val.iter().enumerate() {
        sbox[i] = b;
    }
    sbox
}

fn inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (i, &b) in sbox.iter().enumerate() {
        inv[b as usize] = i as u8;
    }
    inv
}

/// Permütasyon indeksi: chaos dizisinden deterministik shuffle
fn chaos_permutation(sequence: &[u64], length: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..length).collect();
    for i in (1..length).rev() {
        let sample = if sequence.is_empty() {
            (i as u64).wrapping_mul(0x9e3779b97f4a7c15)
        } else {
            sequence[i % sequence.len()]
        };
        let j = (sample as usize) % (i + 1);
        perm.swap(i, j);
    }
    perm
}

fn apply_permutation(data: &mut [u8], perm: &[usize]) {
    let n = data.len();
    let mut out = vec![0u8; n];
    for i in 0..n {
        out[perm[i]] = data[i];
    }
    data.copy_from_slice(&out);
}

fn apply_permutation_inv(data: &mut [u8], perm: &[usize]) {
    let n = data.len();
    let mut out = vec![0u8; n];
    for i in 0..n {
        out[i] = data[perm[i]];
    }
    data.copy_from_slice(&out);
}

/// Katman zinciri: her katmanın seq hash'i bir sonrakine prev olarak verilir (deterministik).
fn layer_hashes(password: &str, salt: &[u8], length: usize) -> [[u8; 32]; 9] {
    use sha2::{Digest, Sha256};
    let mut hashes = [[0u8; 32]; 9];
    for layer in 1..=LAYERS {
        let prev = if layer == 1 {
            None
        } else {
            Some(&hashes[(layer - 1) as usize])
        };
        let seq = generate_hybrid_sequence(password, salt, layer, length, prev);
        let mut hasher = Sha256::new();
        for &v in &seq {
            hasher.update(v.to_le_bytes());
        }
        hashes[layer as usize] = hasher.finalize().into();
    }
    hashes
}

pub fn apply_chaotic_xor_layers(data: &mut [u8], password: &str, salt: &[u8]) -> Result<()> {
    let hashes = layer_hashes(password, salt, data.len());
    for layer in 1..=LAYERS {
        let prev = if layer == 1 {
            None
        } else {
            Some(&hashes[(layer - 1) as usize])
        };
        let seq = generate_hybrid_sequence(password, salt, layer, data.len(), prev);
        let mut key = generate_chaotic_key_hkdf(&seq, password, salt, data.len())?;
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key[i];
        }
        crypto::secure_zero(key.as_mut_slice());

        let perm = chaos_permutation(&seq, data.len());
        apply_permutation(data, &perm);

        let sbox = chaos_sbox(&seq, password, salt, layer, prev);
        for byte in data.iter_mut() {
            *byte = sbox[*byte as usize];
        }
    }
    Ok(())
}

pub fn reverse_chaotic_xor_layers(data: &mut [u8], password: &str, salt: &[u8]) -> Result<()> {
    let hashes = layer_hashes(password, salt, data.len());
    for layer in (1..=LAYERS).rev() {
        let prev = if layer == 1 {
            None
        } else {
            Some(&hashes[(layer - 1) as usize])
        };
        let seq = generate_hybrid_sequence(password, salt, layer, data.len(), prev);
        let sbox = chaos_sbox(&seq, password, salt, layer, prev);
        let inv = inv_sbox(&sbox);
        for byte in data.iter_mut() {
            *byte = inv[*byte as usize];
        }

        let perm = chaos_permutation(&seq, data.len());
        apply_permutation_inv(data, &perm);

        let mut key = generate_chaotic_key_hkdf(&seq, password, salt, data.len())?;
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key[i];
        }
        crypto::secure_zero(key.as_mut_slice());
    }
    Ok(())
}
