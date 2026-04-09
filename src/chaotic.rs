// Çok katmanlı kaotik sistem: Lojistik, Henon, Lorenz, Rössler, Tent, Cubic;
// çapraz bağlama, bayt permütasyonu, S-box. Analiz edilmesi son derece zor.
use crate::crypto;
use crate::error::Result;

const LAYERS: u32 = 8;
const LORENZ_DT: f64 = 0.01;
const LORENZ_ITER: usize = 50;
const ROSSLER_DT: f64 = 0.02;
const ROSSLER_ITER: usize = 30;

#[inline(always)]
fn wrap01(x: f64) -> f64 {
    let mut v = x % 1.0;
    if v < 0.0 {
        v += 1.0;
    }
    v
}

/// Önceki katman çıktısının hash'i (None = ilk katman). Avalanche etkisini artırır.
fn derive_extended_params(
    password: &str,
    salt: &[u8],
    layer: u32,
    prev_layer_hash: Option<&[u8; 32]>,
) -> [f64; 12] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&layer.to_le_bytes());
    hasher.update(salt);
    if let Some(prev) = prev_layer_hash {
        hasher.update(prev);
    }
    let h = hasher.finalize();
    let mut p = [0.0_f64; 12];
    for i in 0..12 {
        let j = i * 2;
        let v = u16::from_le_bytes([h[j % 32], h[(j + 1) % 32]]) as f64 / 65535.0;
        p[i] = v;
    }
    p[0] = 0.1 + p[0] * 0.8;
    p[1] = 3.5 + p[1];
    p[2] = 1.4 + p[2] * 0.1;
    p[3] = 0.3 + p[3] * 0.1;
    p[4] = 10.0 + p[4] * 5.0;
    p[5] = 28.0 + p[5] * 5.0;
    p[6] = 2.0 + p[6] * 2.0;
    p[7] = 0.1 + p[7] * 0.4;
    p[8] = 0.1 + p[8] * 0.4;
    p[9] = 14.0 + p[9] * 5.0;
    p[10] = 0.4 + p[10] * 0.2;
    p[11] = 2.5 + p[11] * 0.5;
    p
}

fn lorenz_step(x: &mut f64, y: &mut f64, z: &mut f64, sigma: f64, rho: f64, beta: f64) {
    let dx = sigma * (*y - *x);
    let dy = *x * (rho - *z) - *y;
    let dz = *x * *y - beta * *z;
    *x += LORENZ_DT * dx;
    *y += LORENZ_DT * dy;
    *z += LORENZ_DT * dz;
    // NaN/Inf koruması: kaotik dizi sapmasını önle
    if !x.is_finite() { *x = 0.1; }
    if !y.is_finite() { *y = 0.0; }
    if !z.is_finite() { *z = 0.0; }
}

fn rossler_step(x: &mut f64, y: &mut f64, z: &mut f64, a: f64, b: f64, c: f64) {
    let dx = -*y - *z;
    let dy = *x + a * *y;
    let dz = b + *z * (*x - c);
    *x += ROSSLER_DT * dx;
    *y += ROSSLER_DT * dy;
    *z += ROSSLER_DT * dz;
    // NaN/Inf koruması: kaotik dizi sapmasını önle
    if !x.is_finite() { *x = 0.1; }
    if !y.is_finite() { *y = 0.0; }
    if !z.is_finite() { *z = 0.0; }
}

fn tent_map(x: f64, mu: f64) -> f64 {
    // mu=0 veya mu=1 olursa sıfıra bölme; epsilon ile sınırla
    let mu = mu.clamp(1e-10, 1.0 - 1e-10);
    if x < mu {
        x / mu
    } else {
        (1.0 - x) / (1.0 - mu)
    }
}

fn cubic_map(x: f64, r: f64) -> f64 {
    r * x * (1.0 - x * x)
}

fn chaotic_sequence_to_prk(sequence: &[f64], password: &str, salt: &[u8]) -> Vec<u8> {
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
    chaotic_sequence: &[f64],
    password: &str,
    salt: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let prk = chaotic_sequence_to_prk(chaotic_sequence, password, salt);
    crypto::hkdf_expand(&prk, b"kaotik-key", length, Some(salt))
}

/// Hibrit kaotik dizi: Lojistik + Henon + Lorenz + Rössler + Tent + Cubic çapraz bağlamalı.
/// prev_layer_hash: önceki katman dizisinin SHA-256'ı (ilk katmanda None).
fn generate_hybrid_sequence(
    password: &str,
    salt: &[u8],
    layer: u32,
    length: usize,
    prev_layer_hash: Option<&[u8; 32]>,
) -> Vec<f64> {
    let p = derive_extended_params(password, salt, layer, prev_layer_hash);
    let (x0, r, a_henon, b_henon) = (p[0], p[1], p[2], p[3]);
    let (sigma, rho, beta) = (p[4], p[5], p[6]);
    let (a_r, b_r, c_r) = (p[7], p[8], p[9]);
    let (mu, r_cubic) = (p[10], p[11]);

    let mut out = Vec::with_capacity(length);
    let mut x_log = x0;
    let mut hx = x0;
    let mut hy = 0.0_f64;
    let mut lx = 0.1 + (x0 * 10.0) % 5.0;
    let mut ly = 0.0;
    let mut lz = 0.0;
    let mut rx = 0.1;
    let mut ry = 0.0;
    let mut rz = 0.0;
    let mut x_tent = wrap01(x0);
    let mut x_cubic = wrap01(x0 + 0.1);

    for _ in 0..1000 {
        x_log = r * x_log * (1.0 - x_log);
    }

    for _ in 0..length {
        for _ in 0..10 {
            x_log = r * x_log * (1.0 - x_log);
        }
        hx = x_log;
        let nhx = 1.0 - a_henon * hx * hx + hy;
        let nhy = b_henon * hx;
        hx = nhx;
        hy = nhy;

        for _ in 0..LORENZ_ITER {
            lorenz_step(&mut lx, &mut ly, &mut lz, sigma, rho, beta);
        }
        for _ in 0..ROSSLER_ITER {
            rossler_step(&mut rx, &mut ry, &mut rz, a_r, b_r, c_r);
        }
        x_tent = wrap01(tent_map(x_tent, mu));
        x_cubic = wrap01(cubic_map(x_cubic, r_cubic));

        let l_norm = wrap01((lx.abs() + ly.abs() + lz.abs()) / 50.0);
        let r_norm = wrap01((rx.abs() + ry.abs() + rz.abs()) / 20.0);
        // Ağırlıklar toplamı = 1.0 (6 harita eşit etki görmemeli ama normalize olmalı)
        let combined = wrap01(x_log) * (1.0 / 6.0)
            + wrap01(hx.abs()) * (1.0 / 6.0)
            + l_norm * (1.0 / 6.0)
            + r_norm * (1.0 / 6.0)
            + x_tent * (1.0 / 6.0)
            + x_cubic * (1.0 / 6.0);
        out.push(wrap01(combined));
    }
    out
}

/// S-box (256 byte) kaotik orbit ile türetilir: sbox[i] = permütasyon(i)
fn chaos_sbox(
    sequence: &[f64],
    password: &str,
    salt: &[u8],
    layer: u32,
    prev_layer_hash: Option<&[u8; 32]>,
) -> [u8; 256] {
    let mut idx_val: Vec<(f64, u8)> = (0..256).map(|i| (0.0_f64, i as u8)).collect();
    let p = derive_extended_params(password, salt, layer, prev_layer_hash);
    let mut x = p[0];
    for i in 0..256 {
        x = 3.9 * x * (1.0 - x);
        x = (x * 1.0 + p[1] * (1.0 - x)) % 1.0;
        if x < 0.0 {
            x += 1.0;
        }
        idx_val[i].0 = x;
    }
    // Sıralama deterministik: aynı f64 değerlerde indeks (a.1) ile ayır. Platformlar arası tutarlı S-box.
    idx_val.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.cmp(&b.1))
    });
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
fn chaos_permutation(sequence: &[f64], length: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..length).collect();
    for i in (1..length).rev() {
        let j = (sequence[i % sequence.len()] * (i + 1) as f64).floor() as usize % (i + 1);
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

fn inv_perm(perm: &[usize]) -> Vec<usize> {
    let n = perm.len();
    let mut inv = vec![0; n];
    for i in 0..n {
        inv[perm[i]] = i;
    }
    inv
}

fn apply_permutation_inv(data: &mut [u8], perm: &[usize]) {
    let inv = inv_perm(perm);
    let n = data.len();
    let mut out = vec![0u8; n];
    for i in 0..n {
        out[i] = data[inv[i]];
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
