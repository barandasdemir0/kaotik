//! kaotik v8 kaos katmanı: zorlanmış Lorenz ODE'si, sabit noktalı RK4 ile entegre edilir.
//!
//! Sabit nokta biçimi: `i64` içinde Q23.40 (40 kesir biti, ±2^23 aralık). Çarpma `i128`
//! ara değerle yapılır; platformlar arası bit-bit aynı sonuç için kayan nokta hiç yok.
//!
//! ODE: dx/dt = σ(y−x) + ε·sin(z), dy/dt = x(ρ−z) − y, dz/dt = xy − βz.
//! Parametreler anahtardan: σ∈[9.5,10.5], ρ∈[27,30], β∈[8/3−0.1, 8/3+0.1], ε∈[0.5,1.5].
//!
//! Bu katman gizleme/çeşitlilik içindir; dosya biçiminin kriptografik güvenliği dıştaki
//! AEAD'den (AES-256-GCM + XChaCha20-Poly1305) gelir, buradan değil.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const FRAC: u32 = 40;
const ONE: i64 = 1 << FRAC;
const PI: i64 = 3_454_217_652_357;
const TWO_PI: i64 = 2 * PI;
const HALF_PI: i64 = PI / 2;
const LN2: i64 = 762_123_384_785;
/// Adım h = 2^-7; çarpma yerine kaydırma ile uygulanır.
const H_SHIFT: u32 = 7;
/// Çekiciye oturmak için atılan ilk adımlar.
const WARMUP: usize = 1000;

#[inline]
fn mul(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128) >> FRAC) as i64
}

/// Maclaurin sin; önce [-π, π], sonra [-π/2, π/2] aralığına indirgenir.
fn sin(x: i64) -> i64 {
    let mut r = x.rem_euclid(TWO_PI);
    if r > PI {
        r -= TWO_PI;
    }
    // sin(π−r) = sin(r): seri yakınsaması için |r| ≤ π/2'ye katla.
    if r > HALF_PI {
        r = PI - r;
    } else if r < -HALF_PI {
        r = -PI - r;
    }
    let r2 = mul(r, r);
    let (mut term, mut sum) = (r, r);
    for k in 1..12i64 {
        term = -mul(term, r2) / ((2 * k) * (2 * k + 1));
        sum += term;
    }
    sum
}

/// Maclaurin exp; x = k·ln2 + r indirgemesi, sonra 2^k kaydırması (|x| ≲ 15 için).
#[cfg_attr(not(test), allow(dead_code))]
fn exp(x: i64) -> i64 {
    let k = (x + LN2 / 2).div_euclid(LN2);
    let r = x - k * LN2;
    let (mut term, mut sum) = (ONE, ONE);
    for n in 1..16i64 {
        term = mul(term, r) / n;
        sum += term;
    }
    if k >= 0 {
        sum << k
    } else {
        sum >> -k
    }
}

struct Lorenz {
    s: [i64; 3],
    sigma: i64,
    rho: i64,
    beta: i64,
    eps: i64,
}

impl Lorenz {
    fn deriv(&self, [x, y, z]: [i64; 3]) -> [i64; 3] {
        [
            mul(self.sigma, y - x) + mul(self.eps, sin(z)),
            mul(x, self.rho - z) - y,
            mul(x, y) - mul(self.beta, z),
        ]
    }

    /// Klasik RK4: s += h/6 · (k1 + 2k2 + 2k3 + k4).
    fn step(&mut self) {
        let s = self.s;
        let add = |k: [i64; 3], sh: u32| [0, 1, 2].map(|i| s[i] + (k[i] >> sh));
        let k1 = self.deriv(s);
        let k2 = self.deriv(add(k1, H_SHIFT + 1));
        let k3 = self.deriv(add(k2, H_SHIFT + 1));
        let k4 = self.deriv(add(k3, H_SHIFT));
        for i in 0..3 {
            self.s[i] += (k1[i] + 2 * k2[i] + 2 * k3[i] + k4[i]) / (6 << H_SHIFT);
        }
    }

    /// Bir adımdan 8 bayt: x, y, z'nin düşük kesir bitleri döndürülüp karıştırılır.
    fn next_u64(&mut self) -> u64 {
        self.step();
        let [x, y, z] = self.s.map(|v| v as u64);
        let mut w = x ^ y.rotate_left(21) ^ z.rotate_left(43);
        // splitmix64 sonlandırıcı: ucuz doğrusal olmayan karıştırma, histogramı düzler.
        w = (w ^ (w >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        w = (w ^ (w >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        w ^ (w >> 31)
    }
}

/// [lo, lo+width) aralığına u64'ü eşler (Q40).
fn ranged(b: &[u8], lo: i64, width: i64) -> i64 {
    let u = u64::from_le_bytes(b.try_into().unwrap());
    lo + ((u as u128 * width as u128) >> 64) as i64
}

/// Kayan nokta yerine Q40 sabitleri derleme zamanında: q(a, b) = a/b.
const fn q(a: i64, b: i64) -> i64 {
    a * ONE / b
}

fn seed(key: &[u8; 32], salt: &[u8]) -> Lorenz {
    let mut okm = [0u8; 56];
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(b"kaotik-v8-chaos-ic", &mut okm)
        .expect("56 bayt HKDF sınırı içinde");
    let c = |i: usize| &okm[i * 8..i * 8 + 8];
    let mut l = Lorenz {
        s: [
            ranged(c(0), q(-10, 1), q(20, 1)),
            ranged(c(1), q(-10, 1), q(20, 1)),
            ranged(c(2), q(10, 1), q(20, 1)),
        ],
        sigma: ranged(c(3), q(19, 2), ONE),
        rho: ranged(c(4), q(27, 1), q(3, 1)),
        beta: ranged(c(5), q(77, 30), q(1, 5)),
        eps: ranged(c(6), q(1, 2), ONE),
    };
    okm.zeroize();
    for _ in 0..WARMUP {
        l.step();
    }
    l
}

/// Kaos akışıyla Fisher–Yates; anahtara bağlı bijektif S-kutusu.
fn sbox(l: &mut Lorenz) -> [u8; 256] {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    for i in (1..256).rev() {
        s.swap(i, (l.next_u64() % (i as u64 + 1)) as usize);
    }
    s
}

fn xor_stream(l: &mut Lorenz, data: &mut [u8]) {
    for chunk in data.chunks_mut(8) {
        for (d, k) in chunk.iter_mut().zip(l.next_u64().to_le_bytes()) {
            *d ^= k;
        }
    }
}

/// key: 32 bytes (an HKDF subkey). salt: arbitrary bytes. Transforms data in place.
pub fn apply(data: &mut [u8], key: &[u8; 32], salt: &[u8]) {
    let mut l = seed(key, salt);
    let s = sbox(&mut l);
    xor_stream(&mut l, data);
    for b in data.iter_mut() {
        *b = s[*b as usize];
    }
}

/// `apply`'ın tam tersi: ters S-kutusu, sonra aynı akışla XOR.
pub fn reverse(data: &mut [u8], key: &[u8; 32], salt: &[u8]) {
    let mut l = seed(key, salt);
    let s = sbox(&mut l);
    let mut inv = [0u8; 256];
    for (i, &v) in s.iter().enumerate() {
        inv[v as usize] = i as u8;
    }
    for b in data.iter_mut() {
        *b = inv[*b as usize];
    }
    xor_stream(&mut l, data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn f(v: i64) -> f64 {
        v as f64 / ONE as f64
    }
    fn to_q(v: f64) -> i64 {
        (v * ONE as f64) as i64
    }

    #[test]
    fn taylor_sin_exp_match_std() {
        for i in -2000..=2000 {
            let x = i as f64 * 0.0517;
            assert!((f(sin(to_q(x))) - x.sin()).abs() < 1e-9, "sin {x}");
        }
        for i in -1000..=1000 {
            let x = i as f64 * 0.01;
            let e = x.exp();
            assert!((f(exp(to_q(x))) - e).abs() / e.max(1.0) < 1e-9, "exp {x}");
        }
    }

    #[test]
    fn lorenz_bounded_and_sensitive() {
        let mut a = seed(&[7; 32], b"s");
        for _ in 0..100_000 {
            a.step();
            assert!(a.s.iter().all(|v| v.abs() < 100 * ONE));
        }
        let mut a = seed(&[7; 32], b"s");
        let mut b = Lorenz { s: a.s, ..a };
        b.s[0] += 1 << 10; // ≈ 1e-9; tek ulp kesme hatasında yutulur
        let mut max = 0;
        for _ in 0..5000 {
            a.step();
            b.step();
            max = max.max((a.s[0] - b.s[0]).abs());
        }
        assert!(max > ONE, "fark {}", f(max));
        let mut k2 = [7; 32];
        k2[0] ^= 1;
        let c = seed(&k2, b"s");
        let a = seed(&[7; 32], b"s");
        assert!((a.s[0] - c.s[0]).abs() > ONE / 100);
    }

    #[test]
    fn roundtrip() {
        for n in [0, 1, 31, 32, 33, 10_000] {
            let orig: Vec<u8> = (0..n).map(|i| (i * 31 % 251) as u8).collect();
            let mut d = orig.clone();
            apply(&mut d, &[3; 32], b"tuz");
            if n > 8 {
                assert_ne!(d, orig);
            }
            reverse(&mut d, &[3; 32], b"tuz");
            assert_eq!(d, orig);
        }
    }

    #[test]
    fn golden_vector() {
        let mut d: Vec<u8> = (0..1024).map(|i| i as u8).collect();
        apply(&mut d, &[0x42; 32], b"kaotik-golden");
        let hex: String = Sha256::digest(&d)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "2a77e77c49d2aa3af34274b65e90f50c9efc8b1349cc0f84fc522700e9d78e6b"
        );
    }

    #[test]
    fn keystream_chi_square() {
        let mut d = vec![0u8; 1 << 20];
        let mut l = seed(&[9; 32], b"chi");
        xor_stream(&mut l, &mut d);
        let mut h = [0u64; 256];
        d.iter().for_each(|&b| h[b as usize] += 1);
        let e = d.len() as f64 / 256.0;
        let chi: f64 = h.iter().map(|&c| (c as f64 - e).powi(2) / e).sum();
        assert!(chi < 400.0, "chi2 {chi}");
    }

    #[test]
    fn key_avalanche() {
        let mut a = vec![0u8; 4096];
        let mut b = a.clone();
        let mut k = [0x11; 32];
        apply(&mut a, &k, b"av");
        k[17] ^= 0x08;
        apply(&mut b, &k, b"av");
        let diff: u32 = a.iter().zip(&b).map(|(x, y)| (x ^ y).count_ones()).sum();
        let r = diff as f64 / (a.len() * 8) as f64;
        assert!((0.4..0.6).contains(&r), "oran {r}");
    }
}
