//! dudect tarzı ölçüm: iki girdi sınıfı (sabit / rastgele gizli veri), Welch t-testi.
//! |t| < 4.5 → tespit edilebilir zamanlama sızıntısı yok.
use std::hint::black_box;
use std::time::Instant;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn fill(&mut self, b: &mut [u8]) {
        b.iter_mut().for_each(|x| *x = self.next() as u8);
    }
}

#[inline(always)]
fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        _mm_lfence();
        let t = _rdtsc();
        _mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use std::sync::OnceLock;
        static T0: OnceLock<Instant> = OnceLock::new();
        T0.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}

#[derive(Default, Clone, Copy)]
struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}
impl Welch {
    fn push(&mut self, c: usize, x: f64) {
        self.n[c] += 1.0;
        let d = x - self.mean[c];
        self.mean[c] += d / self.n[c];
        self.m2[c] += d * (x - self.mean[c]);
    }
    fn t(&self) -> f64 {
        let v = |c: usize| self.m2[c] / (self.n[c] - 1.0);
        (self.mean[0] - self.mean[1]) / (v(0) / self.n[0] + v(1) / self.n[1]).sqrt()
    }
}

/// Girdiler ölçümden önce üretilir (dudect gibi), böylece hazırlık maliyeti ölçüme sızmaz.
/// Ham + yüzdelik kırpılmış testlerin en büyük |t|'si raporlanır.
fn run(name: &str, samples: usize, len: usize, fixed: &[u8], mut op: impl FnMut(&mut [u8])) {
    let mut rng = Rng(0x1234_5678);
    let mut classes = Vec::with_capacity(samples);
    let mut inputs = vec![0u8; samples * len];
    for inp in inputs.chunks_mut(len) {
        let c = (rng.next() & 1) as usize;
        if c == 0 { inp.copy_from_slice(fixed) } else { rng.fill(inp) }
        classes.push(c);
    }
    let mut meas: Vec<(usize, u64)> = Vec::with_capacity(samples);
    for (inp, &class) in inputs.chunks_mut(len).zip(&classes) {
        let t0 = ticks();
        op(inp);
        let t1 = ticks();
        meas.push((class, t1 - t0));
    }
    let mut sorted: Vec<u64> = meas.iter().map(|m| m.1).collect();
    sorted.sort_unstable();
    let mut best = (0.0f64, 1.0f64);
    for p in [1.0, 0.99, 0.95, 0.9, 0.8, 0.7, 0.5] {
        let cut = sorted[((sorted.len() - 1) as f64 * p) as usize];
        let mut w = Welch::default();
        meas.iter().filter(|m| m.1 <= cut).for_each(|m| w.push(m.0, m.1 as f64));
        let t = w.t().abs();
        if t > best.0 {
            best = (t, p);
        }
    }
    let verdict = if best.0 < 4.5 { "sızıntı yok" } else { "SIZINTI" };
    println!(
        "{name:<28} n={samples:>8}  max|t|={:>7.2} (kırpma {:.0}%)  {verdict}",
        best.0,
        best.1 * 100.0
    );
}

fn main() {
    let samples: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let key = [0x42u8; 32];

    // chaotic2::apply: anahtar sabit, gizli düz metin sabit (sıfır) vs rastgele.
    let n = 1024;
    run("chaotic2::apply (1 KiB)", samples / 10, n, &vec![0u8; n], |b| {
        kaotik::chaotic2::apply(black_box(b), &key, b"ct");
    });

    // crypto::ct_eq: gizli değer sabit (eşit) vs rastgele (çoğunlukla ilk baytta farklı).
    let secret = [0x5au8; 32];
    run("crypto::ct_eq (32 B)", samples, 32, &secret, |g| {
        black_box(kaotik::crypto::ct_eq(black_box(g), black_box(&secret)));
    });

    // Throughput (MB/s) of chaotic2::apply on 16 MiB.
    let mut big = vec![7u8; 16 << 20];
    let t = Instant::now();
    kaotik::chaotic2::apply(&mut big, &key, b"tp");
    let s = t.elapsed().as_secs_f64();
    println!("chaotic2::apply verim: {:.1} MB/s", 16.0 * 1.048_576 / s);
}
