//! dudect tarzı sabit-zaman kontrolü (Reparaz–Balasch–Verbauwhede, 2017).
//!
//! İki girdi sınıfı rastgele sırayla ölçülür; Welch t-istatistiği |t| > 4.5 ise
//! "zamanlama sızıntısı olası" denir. Çalıştırma:
//!     cargo run --release --example ct_check [ölçüm_sayısı]
//! Not: Bu istatistiksel bir duman testidir, kanıt değildir; gürültülü makinelerde tekrarlayın.
use kaotik::hybrid::{self, HybridKemSecretKey, HybridSigningKey};
use std::hint::black_box;
use std::time::Instant;

#[derive(Default)]
struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    fn push(&mut self, class: usize, x: f64) {
        self.n[class] += 1.0;
        let d = x - self.mean[class];
        self.mean[class] += d / self.n[class];
        self.m2[class] += d * (x - self.mean[class]);
    }
    fn t(&self) -> f64 {
        let v0 = self.m2[0] / (self.n[0] - 1.0);
        let v1 = self.m2[1] / (self.n[1] - 1.0);
        (self.mean[0] - self.mean[1]) / (v0 / self.n[0] + v1 / self.n[1]).sqrt()
    }
}

fn rand_bit() -> usize {
    let mut b = [0u8; 1];
    getrandom::getrandom(&mut b).unwrap();
    (b[0] & 1) as usize
}

/// Ölçümlerin üst %10'unu (kesintiler) atarak t-istatistiği hesaplar.
fn run(name: &str, n: usize, mut f: impl FnMut(usize)) -> f64 {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let c = rand_bit();
        let t0 = Instant::now();
        f(c);
        samples.push((c, t0.elapsed().as_nanos() as f64));
    }
    let mut sorted: Vec<f64> = samples.iter().map(|s| s.1).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let cutoff = sorted[(sorted.len() as f64 * 0.9) as usize];
    let mut w = Welch::default();
    for (c, x) in samples.into_iter().filter(|s| s.1 <= cutoff) {
        w.push(c, x);
    }
    let t = w.t();
    let verdict = if t.abs() > 4.5 { "SIZINTI OLASI" } else { "ok" };
    println!("{name:<44} |t| = {:>6.2}  {verdict}", t.abs());
    t
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20_000);
    println!("ölçüm/sınıf ≈ {}\n", n / 2);

    let key = hybrid::generate_key().unwrap();
    let ct = hybrid::seal(&key, &[0u8; 256], b"").unwrap();
    let mut bad_first = ct.clone();
    bad_first[30] ^= 1;
    let mut bad_last = ct.clone();
    let l = bad_last.len() - 1;
    bad_last[l] ^= 1;
    run("open: bozuk ilk bayt vs bozuk son bayt", n, |c| {
        let m = if c == 0 { &bad_first } else { &bad_last };
        let _ = black_box(hybrid::open(&key, black_box(m), b""));
    });

    let sk = HybridKemSecretKey::generate().unwrap();
    let (kct, _) = sk.public_key().encapsulate().unwrap();
    let mut kbad = kct.clone();
    kbad[500] ^= 1;
    run("KEM decapsulate: geçerli vs bozuk (ML-KEM)", n / 10, |c| {
        let m = if c == 0 { &kct } else { &kbad };
        let _ = black_box(sk.decapsulate(black_box(m)));
    });

    let sig_key = HybridSigningKey::generate().unwrap();
    let vk = sig_key.verifying_key();
    let sig = sig_key.sign(b"m", b"").unwrap();
    let mut sbad = sig.clone();
    sbad[3000] ^= 1;
    run("verify: geçerli vs bozuk ML-DSA imzası", n / 20, |c| {
        let s = if c == 0 { &sig } else { &sbad };
        black_box(vk.verify(b"m", b"", black_box(s)));
    });
    println!("\nNot: imza doğrulama girdisi açıktır; sızıntı orada gizli bilgi açığa çıkarmaz.");
}
