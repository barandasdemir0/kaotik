# Kaotik — WebAssembly / JavaScript

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --lib --target wasm32-unknown-unknown --features wasm
wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/kaotik.wasm
# Node için: --target nodejs
```

```js
import init, * as k from "./pkg/kaotik.js";
await init();

// Simetrik
const key = k.generateKey();
const ct = k.seal(key, new TextEncoder().encode("merhaba"), new Uint8Array());
k.open(key, ct, new Uint8Array());

// Sohbet (Double Ratchet)
const alice = k.signKeypair(), bob = k.signKeypair();
const pre = k.prekeyBundle(bob.secret);                 // pre.public → sunucuya
const a = k.RatchetSession.initiate(alice.secret, pre.public);
const b = k.RatchetSession.respond(bob.secret, pre.secret, a.handshake);
// b.handshake === alice.public olmalı (kişi doğrulaması)
const msg = a.encrypt(new TextEncoder().encode("selam"), new Uint8Array());
b.decrypt(msg, new Uint8Array());
const saved = b.export(storageKey);                     // IndexedDB'ye yazın
```

Not: Eski Kyber-768 dosya modu (C kodu) wasm'da yoktur; yeni API'nin tamamı vardır.
Tarayıcıda parola hash'i (`hashPassword`) 64 MiB bellek kullanır.
