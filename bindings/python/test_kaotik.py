import kaotik

k = kaotik.generate_key()
c = kaotik.seal(k, b"merhaba", b"chat:1")
assert kaotik.open(k, c, b"chat:1") == b"merhaba"
try:
    kaotik.open(k, c, b"chat:2")
    raise SystemExit("aad not enforced")
except kaotik.KaotikError:
    pass
sk, pk = kaotik.kem_keypair()
assert kaotik.open_from(sk, kaotik.seal_to(pk, b"gizli")) == b"gizli"
ssk, spk = kaotik.sign_keypair()
s = kaotik.sign(ssk, b"m", b"ctx")
assert kaotik.verify(spk, b"m", s, b"ctx") and not kaotik.verify(spk, b"x", s, b"ctx")
h = kaotik.hash_password("parola")
assert kaotik.verify_password("parola", h) and not kaotik.verify_password("yanlis", h)
pw = "GucluParola16!xyz"
assert kaotik.decrypt_with_password(kaotik.encrypt_with_password(b"dosya", pw), pw) == b"dosya"
print("python binding OK")
