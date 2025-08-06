# encryptiontool

Disclaimer: This is a hobby project. It has not been audited for security issues. If you find any, please let me know!

File encryption tool made with Botan, Qt and libargon2. Essentially a Qt frontend for some Botan ciphers and libargon2. 

Features: A variety of ciphers and modes of operation. Customizable Argon2 parameters. Customizable cipher chain. 

Supported ciphers: AES, ChaCha20, Blowfish, IDEA, Camellia, SM4, Kuznyechik, Serpent, Twofish, Threefish-512, SHACAL2

Supported authenticated modes: GCM (for AES), Poly1305 (for ChaCha20), OCB, EAX, SIV, CCM

Supported unauthenticated modes: CBC, CTR, CFB, OFB. Authenticated with HMAC-SHA256

Supported PBKDFs: Argon2id, Argon2d, Argon2i, PBKDF2, Scrypt

bugs: Chaining some modes and ciphers may cause crashes.

![Screenshot_20250705_234309](https://github.com/user-attachments/assets/ab9e5620-7c0e-4655-af27-e67c362f2ade)
