# unicrack – Swiss-army-knife for JWT Research & Exploitation

`unicrack` is a comprehensive tool for JWT (JSON Web Token) security testing, supporting numerous research and exploitation techniques.  
It includes support for passive decoding, brute-force attacks, signature confusion, header manipulations, nested JWT attacks, and more.

## 🔧 Features

- Decode JWTs with pretty-print output
- HS256/384/512 secret brute-force (CPU/GPU via hashcat)
- Key confusion attacks (RS→HS)
- Header forgery (`alg: none`, `crit`, `kid`, `jku`, etc.)
- JWKS server simulation
- Duplicate claims and invalid claim names
- Nested JWT forging
- Audience and issuer bypass
- Signature re-signing with EdDSA / ES256K
- Various advanced attack vectors (zip deflation, replay, typoclaims, etc.)

## 📦 Requirements

- Python 3.7+
- PyJWT >= 2.7
- Typer
- Cryptography
- Rich
- Colorama
- Optional: [Hashcat](https://hashcat.net/hashcat/) for GPU-based cracking (only for HS256)

## 🚀 Installation

```bash
git clone https://github.com/UniShotProject/UniCrack.git
cd unicrack
pip install -r requirements.txt
```

## 🧪 Usage Examples

### Decode a JWT:

```bash
python3 unicrack.py decode -t <jwt_token>
```

### Brute-force a JWT with HS256 algorithm:

```bash
python3 unicrack.py crack -t <jwt_token> -w wordlist.txt --active
```

### Forge a JWT with `alg=none`:

```bash
python3 unicrack.py none -t <jwt_token> --active
```

_Use `--help` after each command for details._

## ⚠️ Legal Notice

This tool is intended for **educational and authorized penetration testing** purposes only.  
Using it on systems without permission is illegal and unethical.

## 👤 Author : Mon3m


- [LinkedIn](https://www.linkedin.com/in/mohamed-abd-el-moneam-162933315)

## 📄 License

MIT License
