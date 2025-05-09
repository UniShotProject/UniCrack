# unicrack - JWT Security Testing Tool (Pentesting Edition)

```
██╗   ██╗███╗   ██╗██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██║   ██║████╗  ██║██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██║   ██║██╔██╗ ██║██║██║     ██████╔╝███████║██║     █████╔╝ 
██║   ██║██║╚██╗██║██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
╚██████╔╝██║ ╚████║██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

**Version:** 3.1.0 

**Author:** Mon3m 

## Overview

**unicrack** is a comprehensive, Swiss-army-knife for JSON Web Token (JWT) research, security testing, and exploitation. This enhanced pentesting edition provides a wide array of tools for decoding, analyzing, forging, and attacking JWTs, making it an essential utility for security professionals and penetration testers.

![WhatsApp Image 2025-05-09 at 20 52 14_83efc955](https://github.com/user-attachments/assets/ea7e6d16-42f3-4d65-aa1a-7f6f645a1637)


## Features

*   **JWT Decoding & Analysis**: Pretty-print JWT headers, payloads, and signatures. Perform security analysis to identify common vulnerabilities (e.g., `alg:none`, weak algorithms, missing claims, long expiration).
*   **Website Scanning**: Scan websites for JWTs in headers, cookies, and response bodies, with an option to analyze found tokens.
*   **Token Forgery**: 
    *   `alg:none` attack.
    *   HMAC secret forging (HS256, HS384, HS512).
    *   Asymmetric key forging (RS/ES/PS) using provided key files.
*   **HS Secret Brute-Forcing**: 
    *   CPU-based brute-force for HS256, HS384, HS512 secrets using a wordlist.
    *   GPU-accelerated brute-force for HS256 via Hashcat integration.
*   **Common JWT Attacks**: 
    *   Key Confusion (RS/ES/PS → HS).
    *   JKU/X5U Injection with a built-in JWKS server (HTTP/HTTPS).
    *   Duplicate Claim Injection.
    *   Critical (`crit`) Header Injection.
    *   `kid` (Key ID) Header Attacks (e.g., Path Traversal - *details depend on specific `kid traversal` command logic*).
    *   Many other advanced attacks (see command list below).
*   **Key Generation**: Generate RSA, EC (P-256, P-384, P-521), and Ed25519 key pairs.
*   **JWKS Generation**: Generate JWKS (JSON Web Key Set) for `oct`, `RSA`, and `EC` key types, with proper parameters for EC keys (crv, x, y).
*   **Attack Session Management**: Tracks forged tokens and findings during a testing session.
*   **User-Friendly CLI**: Richly formatted output, progress bars, and clear command structure powered by Typer and Rich.
*   **Output Management**: Saves attack results and scan outputs to a timestamped file in the `unicrack_output` directory.

## Requirements

*   Python 3.7+ (Python 3.11 recommended as used in development environment)
*   **Core Libraries** (installable via pip):
    *   `PyJWT>=2.7`
    *   `Typer`
    *   `Rich`
    *   `colorama`
    *   `cryptography`
    *   `requests`
    *   `urllib3`
*   **Optional for GPU Cracking**:
    *   `hashcat` installed and in your system's PATH.

## Installation

1.  **Clone the repository or download `unicrack.py`**.

2.  **Install Python dependencies**:
    It is recommended to use a virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Ensure `unicrack.py` is executable** (if needed):
    ```bash
    chmod +x unicrack.py
    ```

## Usage

Run the tool using:

```bash
python3 unicrack.py [COMMAND] [OPTIONS]
# or if executable and in PATH
./unicrack.py [COMMAND] [OPTIONS]
```

**Important Note on Active Commands:**
Many commands that forge tokens, perform network attacks, or attempt to crack secrets are considered **ACTIVE**. These commands require the `--active` flag to be explicitly set. This is a safety measure to prevent accidental execution of potentially harmful operations.

```bash
python3 unicrack.py [ACTIVE_COMMAND] --active [OPTIONS]
```

### General Help

To see the main help message and list of commands:

```bash
python3 unicrack.py --help
```

To get help for a specific command:

```bash
python3 unicrack.py [COMMAND] --help
```

### Command Categories

As shown in the tool's help message:

*   **SAFE commands (read-only)**: `decode`, `scan`
*   **ACTIVE commands (forge / network / cracking)**: `none`, `crack`, `confuse`, `jku`, `duplicate`, `crit`, `sign`, `kid`, `traversal`, `jwkskey`, `jkuadv`, `nested`, `nestednone`, `weakkey`, `jwkrewrite`, `confuseadv`, `audbypass`, `issuer`, `critconfuse`, `typoclaim`, `jwemix`, `nbf`, `replay`, `algtypo`, `zipdef`, `nestmix`
*   **ADVANCED commands**: `proxy`, `bruteheaders`, `fuzz`, `report`

### Common Command Examples

1.  **Decode a JWT and Analyze it**:
    ```bash
    python3 unicrack.py decode -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" --analyze
    ```
    Output options: `--output table` (default), `json`, `raw`.

2.  **Scan a Website for JWTs**:
    ```bash
    python3 unicrack.py scan --url "https://example.com/api/login"
    # With custom cookies and headers, and save output
    python3 unicrack.py scan --url "https://example.com/api/data" -c "sessionid=abcdef" -H "X-API-Key: secretkey" --output-file
    ```

3.  **Crack an HS256 Secret (CPU)**:
    ```bash
    python3 unicrack.py crack -t "<HS256_TOKEN>" -w /path/to/wordlist.txt --active
    ```

4.  **Crack an HS256 Secret (GPU via Hashcat)**:
    ```bash
    python3 unicrack.py crack -t "<HS256_TOKEN>" -w /path/to/wordlist.txt --gpu --active
    ```

5.  **Forge an `alg:none` Token**:
    ```bash
    python3 unicrack.py none -t "<ORIGINAL_TOKEN>" --active
    ```
    The tool may prompt to test the forged token against a target URL if one was previously set (e.g., via the `scan` command).

6.  **Perform Key Confusion Attack (RS256 -> HS256)**:
    ```bash
    # Using an auto-generated public key
    python3 unicrack.py confuse -t "<RS256_TOKEN>" --active
    # Using a specific public key file
    python3 unicrack.py confuse -t "<RS256_TOKEN>" --pubkey /path/to/public.pem --active
    ```

7.  **JKU Injection Attack**:
    This command starts a local JWKS server.
    ```bash
    # Forge token with JKU header pointing to a local server serving an RSA key in JWKS
    python3 unicrack.py jku -t "<ORIGINAL_TOKEN>" --active --jwks-key-type RSA
    
    # Using HTTPS and a specific EC curve (e.g., P-384) for the JWKS key
    python3 unicrack.py jku -t "<ORIGINAL_TOKEN>" --active --https --jwks-key-type EC --jwks-ec-curve P-384 --bind 0.0.0.0
    ```
    The `--bind` option allows the JWKS server to be accessible on a specific IP address (e.g., `0.0.0.0` for all interfaces).

8.  **Sign a custom payload with a key file (e.g., RS256)**:
    *(Assuming the `sign` command takes payload as input and a key file)*
    ```bash
    # The exact options for 'sign' command should be checked with:
    # python3 unicrack.py sign --help
    # Example (hypothetical based on common JWT tool functionality):
    # python3 unicrack.py sign --payload '{"user":"admin","exp":1700000000}' --key /path/to/private.key --alg RS256 --active
    ```
  9.  **Edit and Re-sign JWTs with Known Secret**:
    The `edit` command is a powerful feature that allows you to modify and re-sign JWT tokens when you have the secret key.
  ```bash
  python3 unicrack.py edit -t "your_token" -s "your_secret" --claim "role=admin" --add "permissions=[\"admin_panel\",\"user_management\"]" --active
  ```

  ```bash
  python3 unicrack.py edit -t "your_token" -s "your_secret" --payload '{"sub":"admin","role":"admin","custom":"value"}' --active
   ```

  ```bash
  python3 unicrack.py edit -t "your_token" -s "your_secret" --payload-file custom_payload.json --active
   ```

    
  Please refer to `python3 unicrack.py [COMMAND] --help` for detailed options of each command.

## Output Directory

By default, any files generated by the tool (e.g., scan reports, attack details if saved) will be placed in a directory named `unicrack_output` in the current working directory.

## Attack Session

The tool maintains an `AttackSession` object in memory during its runtime. This session tracks:
*   The target URL (if set by commands like `scan`).
*   Custom headers and cookies for the target.
*   Original tokens and any tokens forged from them.
*   Security findings identified during the session.

This information can be valuable for correlating different attack steps and is intended to be used by the `report` command (details of which can be found via `python unicrack.py report --help`).

## Disclaimer

This tool is intended for educational purposes and for authorized security testing only. The author and contributors are not responsible for any misuse or damage caused by this tool. Always obtain explicit permission from the target system owner before conducting any security testing.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to open an issue or submit a pull request on the project's repository.

## 👤 Author : Mon3m


- [LinkedIn](https://www.linkedin.com/in/mohamed-abd-el-moneam-162933315)

## 📄 License

MIT License
