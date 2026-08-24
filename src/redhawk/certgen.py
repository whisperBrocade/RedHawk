"""RedHawk — HTTPS 中间人证书管理。

生成自签 CA → 为每个访问的域名动态签发证书（缓存）→ 供代理做 TLS 中间人。
用户需将 CA 证书安装到系统"受信任的根证书颁发机构"，浏览器才会信任。

文件位置（固定，见 cert_dir()，与 REDHAWK_DB/CWD/_MEIPASS 无关）：
  %LOCALAPPDATA%\\RedHawk\\certs\\redhawk-ca.crt   CA 证书（安装到系统信任根）
  %LOCALAPPDATA%\\RedHawk\\certs\\redhawk-ca.key   CA 私钥（本机保存）
  %LOCALAPPDATA%\\RedHawk\\certs\\sites\\<host>.crt 每个域名的签发证书
可用环境变量 REDHAWK_CERT_DIR 覆盖证书目录（测试/定制）。
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CA_CN = "RedHawk MITM CA"
CA_VALID_DAYS = 3650  # 10 年
SITE_VALID_DAYS = 365


def cert_dir() -> Path:
    """CA 存储目录（固定位置，避免每次启动/换数据根就生成一张不同的 CA）。

    优先级：
      1) 显式 REDHAWK_CERT_DIR（测试/定制用，指向确切证书目录）
      2) 用户级固定目录（Windows: %LOCALAPPDATA%\\RedHawk\\certs；其他: ~/.redhawk/certs）

    关键：此目录与 REDHAWK_DB / 当前目录 / PyInstaller(_MEIPASS) 均无关，
    保证 CA 只生成一次，安装到系统信任根后长期有效，不再出现
    “浏览器信任的 CA 和代理实际签名的 CA 同名不同钥匙” 的 ERR_CERT_AUTHORITY_INVALID。
    """
    override = os.environ.get("REDHAWK_CERT_DIR", "")
    if override:
        d = Path(override)
    else:
        local = os.environ.get("LOCALAPPDATA", "")
        base = (Path(local) / "RedHawk") if local else (Path.home() / ".redhawk")
        d = base / "certs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_or_create_ca() -> tuple[Any, Any, Path, Path]:
    """加载已有 CA，不存在则生成。返回 (cert, key, crt_path, key_path)。"""
    d = cert_dir()
    sites_dir = d / "sites"
    d.mkdir(parents=True, exist_ok=True)
    sites_dir.mkdir(parents=True, exist_ok=True)
    crt_path = d / "redhawk-ca.crt"
    key_path = d / "redhawk-ca.key"

    if crt_path.exists() and key_path.exists():
        try:
            with open(crt_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            with open(key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            return cert, key, crt_path, key_path
        except Exception:
            pass

    # 生成新 CA
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert, key, crt_path, key_path


def _build_site_cert(host: str, ca_cert: Any, ca_key: Any, sites_dir: Path) -> Path:
    """为域名/主机签发证书，返回 crt 路径。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    sans: list[x509.GeneralName] = []
    try:
        ip = ipaddress.ip_address(host)
        sans.append(x509.IPAddress(ip))
    except ValueError:
        sans.append(x509.DNSName(host))
        sans.append(x509.DNSName(f"*.{host}"))  # 覆盖子域

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=SITE_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    crt_path = sites_dir / f"{host.replace('*', '_').replace(':', '_')}.crt"
    key_path = sites_dir / f"{host.replace('*', '_').replace(':', '_')}.key"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return crt_path


def get_site_cert(host: str) -> tuple[Path, Path]:
    """获取域名证书（缓存命中直接返回，否则签发）。返回 (crt, key)。"""
    ca_cert, ca_key, _, _ = _load_or_create_ca()
    sites_dir = cert_dir() / "sites"
    safe = host.replace("*", "_").replace(":", "_")
    crt_path = sites_dir / f"{safe}.crt"
    key_path = sites_dir / f"{safe}.key"
    if crt_path.exists() and key_path.exists():
        return crt_path, key_path
    crt_path = _build_site_cert(host, ca_cert, ca_key, sites_dir)
    return crt_path, key_path


def get_ca_paths() -> dict[str, Any]:
    """返回 CA 证书路径（供下载安装）。"""
    _, _, crt_path, _ = _load_or_create_ca()
    return {"crt": str(crt_path), "exists": crt_path.exists()}


def get_ca_pem() -> bytes:
    _, _, crt_path, _ = _load_or_create_ca()
    return crt_path.read_bytes()


def install_ca() -> dict:
    """一键安装 RedHawk CA 到系统"受信任的根证书颁发机构"。

    通过 PowerShell 提权（会弹 UAC 确认）。安装后浏览器即信任，可解密 HTTPS。
    """
    import subprocess

    _, _, crt_path, _ = _load_or_create_ca()
    ps_script = (
        f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2"
        f"('{crt_path}'); "
        f"$store = New-Object System.Security.Cryptography.X509Certificates.X509Store"
        f"('Root', 'LocalMachine'); "
        f"$store.Open('ReadWrite'); $store.Add($cert); $store.Close(); "
        f"Write-Output 'INSTALLED'"
    )
    try:
        # 提权运行（UAC 弹窗）
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=60,
        )
        if "INSTALLED" in proc.stdout:
            return {"ok": True, "msg": "CA 已安装到系统信任根，重启浏览器后 HTTPS 可解密"}
        err = (proc.stderr or proc.stdout or "").strip()
        return {"ok": False, "error": f"安装失败（可能已取消授权）: {err[:200]}"}
    except FileNotFoundError:
        return {"ok": False, "error": "PowerShell 不可用"}
    except Exception as e:
        return {"ok": False, "error": f"安装异常: {e}"}


def is_ca_installed() -> bool:
    """检查 CA 是否已在系统信任根（certutil 查询，可靠且无转义问题）。"""
    import subprocess
    try:
        r = subprocess.run(
            ["certutil", "-store", "Root", "RedHawk"],
            capture_output=True, text=True, timeout=30,
        )
        return "RedHawk MITM CA" in (r.stdout or "")
    except Exception:
        return False
