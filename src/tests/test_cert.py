"""RedHawk — HTTPS 证书管理测试。"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# 隔离证书目录
os.environ["REDHAWK_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from redhawk.certgen import (
    _load_or_create_ca,
    cert_dir,
    get_ca_paths,
    get_ca_pem,
    get_site_cert,
)


def test_ca_created():
    cert, key, crt_path, key_path = _load_or_create_ca()
    assert crt_path.exists()
    assert key_path.exists()
    assert "RedHawk MITM CA" in cert.subject.rfc4514_string()
    # CA 必须标记为 CA
    assert cert.extensions.get_extension_for_class(__import__("cryptography").x509.BasicConstraints).value.ca


def test_ca_reused_not_regenerated():
    """重复调用应加载同一 CA（不重新生成）。"""
    _, _, crt1, _ = _load_or_create_ca()
    _, _, crt2, _ = _load_or_create_ca()
    assert crt1.read_bytes() == crt2.read_bytes()


def test_site_cert_signed_by_ca():
    crt_path, key_path = get_site_cert("www.example.com")
    assert crt_path.exists() and key_path.exists()
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    # 由我们的 CA 签发
    assert "RedHawk MITM CA" in cert.issuer.rfc4514_string()
    # SAN 包含域名（get_values_for_type 直接返回字符串值）
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = san.get_values_for_type(x509.DNSName)
    assert "www.example.com" in dns_names


def test_site_cert_ip():
    crt_path, _ = get_site_cert("127.0.0.1")
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ip_names = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    assert "127.0.0.1" in ip_names


def test_site_cert_cached():
    """同一域名再次获取应命中缓存（文件相同）。"""
    c1, _ = get_site_cert("api.test.dev")
    c2, _ = get_site_cert("api.test.dev")
    assert c1 == c2


def test_get_ca_pem():
    pem = get_ca_pem()
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    paths = get_ca_paths()
    assert paths["exists"] is True


def test_is_ca_installed_returns_bool():
    """检查函数不抛异常且返回 bool（本机可能装或没装）。"""
    from redhawk.certgen import is_ca_installed
    result = is_ca_installed()
    assert isinstance(result, bool)
