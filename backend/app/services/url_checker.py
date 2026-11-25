"""
PhishGuard AI - Live URL Existence & Reachability Checker
Checks whether a normalized URL/domain exists via DNS resolution and a lightweight
HTTP/HTTPS probe without blocking the async event loop or crashing offline.
"""

import asyncio
import errno
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from app.utils.url_validator import is_valid_ip


def _probe_http(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Performs a lightweight HTTP HEAD (falling back to ranged GET) request.
    Executed inside a worker thread via asyncio.to_thread.
    """
    headers = {
        "User-Agent": "PhishGuard-AI-Scanner/1.0 (+https://localhost)",
        "Accept": "*/*",
    }

    def _attempt(method: str, verify_ssl: bool = True) -> Dict[str, Any]:
        req = urllib.request.Request(url, method=method, headers=headers)
        if method == "GET":
            req.add_header("Range", "bytes=0-0")

        context = None
        if url.lower().startswith("https://"):
            context = (
                ssl.create_default_context()
                if verify_ssl
                else ssl._create_unverified_context()
            )

        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {
                "http_status": getattr(resp, "status", resp.getcode()),
                "final_url": resp.geturl(),
                "response_time_ms": elapsed_ms,
                "ssl_error": not verify_ssl,
            }

    try:
        return _attempt("HEAD", verify_ssl=True)
    except urllib.error.HTTPError as http_err:
        if http_err.code in (405, 501):
            try:
                return _attempt("GET", verify_ssl=True)
            except urllib.error.HTTPError as get_err:
                return {
                    "http_status": get_err.code,
                    "final_url": get_err.geturl(),
                    "response_time_ms": None,
                    "ssl_error": False,
                }
        return {
            "http_status": http_err.code,
            "final_url": http_err.geturl(),
            "response_time_ms": None,
            "ssl_error": False,
        }
    except urllib.error.URLError as url_err:
        if isinstance(url_err.reason, ssl.SSLError):
            try:
                res = _attempt("HEAD", verify_ssl=False)
                res["ssl_error"] = True
                return res
            except urllib.error.HTTPError as http_err:
                return {
                    "http_status": http_err.code,
                    "final_url": http_err.geturl(),
                    "response_time_ms": None,
                    "ssl_error": True,
                }
            except Exception:
                return {"error": f"SSL handshake failed: {url_err.reason}", "ssl_error": True}
        return {"error": str(url_err.reason)}
    except Exception as exc:
        return {"error": str(exc)}


async def _is_dns_online(loop: asyncio.AbstractEventLoop, timeout: float = 1.5) -> bool:
    """
    Verifies whether outbound DNS is functional in this runtime by resolving
    a known public reference domain. Distinguishes sandbox/offline environments
    from genuine NXDOMAIN responses.
    """
    for ref_domain in ("example.com", "google.com"):
        try:
            await asyncio.wait_for(
                loop.getaddrinfo(ref_domain, None, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            return True
        except Exception:
            continue
    return False


async def check_url_existence(
    normalized_url: str, domain: str, timeout: float = 2.5
) -> Dict[str, Any]:
    """
    Verifies whether the target domain resolves in DNS and responds over HTTP/HTTPS.
    Never raises exceptions; returns a structured status dictionary.
    """
    is_ip = is_valid_ip(domain)
    dns_resolved = is_ip
    resolved_ip: Optional[str] = domain if is_ip else None

    if not is_ip:
        loop = asyncio.get_running_loop()
        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            if addr_info:
                dns_resolved = True
                resolved_ip = addr_info[0][4][0]
        except asyncio.TimeoutError:
            return {
                "exists": None,
                "dns_resolved": False,
                "http_status": None,
                "resolved_ip": None,
                "final_url": None,
                "response_time_ms": None,
                "status": "Check Timed Out",
                "detail": f"DNS lookup for '{domain}' timed out after {timeout:.1f}s.",
            }
        except socket.gaierror:
            dns_online = await _is_dns_online(loop)
            if not dns_online:
                return {
                    "exists": None,
                    "dns_resolved": False,
                    "http_status": None,
                    "resolved_ip": None,
                    "final_url": None,
                    "response_time_ms": None,
                    "status": "Check Unavailable (Offline / Network Restricted)",
                    "detail": "Outbound DNS/network access is unavailable in the current runtime environment.",
                }
            return {
                "exists": False,
                "dns_resolved": False,
                "http_status": None,
                "resolved_ip": None,
                "final_url": None,
                "response_time_ms": None,
                "status": "Does Not Exist (Domain Not Found)",
                "detail": f"Live DNS lookup failed for '{domain}'. The domain appears unregistered or non-existent.",
            }
        except OSError as os_err:
            if os_err.errno in (errno.EPERM, errno.EACCES, errno.ENETUNREACH, errno.EHOSTUNREACH):
                return {
                    "exists": None,
                    "dns_resolved": False,
                    "http_status": None,
                    "resolved_ip": None,
                    "final_url": None,
                    "response_time_ms": None,
                    "status": "Check Unavailable (Network Restricted)",
                    "detail": "Outbound DNS/network access is restricted in the current runtime environment.",
                }
            return {
                "exists": False,
                "dns_resolved": False,
                "http_status": None,
                "resolved_ip": None,
                "final_url": None,
                "response_time_ms": None,
                "status": "Does Not Exist (Unresolvable)",
                "detail": f"Could not resolve '{domain}': {os_err}",
            }

    probe = await asyncio.to_thread(_probe_http, normalized_url, timeout)
    http_status = probe.get("http_status")
    final_url = probe.get("final_url")
    response_time_ms = probe.get("response_time_ms")
    ssl_error = probe.get("ssl_error", False)

    if http_status is not None:
        if 200 <= http_status < 400:
            ssl_note = " (with untrusted/invalid SSL certificate)" if ssl_error else ""
            return {
                "exists": True,
                "dns_resolved": dns_resolved,
                "http_status": http_status,
                "resolved_ip": resolved_ip,
                "final_url": final_url,
                "response_time_ms": response_time_ms,
                "ssl_error": ssl_error,
                "status": "Exists (Reachable)" if not ssl_error else "Exists (Invalid SSL Certificate)",
                "detail": f"URL is live and responded with HTTP {http_status}{ssl_note}.",
            }
        if http_status in (401, 403, 429):
            return {
                "exists": True,
                "dns_resolved": dns_resolved,
                "http_status": http_status,
                "resolved_ip": resolved_ip,
                "final_url": final_url,
                "response_time_ms": response_time_ms,
                "status": "Exists (Access Restricted)",
                "detail": f"Host is online and returned HTTP {http_status} (authentication or bot protection active).",
            }
        if http_status in (404, 410):
            return {
                "exists": False,
                "dns_resolved": dns_resolved,
                "http_status": http_status,
                "resolved_ip": resolved_ip,
                "final_url": final_url,
                "response_time_ms": response_time_ms,
                "status": f"Domain Exists, Page Not Found (HTTP {http_status})",
                "detail": f"Host '{domain}' resolved ({resolved_ip}), but this specific URL returned HTTP {http_status}.",
            }
        return {
            "exists": True,
            "dns_resolved": dns_resolved,
            "http_status": http_status,
            "resolved_ip": resolved_ip,
            "final_url": final_url,
            "response_time_ms": response_time_ms,
            "status": f"Exists (HTTP {http_status})",
            "detail": f"Server responded with HTTP status {http_status}.",
        }

    return {
        "exists": None if not is_ip else False,
        "dns_resolved": dns_resolved,
        "http_status": None,
        "resolved_ip": resolved_ip,
        "final_url": None,
        "response_time_ms": None,
        "status": "Domain Exists (HTTP Unreachable)",
        "detail": (
            f"Domain '{domain}' resolved to {resolved_ip}, but HTTP connection failed: "
            f"{probe.get('error', 'connection refused or timed out')}."
        ),
    }
