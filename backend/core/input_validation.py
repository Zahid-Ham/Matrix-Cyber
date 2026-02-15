"""
Input Validation Utilities.

Provides functions to validate URLs, file paths, and other inputs
to prevent SSRF, Path Traversal, and Injection attacks against the scanner.
"""
import ipaddress
import socket
import os
from urllib.parse import urlparse
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Private IP ranges to block for SSRF protection
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"), # Loopback
    ipaddress.ip_network("10.0.0.0/8"),  # Private Class A
    ipaddress.ip_network("172.16.0.0/12"), # Private Class B
    ipaddress.ip_network("192.168.0.0/16"), # Private Class C
    ipaddress.ip_network("169.254.0.0/16"), # Link-local
    ipaddress.ip_network("::1/128"),     # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),    # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),   # IPv6 Link-local
]

BLACKLISTED_SCHEMES = {"file", "gopher", "ftp", "ldap", "dict"}


def is_safe_url(url: str, allow_internal: bool = False) -> bool:
    """
    Validate if a URL is safe to scan (SSRF protection).
    
    Args:
        url: The URL to check.
        allow_internal: If True, allows scanning internal IPs.
        
    Returns:
        True if safe, False otherwise.
    """
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme.lower() in BLACKLISTED_SCHEMES:
            logger.warning(f"Blocked URL scheme: {parsed.scheme}")
            return False
            
        if parsed.scheme.lower() not in ("http", "https"):
            # If no scheme, valid for some contexts, but let's be strict
            if not parsed.netloc:
                return False
        
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # If allow_internal is explicitly set, we skip IP checks
        if allow_internal:
            return True
            
        # Resolve hostname to IP
        try:
            # Note: This has a TOCTOU race condition if DNS changes between check and use
            # But it catches basic mistakes/malice
            ips = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            logger.warning(f"Could not resolve hostname: {hostname}")
            return False
            
        for info in ips:
            ip_str = info[4][0]
            ip = ipaddress.ip_address(ip_str)
            
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                logger.warning(f"Blocked internal IP: {ip} for {hostname}")
                return False

            # Check against specific private networks list for robustness (e.g. 0.0.0.0/8)
            for network in PRIVATE_NETWORKS:
                if ip in network:
                    logger.warning(f"Blocked restricted IP: {ip} for {hostname}")
                    return False
                        
        return True
        
    except Exception as e:
        logger.error(f"Error validating URL {url}: {e}")
        return False


def validate_file_path(path: str, base_dir: str = None) -> Path:
    """
    Validate that a file path is safe and strictly within the allowed directory.
    Prevents path traversal.
    
    Args:
        path: The file path to check.
        base_dir: The directory the file must reside in. Defaults to current working dir.
        
    Returns:
        Resolved Path object.
        
    Raises:
        ValueError: If path attempts traversal out of base_dir.
    """
    if base_dir is None:
        base_dir = os.getcwd()
        
    # Resolve absolute paths
    base = Path(base_dir).resolve()
    target = Path(path).resolve()
    
    # Check if target is relative to base
    try:
        target.relative_to(base)
    except ValueError:
        logger.warning(f"Path traversal attempt blocked: {path} is outside {base_dir}")
        raise ValueError(f"Path must be within {base_dir}")
        
    return target
