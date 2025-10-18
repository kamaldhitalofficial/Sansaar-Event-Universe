"""
Utility functions for device detection and IP address handling.
"""
import hashlib
from django.core.cache import cache
from django.contrib.auth import get_user_model
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    Get the client's IP address from the request.

    Args:
        request: Django request object

    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def get_device_fingerprint(ip_address, user_agent):
    """
    Generate a device fingerprint based on IP and user agent.

    Args:
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        str: Device fingerprint hash
    """
    # Create a simple fingerprint based on IP and user agent
    fingerprint_data = f"{ip_address}:{user_agent}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]


def detect_new_device(user, ip_address, user_agent):
    """
    Detect if this is a new device for the user.

    Args:
        user: User instance
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        bool: True if this is a new device
    """
    device_fingerprint = get_device_fingerprint(ip_address, user_agent)
    cache_key = f"known_device:{user.id}:{device_fingerprint}"

    # Check if we've seen this device before
    is_known_device = cache.get(cache_key, False)

    if not is_known_device:
        # Mark this device as known for future logins
        # Store for 90 days
        cache.set(cache_key, True, 60 * 60 * 24 * 90)
        return True

    return False


def is_suspicious_login(user, ip_address, user_agent):
    """
    Basic suspicious login detection.

    Args:
        user: User instance
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        tuple: (is_suspicious, reasons)
    """
    reasons = []

    # Check for rapid login attempts from different IPs
    recent_ips_key = f"recent_login_ips:{user.id}"
    recent_ips = cache.get(recent_ips_key, set())

    if len(recent_ips) > 3:  # More than 3 different IPs in recent time
        reasons.append("Multiple IP addresses")

    # Add current IP to recent IPs
    recent_ips.add(ip_address)
    cache.set(recent_ips_key, recent_ips, 3600)  # 1 hour

    # Check for suspicious user agents
    if not user_agent or len(user_agent) < 10:
        reasons.append("Suspicious user agent")

    # Check for known bot patterns
    bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
    if any(pattern in user_agent.lower() for pattern in bot_patterns):
        reasons.append("Bot-like user agent")

    return len(reasons) > 0, reasons


def get_geographic_info(ip_address):
    """
    Get basic geographic information for an IP address.
    This is a placeholder - in production, you'd use a service like MaxMind GeoIP.

    Args:
        ip_address: IP address to lookup

    Returns:
        dict: Geographic information
    """
    # Placeholder implementation
    # In production, integrate with a GeoIP service
    return {
        'country': 'Unknown',
        'city': 'Unknown'
    }


def log_security_event(user, event_type, details, ip_address=None):
    """
    Log a security-related event.

    Args:
        user: User instance
        event_type: Type of security event
        details: Event details
        ip_address: IP address if available
    """
    logger.warning(
        f"Security event - User: {user.email}, Type: {event_type}, "
        f"Details: {details}, IP: {ip_address}"
    )