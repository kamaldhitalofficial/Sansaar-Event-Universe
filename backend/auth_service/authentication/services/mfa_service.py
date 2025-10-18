"""
Multi-Factor Authentication Service

This service handles TOTP generation, verification, backup codes,
and trusted device management for MFA functionality.
"""

import pyotp
import qrcode
import secrets
import string
import hashlib
from io import BytesIO
from base64 import b64encode
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache
from django.conf import settings
from ..models import MFADevice, MFABackupCode, TrustedDevice, User


class MFAService:
    """Service for handling Multi-Factor Authentication operations."""

    # Rate limiting settings
    MFA_ATTEMPT_LIMIT = 5
    MFA_LOCKOUT_DURATION = 15  # minutes
    MFA_RATE_LIMIT_KEY = "mfa_attempts_{user_id}"

    @staticmethod
    def generate_totp_secret():
        """Generate a new TOTP secret key."""
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(user_email, secret, issuer_name="Sansaar Event Universe"):
        """Generate TOTP URI for QR code generation."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer_name
        )

    @staticmethod
    def generate_qr_code(totp_uri):
        """Generate QR code image for TOTP setup."""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64 for API response
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_str}"

    @classmethod
    def setup_mfa_device(cls, user, device_name):
        """
        Set up a new MFA device for a user.
        Returns the device, TOTP URI, QR code, and backup codes.
        """
        # Check if user already has an active MFA device
        existing_device = MFADevice.objects.filter(
            user=user,
            is_active=True,
            is_verified=True
        ).first()

        if existing_device:
            raise ValueError("User already has an active MFA device")

        # Generate secret and create device
        secret = cls.generate_totp_secret()

        # Deactivate any existing unverified devices
        MFADevice.objects.filter(
            user=user,
            is_verified=False
        ).update(is_active=False)

        device = MFADevice.objects.create(
            user=user,
            device_name=device_name,
            secret_key=secret,
            is_active=True,
            is_verified=False
        )

        # Generate TOTP URI and QR code
        totp_uri = cls.get_totp_uri(user.email, secret)
        qr_code = cls.generate_qr_code(totp_uri)

        # Generate backup codes
        backup_codes = MFABackupCode.generate_codes_for_user(user)

        return {
            'device': device,
            'secret': secret,
            'totp_uri': totp_uri,
            'qr_code': qr_code,
            'backup_codes': backup_codes
        }

    @classmethod
    def verify_totp_code(cls, user, code, device_id=None):
        """
        Verify a TOTP code for a user.
        Returns True if valid, False otherwise.
        """
        # Check rate limiting
        if cls._is_rate_limited(user):
            raise ValueError("Too many failed MFA attempts. Please try again later.")

        # Get the user's MFA device
        if device_id:
            try:
                device = MFADevice.objects.get(
                    id=device_id,
                    user=user,
                    is_active=True
                )
            except MFADevice.DoesNotExist:
                cls._record_failed_attempt(user)
                return False
        else:
            device = MFADevice.objects.filter(
                user=user,
                is_active=True,
                is_verified=True
            ).first()

            if not device:
                return False

        # Check if device is locked
        if device.is_locked():
            raise ValueError("MFA device is temporarily locked due to failed attempts")

        # Verify TOTP code
        totp = pyotp.TOTP(device.secret_key)

        # Allow for time drift (check current and previous/next time windows)
        is_valid = totp.verify(code, valid_window=1)

        if is_valid:
            # Reset failed attempts on successful verification
            device.reset_failed_attempts()
            device.mark_as_used()
            cls._clear_rate_limit(user)

            # Mark device as verified if it wasn't already
            if not device.is_verified:
                device.verify_device()

            return True
        else:
            # Record failed attempt
            device.increment_failed_attempts()
            cls._record_failed_attempt(user)
            return False

    @classmethod
    def verify_backup_code(cls, user, code):
        """
        Verify a backup code for a user.
        Returns True if valid, False otherwise.
        """
        # Check rate limiting
        if cls._is_rate_limited(user):
            raise ValueError("Too many failed MFA attempts. Please try again later.")

        # Get unused backup codes for the user
        backup_codes = MFABackupCode.objects.filter(
            user=user,
            is_used=False
        )

        for backup_code in backup_codes:
            if check_password(code.upper(), backup_code.code_hash):
                backup_code.mark_as_used()
                cls._clear_rate_limit(user)
                return True

        # Record failed attempt
        cls._record_failed_attempt(user)
        return False

    @classmethod
    def disable_mfa(cls, user):
        """Disable MFA for a user by deactivating all devices and clearing backup codes."""
        # Deactivate all MFA devices
        MFADevice.objects.filter(user=user).update(is_active=False)

        # Clear unused backup codes
        MFABackupCode.objects.filter(user=user, is_used=False).delete()

        # Revoke all trusted devices
        TrustedDevice.objects.filter(user=user).update(is_active=False)

        return True

    @classmethod
    def regenerate_backup_codes(cls, user):
        """Regenerate backup codes for a user."""
        # Check if user has active MFA
        if not cls.user_has_active_mfa(user):
            raise ValueError("User does not have active MFA")

        # Generate new backup codes
        backup_codes = MFABackupCode.generate_codes_for_user(user)
        return backup_codes

    @classmethod
    def user_has_active_mfa(cls, user):
        """Check if user has active MFA enabled."""
        return MFADevice.objects.filter(
            user=user,
            is_active=True,
            is_verified=True
        ).exists()

    @classmethod
    def create_trusted_device(cls, user, request, remember_days=30):
        """
        Create a trusted device for MFA bypass.
        Returns the trusted device instance.
        """
        # Generate device fingerprint from request
        device_fingerprint = cls._generate_device_fingerprint(request)

        # Get device info
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ip_address = cls._get_client_ip(request)
        device_name = cls._generate_device_name(user_agent)

        # Create trusted device
        trusted_device = TrustedDevice.create_trusted_device(
            user=user,
            device_fingerprint=device_fingerprint,
            device_name=device_name,
            user_agent=user_agent,
            ip_address=ip_address,
            days=remember_days
        )

        return trusted_device

    @classmethod
    def is_trusted_device(cls, user, request):
        """Check if the current device is trusted for MFA bypass."""
        device_fingerprint = cls._generate_device_fingerprint(request)

        trusted_device = TrustedDevice.objects.filter(
            user=user,
            device_fingerprint=device_fingerprint,
            is_active=True
        ).first()

        if trusted_device and trusted_device.is_valid():
            # Extend expiry on use
            trusted_device.extend_expiry()
            return True

        return False

    @classmethod
    def revoke_trusted_device(cls, user, device_id):
        """Revoke a specific trusted device."""
        try:
            device = TrustedDevice.objects.get(
                id=device_id,
                user=user
            )
            device.revoke()
            return True
        except TrustedDevice.DoesNotExist:
            return False

    @classmethod
    def get_user_trusted_devices(cls, user):
        """Get all active trusted devices for a user."""
        return TrustedDevice.objects.filter(
            user=user,
            is_active=True
        ).order_by('-last_used_at')

    @classmethod
    def send_mfa_recovery_email(cls, user):
        """Send MFA recovery email to user."""
        from .email_service import EmailService

        # Generate recovery token (valid for 1 hour)
        recovery_token = secrets.token_urlsafe(32)
        cache_key = f"mfa_recovery_{user.id}"
        cache.set(cache_key, recovery_token, timeout=3600)  # 1 hour

        # Send recovery email
        context = {
            'user': user,
            'recovery_token': recovery_token,
            'recovery_url': f"{settings.FRONTEND_URL}/auth/mfa-recovery?token={recovery_token}&user_id={user.id}"
        }

        EmailService.send_template_email(
            to_email=user.email,
            template_name='mfa_recovery',
            context=context,
            subject='MFA Recovery Request'
        )

        return True

    @classmethod
    def verify_recovery_token(cls, user, token):
        """Verify MFA recovery token."""
        cache_key = f"mfa_recovery_{user.id}"
        stored_token = cache.get(cache_key)

        if stored_token and stored_token == token:
            # Clear the token after use
            cache.delete(cache_key)
            return True

        return False

    # Private helper methods

    @classmethod
    def _is_rate_limited(cls, user):
        """Check if user is rate limited for MFA attempts."""
        cache_key = cls.MFA_RATE_LIMIT_KEY.format(user_id=user.id)
        attempts = cache.get(cache_key, 0)
        return attempts >= cls.MFA_ATTEMPT_LIMIT

    @classmethod
    def _record_failed_attempt(cls, user):
        """Record a failed MFA attempt."""
        cache_key = cls.MFA_RATE_LIMIT_KEY.format(user_id=user.id)
        attempts = cache.get(cache_key, 0) + 1
        cache.set(cache_key, attempts, timeout=cls.MFA_LOCKOUT_DURATION * 60)

    @classmethod
    def _clear_rate_limit(cls, user):
        """Clear rate limiting for user."""
        cache_key = cls.MFA_RATE_LIMIT_KEY.format(user_id=user.id)
        cache.delete(cache_key)

    @classmethod
    def _generate_device_fingerprint(cls, request):
        """Generate a device fingerprint from request headers."""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
        accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')

        # Create fingerprint from headers
        fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()

    @classmethod
    def _get_client_ip(cls, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or '127.0.0.1'

    @classmethod
    def _generate_device_name(cls, user_agent):
        """Generate a friendly device name from user agent."""
        user_agent = user_agent.lower()

        if 'mobile' in user_agent or 'android' in user_agent:
            if 'android' in user_agent:
                return 'Android Device'
            return 'Mobile Device'
        elif 'iphone' in user_agent or 'ipad' in user_agent:
            if 'iphone' in user_agent:
                return 'iPhone'
            return 'iPad'
        elif 'chrome' in user_agent:
            return 'Chrome Browser'
        elif 'firefox' in user_agent:
            return 'Firefox Browser'
        elif 'safari' in user_agent:
            return 'Safari Browser'
        elif 'edge' in user_agent:
            return 'Edge Browser'
        else:
            return 'Unknown Device'