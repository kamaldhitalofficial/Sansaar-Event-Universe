"""
MFA Serializers

Serializers for Multi-Factor Authentication endpoints including
TOTP setup, verification, backup codes, and trusted devices.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from ..models import MFADevice, TrustedDevice

User = get_user_model()


class MFASetupSerializer(serializers.Serializer):
    """Serializer for MFA setup request."""
    device_name = serializers.CharField(
        max_length=100,
        help_text="User-friendly name for the MFA device"
    )

    def validate_device_name(self, value):
        """Validate device name."""
        if not value.strip():
            raise serializers.ValidationError("Device name cannot be empty")
        return value.strip()


class MFASetupResponseSerializer(serializers.Serializer):
    """Serializer for MFA setup response."""
    device_id = serializers.UUIDField()
    secret = serializers.CharField()
    qr_code = serializers.CharField()
    backup_codes = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of backup codes for recovery"
    )

    class Meta:
        fields = ['device_id', 'secret', 'qr_code', 'backup_codes']


class MFAVerificationSerializer(serializers.Serializer):
    """Serializer for MFA verification during setup."""
    device_id = serializers.UUIDField()
    code = serializers.CharField(
        min_length=6,
        max_length=6,
        help_text="6-digit TOTP code from authenticator app"
    )

    def validate_code(self, value):
        """Validate TOTP code format."""
        if not value.isdigit():
            raise serializers.ValidationError("Code must contain only digits")
        if len(value) != 6:
            raise serializers.ValidationError("Code must be exactly 6 digits")
        return value


class MFALoginVerificationSerializer(serializers.Serializer):
    """Serializer for MFA verification during login."""
    code = serializers.CharField(
        min_length=6,
        max_length=8,
        help_text="6-digit TOTP code or 8-character backup code"
    )
    remember_device = serializers.BooleanField(
        default=False,
        help_text="Remember this device for 30 days"
    )

    def validate_code(self, value):
        """Validate code format."""
        value = value.strip().upper()

        # TOTP code (6 digits)
        if len(value) == 6:
            if not value.isdigit():
                raise serializers.ValidationError("TOTP code must contain only digits")
        # Backup code (8 alphanumeric characters)
        elif len(value) == 8:
            if not value.isalnum():
                raise serializers.ValidationError("Backup code must contain only letters and numbers")
        else:
            raise serializers.ValidationError("Code must be 6 digits (TOTP) or 8 characters (backup code)")

        return value


class MFAStatusSerializer(serializers.Serializer):
    """Serializer for MFA status response."""
    is_enabled = serializers.BooleanField()
    device_count = serializers.IntegerField()
    backup_codes_remaining = serializers.IntegerField()
    trusted_devices_count = serializers.IntegerField()


class MFADeviceSerializer(serializers.ModelSerializer):
    """Serializer for MFA device information."""

    class Meta:
        model = MFADevice
        fields = [
            'id', 'device_name', 'mfa_type', 'is_active',
            'is_verified', 'created_at', 'verified_at', 'last_used_at'
        ]
        read_only_fields = [
            'id', 'mfa_type', 'is_active', 'is_verified',
            'created_at', 'verified_at', 'last_used_at'
        ]


class TrustedDeviceSerializer(serializers.ModelSerializer):
    """Serializer for trusted device information."""

    class Meta:
        model = TrustedDevice
        fields = [
            'id', 'device_name', 'ip_address', 'created_at',
            'last_used_at', 'expires_at', 'is_active'
        ]
        read_only_fields = [
            'id', 'device_name', 'ip_address', 'created_at',
            'last_used_at', 'expires_at', 'is_active'
        ]


class MFADisableSerializer(serializers.Serializer):
    """Serializer for MFA disable request."""
    password = serializers.CharField(
        write_only=True,
        help_text="Current password for verification"
    )

    def validate_password(self, value):
        """Validate current password."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Invalid password")
        return value


class BackupCodesRegenerateSerializer(serializers.Serializer):
    """Serializer for backup codes regeneration."""
    password = serializers.CharField(
        write_only=True,
        help_text="Current password for verification"
    )

    def validate_password(self, value):
        """Validate current password."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Invalid password")
        return value


class BackupCodesResponseSerializer(serializers.Serializer):
    """Serializer for backup codes response."""
    backup_codes = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of new backup codes"
    )
    message = serializers.CharField(
        help_text="Instructions for backup codes"
    )


class MFARecoveryRequestSerializer(serializers.Serializer):
    """Serializer for MFA recovery request."""
    email = serializers.EmailField(
        help_text="Email address for MFA recovery"
    )


class MFARecoveryVerifySerializer(serializers.Serializer):
    """Serializer for MFA recovery verification."""
    user_id = serializers.IntegerField()
    recovery_token = serializers.CharField()
    new_password = serializers.CharField(
        min_length=8,
        write_only=True,
        help_text="New password for account recovery"
    )

    def validate_new_password(self, value):
        """Validate new password strength."""
        from ..utils.validators import validate_password_strength
        validate_password_strength(value)
        return value


class TrustedDeviceRevokeSerializer(serializers.Serializer):
    """Serializer for trusted device revocation."""
    device_id = serializers.UUIDField(
        help_text="ID of the trusted device to revoke"
    )