"""
MFA URL Configuration

URL patterns for Multi-Factor Authentication endpoints including
TOTP setup, verification, backup codes, and trusted devices.
"""

from django.urls import path
from ..views import mfa

app_name = 'mfa'

urlpatterns = [
    # MFA Status and Management
    path('status/', mfa.mfa_status, name='mfa_status'),
    path('setup/', mfa.mfa_setup, name='mfa_setup'),
    path('verify-setup/', mfa.mfa_verify_setup, name='mfa_verify_setup'),
    path('verify-login/', mfa.mfa_verify_login, name='mfa_verify_login'),
    path('disable/', mfa.mfa_disable, name='mfa_disable'),

    # Backup Codes
    path('backup-codes/regenerate/', mfa.mfa_regenerate_backup_codes, name='mfa_regenerate_backup_codes'),

    # Device Management
    path('devices/', mfa.mfa_devices, name='mfa_devices'),
    path('trusted-devices/', mfa.trusted_devices, name='trusted_devices'),
    path('trusted-devices/revoke/', mfa.revoke_trusted_device, name='revoke_trusted_device'),
    path('trusted-devices/check/', mfa.check_trusted_device, name='check_trusted_device'),

    # Recovery
    path('recovery/request/', mfa.mfa_recovery_request, name='mfa_recovery_request'),
    path('recovery/verify/', mfa.mfa_recovery_verify, name='mfa_recovery_verify'),
]