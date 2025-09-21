"""
Tests for Multi-Factor Authentication system.

This module contains tests for MFA setup, verification, backup codes,
and trusted device functionality.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
import pyotp

from ..models import MFADevice, MFABackupCode, TrustedDevice
from ..services import MFAService

User = get_user_model()


class MFAServiceTestCase(TestCase):
    """Test cases for MFA service functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )

    def test_generate_totp_secret(self):
        """Test TOTP secret generation."""
        secret = MFAService.generate_totp_secret()
        self.assertIsInstance(secret, str)
        self.assertEqual(len(secret), 32)  # Base32 encoded secret

    def test_setup_mfa_device(self):
        """Test MFA device setup."""
        device_name = "Test Device"

        with patch('pyotp.random_base32') as mock_secret:
            mock_secret.return_value = 'JBSWY3DPEHPK3PXP'

            result = MFAService.setup_mfa_device(self.user, device_name)

            self.assertIn('device', result)
            self.assertIn('secret', result)
            self.assertIn('qr_code', result)
            self.assertIn('backup_codes', result)

            # Check device was created
            device = result['device']
            self.assertEqual(device.user, self.user)
            self.assertEqual(device.device_name, device_name)
            self.assertFalse(device.is_verified)

    def test_verify_totp_code_valid(self):
        """Test TOTP code verification with valid code."""
        # Create MFA device
        device = MFADevice.objects.create(
            user=self.user,
            device_name="Test Device",
            secret_key='JBSWY3DPEHPK3PXP',
            is_active=True,
            is_verified=True
        )

        # Generate valid TOTP code
        totp = pyotp.TOTP('JBSWY3DPEHPK3PXP')
        valid_code = totp.now()

        # Verify code
        is_valid = MFAService.verify_totp_code(self.user, valid_code)
        self.assertTrue(is_valid)

    def test_verify_totp_code_invalid(self):
        """Test TOTP code verification with invalid code."""
        # Create MFA device
        MFADevice.objects.create(
            user=self.user,
            device_name="Test Device",
            secret_key='JBSWY3DPEHPK3PXP',
            is_active=True,
            is_verified=True
        )

        # Use invalid code
        is_valid = MFAService.verify_totp_code(self.user, '000000')
        self.assertFalse(is_valid)

    def test_user_has_active_mfa(self):
        """Test checking if user has active MFA."""
        # Initially no MFA
        self.assertFalse(MFAService.user_has_active_mfa(self.user))

        # Create active MFA device
        MFADevice.objects.create(
            user=self.user,
            device_name="Test Device",
            secret_key='JBSWY3DPEHPK3PXP',
            is_active=True,
            is_verified=True
        )

        # Now has MFA
        self.assertTrue(MFAService.user_has_active_mfa(self.user))

    def test_disable_mfa(self):
        """Test disabling MFA for user."""
        # Create MFA device and backup codes
        MFADevice.objects.create(
            user=self.user,
            device_name="Test Device",
            secret_key='JBSWY3DPEHPK3PXP',
            is_active=True,
            is_verified=True
        )

        MFABackupCode.generate_codes_for_user(self.user)

        # Disable MFA
        result = MFAService.disable_mfa(self.user)
        self.assertTrue(result)

        # Check MFA is disabled
        self.assertFalse(MFAService.user_has_active_mfa(self.user))

        # Check backup codes are cleared
        backup_codes = MFABackupCode.objects.filter(user=self.user, is_used=False)
        self.assertEqual(backup_codes.count(), 0)


class MFAAPITestCase(APITestCase):
    """Test cases for MFA API endpoints."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )

    def test_mfa_status_no_mfa(self):
        """Test MFA status endpoint when user has no MFA."""
        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:mfa:mfa_status')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['is_enabled'])
        self.assertEqual(response.data['device_count'], 0)

    def test_mfa_setup_success(self):
        """Test successful MFA setup."""
        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:mfa:mfa_setup')
        data = {'device_name': 'Test Device'}

        with patch('pyotp.random_base32') as mock_secret:
            mock_secret.return_value = 'JBSWY3DPEHPK3PXP'

            response = self.client.post(url, data)

            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertIn('device_id', response.data)
            self.assertIn('qr_code', response.data)
            self.assertIn('backup_codes', response.data)

    def test_mfa_setup_duplicate_device(self):
        """Test MFA setup when user already has active MFA."""
        # Create existing MFA device
        MFADevice.objects.create(
            user=self.user,
            device_name="Existing Device",
            secret_key='JBSWY3DPEHPK3PXP',
            is_active=True,
            is_verified=True
        )

        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:mfa:mfa_setup')
        data = {'device_name': 'Test Device'}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)


class MFAModelTestCase(TestCase):
    """Test cases for MFA models."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )

    def test_mfa_device_creation(self):
        """Test MFA device model creation."""
        device = MFADevice.objects.create(
            user=self.user,
            device_name="Test Device",
            secret_key='JBSWY3DPEHPK3PXP',
            is_active=True
        )

        self.assertEqual(device.user, self.user)
        self.assertEqual(device.device_name, "Test Device")
        self.assertEqual(device.mfa_type, 'totp')
        self.assertFalse(device.is_verified)
        self.assertFalse(device.is_locked())

    def test_backup_code_generation(self):
        """Test backup code generation."""
        codes = MFABackupCode.generate_codes_for_user(self.user)

        self.assertEqual(len(codes), 10)  # Default 10 codes

        # Check codes are stored in database
        db_codes = MFABackupCode.objects.filter(user=self.user)
        self.assertEqual(db_codes.count(), 10)

        # Check all codes are unused
        unused_codes = db_codes.filter(is_used=False)
        self.assertEqual(unused_codes.count(), 10)

    def test_trusted_device_creation(self):
        """Test trusted device model creation."""
        device = TrustedDevice.create_trusted_device(
            user=self.user,
            device_fingerprint='test_fingerprint',
            device_name='Test Device',
            ip_address='127.0.0.1'
        )

        self.assertEqual(device.user, self.user)
        self.assertEqual(device.device_fingerprint, 'test_fingerprint')
        self.assertTrue(device.is_valid())
        self.assertFalse(device.is_expired())