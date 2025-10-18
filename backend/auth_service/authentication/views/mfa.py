"""
Multi-Factor Authentication Views

Views for handling MFA setup, verification, backup codes,
trusted devices, and recovery functionality.
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.openapi import OpenApiTypes

from ..services import MFAService
from ..serializers import (
    MFASetupSerializer, MFASetupResponseSerializer, MFAVerificationSerializer,
    MFALoginVerificationSerializer, MFAStatusSerializer, MFADeviceSerializer,
    TrustedDeviceSerializer, MFADisableSerializer, BackupCodesRegenerateSerializer,
    BackupCodesResponseSerializer, MFARecoveryRequestSerializer, MFARecoveryVerifySerializer,
    TrustedDeviceRevokeSerializer
)
from ..models import MFADevice, TrustedDevice, MFABackupCode

User = get_user_model()


@extend_schema(
    summary="Get MFA Status",
    description="Get the current MFA status for the authenticated user",
    responses={200: MFAStatusSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_status(request):
    """Get MFA status for the authenticated user."""
    user = request.user

    # Get MFA device count
    device_count = MFADevice.objects.filter(
        user=user,
        is_active=True,
        is_verified=True
    ).count()

    # Get backup codes remaining
    backup_codes_remaining = MFABackupCode.objects.filter(
        user=user,
        is_used=False
    ).count()

    # Get trusted devices count
    trusted_devices_count = TrustedDevice.objects.filter(
        user=user,
        is_active=True
    ).count()

    data = {
        'is_enabled': device_count > 0,
        'device_count': device_count,
        'backup_codes_remaining': backup_codes_remaining,
        'trusted_devices_count': trusted_devices_count
    }

    serializer = MFAStatusSerializer(data)
    return Response(serializer.data)


@extend_schema(
    summary="Setup MFA Device",
    description="Setup a new MFA device with TOTP and generate QR code",
    request=MFASetupSerializer,
    responses={
        201: MFASetupResponseSerializer,
        400: {"description": "Bad request - validation errors or user already has MFA"}
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@transaction.atomic
def mfa_setup(request):
    """Setup MFA for the authenticated user."""
    serializer = MFASetupSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = request.user
        device_name = serializer.validated_data['device_name']

        # Setup MFA device
        setup_data = MFAService.setup_mfa_device(user, device_name)

        response_data = {
            'device_id': setup_data['device'].id,
            'secret': setup_data['secret'],
            'qr_code': setup_data['qr_code'],
            'backup_codes': setup_data['backup_codes']
        }

        response_serializer = MFASetupResponseSerializer(response_data)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    except ValueError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to setup MFA device'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Verify MFA Setup",
    description="Verify TOTP code to complete MFA device setup",
    request=MFAVerificationSerializer,
    responses={
        200: {"description": "MFA device verified successfully"},
        400: {"description": "Invalid verification code or device not found"}
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_verify_setup(request):
    """Verify MFA device setup with TOTP code."""
    serializer = MFAVerificationSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = request.user
        device_id = serializer.validated_data['device_id']
        code = serializer.validated_data['code']

        # Verify TOTP code
        is_valid = MFAService.verify_totp_code(user, code, device_id)

        if is_valid:
            return Response({
                'message': 'MFA device verified successfully',
                'status': 'verified'
            })
        else:
            return Response(
                {'error': 'Invalid verification code'},
                status=status.HTTP_400_BAD_REQUEST
            )

    except ValueError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to verify MFA device'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Verify MFA for Login",
    description="Verify MFA code during login process",
    request=MFALoginVerificationSerializer,
    responses={
        200: {"description": "MFA verification successful"},
        400: {"description": "Invalid MFA code"},
        429: {"description": "Too many failed attempts"}
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@method_decorator(never_cache, name='dispatch')
def mfa_verify_login(request):
    """Verify MFA code during login."""
    serializer = MFALoginVerificationSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = request.user
        code = serializer.validated_data['code']
        remember_device = serializer.validated_data.get('remember_device', False)

        is_valid = False

        # Try TOTP verification first (6 digits)
        if len(code) == 6:
            is_valid = MFAService.verify_totp_code(user, code)
        # Try backup code verification (8 characters)
        elif len(code) == 8:
            is_valid = MFAService.verify_backup_code(user, code)

        if is_valid:
            response_data = {
                'message': 'MFA verification successful',
                'status': 'verified'
            }

            # Create trusted device if requested
            if remember_device:
                trusted_device = MFAService.create_trusted_device(user, request)
                response_data['trusted_device_created'] = True
                response_data['trusted_device_id'] = str(trusted_device.id)

            return Response(response_data)
        else:
            return Response(
                {'error': 'Invalid MFA code'},
                status=status.HTTP_400_BAD_REQUEST
            )

    except ValueError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to verify MFA code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Disable MFA",
    description="Disable MFA for the authenticated user",
    request=MFADisableSerializer,
    responses={
        200: {"description": "MFA disabled successfully"},
        400: {"description": "Invalid password or MFA not enabled"}
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@transaction.atomic
def mfa_disable(request):
    """Disable MFA for the authenticated user."""
    serializer = MFADisableSerializer(data=request.data, context={'request': request})

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = request.user

        # Check if user has MFA enabled
        if not MFAService.user_has_active_mfa(user):
            return Response(
                {'error': 'MFA is not enabled for this account'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Disable MFA
        MFAService.disable_mfa(user)

        return Response({
            'message': 'MFA has been disabled successfully',
            'status': 'disabled'
        })

    except Exception as e:
        return Response(
            {'error': 'Failed to disable MFA'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Regenerate Backup Codes",
    description="Generate new backup codes for MFA recovery",
    request=BackupCodesRegenerateSerializer,
    responses={
        200: BackupCodesResponseSerializer,
        400: {"description": "Invalid password or MFA not enabled"}
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@transaction.atomic
def mfa_regenerate_backup_codes(request):
    """Regenerate backup codes for the authenticated user."""
    serializer = BackupCodesRegenerateSerializer(data=request.data, context={'request': request})

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = request.user

        # Generate new backup codes
        backup_codes = MFAService.regenerate_backup_codes(user)

        response_data = {
            'backup_codes': backup_codes,
            'message': 'Save these backup codes in a secure location. They can only be used once each.'
        }

        response_serializer = BackupCodesResponseSerializer(response_data)
        return Response(response_serializer.data)

    except ValueError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to regenerate backup codes'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Get MFA Devices",
    description="Get all MFA devices for the authenticated user",
    responses={200: MFADeviceSerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_devices(request):
    """Get all MFA devices for the authenticated user."""
    user = request.user
    devices = MFADevice.objects.filter(user=user, is_active=True).order_by('-created_at')
    serializer = MFADeviceSerializer(devices, many=True)
    return Response(serializer.data)


@extend_schema(
    summary="Get Trusted Devices",
    description="Get all trusted devices for the authenticated user",
    responses={200: TrustedDeviceSerializer(many=True)}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def trusted_devices(request):
    """Get all trusted devices for the authenticated user."""
    user = request.user
    devices = MFAService.get_user_trusted_devices(user)
    serializer = TrustedDeviceSerializer(devices, many=True)
    return Response(serializer.data)


@extend_schema(
    summary="Revoke Trusted Device",
    description="Revoke a specific trusted device",
    request=TrustedDeviceRevokeSerializer,
    responses={
        200: {"description": "Trusted device revoked successfully"},
        404: {"description": "Trusted device not found"}
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_trusted_device(request):
    """Revoke a specific trusted device."""
    serializer = TrustedDeviceRevokeSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = request.user
        device_id = serializer.validated_data['device_id']

        success = MFAService.revoke_trusted_device(user, device_id)

        if success:
            return Response({
                'message': 'Trusted device revoked successfully',
                'status': 'revoked'
            })
        else:
            return Response(
                {'error': 'Trusted device not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    except Exception as e:
        return Response(
            {'error': 'Failed to revoke trusted device'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Request MFA Recovery",
    description="Request MFA recovery via email",
    request=MFARecoveryRequestSerializer,
    responses={
        200: {"description": "Recovery email sent successfully"},
        404: {"description": "User not found"}
    }
)
@api_view(['POST'])
@csrf_exempt
def mfa_recovery_request(request):
    """Request MFA recovery via email."""
    serializer = MFARecoveryRequestSerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        email = serializer.validated_data['email']

        # Find user by email
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            # Don't reveal if email exists or not for security
            return Response({
                'message': 'If an account with this email exists, a recovery email has been sent.'
            })

        # Check if user has MFA enabled
        if not MFAService.user_has_active_mfa(user):
            return Response({
                'message': 'If an account with this email exists, a recovery email has been sent.'
            })

        # Send recovery email
        MFAService.send_mfa_recovery_email(user)

        return Response({
            'message': 'If an account with this email exists, a recovery email has been sent.'
        })

    except Exception as e:
        return Response(
            {'error': 'Failed to process recovery request'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Verify MFA Recovery",
    description="Verify MFA recovery token and reset account access",
    request=MFARecoveryVerifySerializer,
    responses={
        200: {"description": "Account recovery successful"},
        400: {"description": "Invalid recovery token or user"}
    }
)
@api_view(['POST'])
@csrf_exempt
@transaction.atomic
def mfa_recovery_verify(request):
    """Verify MFA recovery token and reset account access."""
    serializer = MFARecoveryVerifySerializer(data=request.data)

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        user_id = serializer.validated_data['user_id']
        recovery_token = serializer.validated_data['recovery_token']
        new_password = serializer.validated_data['new_password']

        # Find user
        try:
            user = User.objects.get(id=user_id, is_active=True)
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid recovery request'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify recovery token
        if not MFAService.verify_recovery_token(user, recovery_token):
            return Response(
                {'error': 'Invalid or expired recovery token'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Reset password and disable MFA
        user.set_password(new_password)
        user.save()

        # Disable MFA for security
        MFAService.disable_mfa(user)

        return Response({
            'message': 'Account recovery successful. MFA has been disabled for security. Please log in with your new password.',
            'status': 'recovered'
        })

    except Exception as e:
        return Response(
            {'error': 'Failed to process recovery verification'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Check if Device is Trusted",
    description="Check if the current device is trusted for MFA bypass",
    responses={
        200: {"description": "Device trust status"},
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_trusted_device(request):
    """Check if the current device is trusted."""
    user = request.user
    is_trusted = MFAService.is_trusted_device(user, request)

    return Response({
        'is_trusted': is_trusted,
        'requires_mfa': not is_trusted and MFAService.user_has_active_mfa(user)
    })