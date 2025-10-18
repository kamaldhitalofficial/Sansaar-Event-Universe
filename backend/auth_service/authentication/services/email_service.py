"""
Email service for handling email verification and notifications.
"""
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from ..models import EmailVerification
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """
    Service class for handling email operations.
    """

    @staticmethod
    def send_verification_email(user, request=None):
        """
        Send email verification email to user.

        Args:
            user: User instance
            request: Django request object for tracking

        Returns:
            tuple: (success: bool, message: str, verification: EmailVerification or None)
        """
        try:
            # Check rate limiting for email sending
            cache_key = f"email_verification_sent_{user.email}"
            last_sent = cache.get(cache_key)

            if last_sent:
                return False, "Verification email was recently sent. Please wait before requesting another.", None

            # Create verification token
            logger.info(f"Creating verification token for user: {user.email}")
            try:
                verification = EmailVerification.create_verification(user, request=request)
                logger.info(f"Verification token created: {verification.token}")
            except Exception as verification_error:
                logger.error(f"Failed to create verification token: {str(verification_error)}")
                return False, f"Failed to create verification token: {str(verification_error)}", None

            logger.info(f"Created verification token for user: {user.email}, token: {verification.token}")

            # Prepare email context
            context = {
                'user': user,
                'verification_token': str(verification.token),
                'verification_url': EmailService._build_verification_url(verification.token),
                'site_name': 'Sansaar Event Universe',
                'expires_at': verification.expires_at,
            }

            # Render email templates
            subject = f"Verify your email address - {context['site_name']}"
            html_message = EmailService._render_verification_email_html(context)
            plain_message = EmailService._render_verification_email_text(context)

            # Send email
            try:
                from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@sansaar.com')
                logger.info(f"Attempting to send email to: {user.email} from: {from_email}")

                emails_sent = send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False
                )
                logger.info(f"Emails sent count: {emails_sent}")

            except Exception as email_error:
                logger.error(f"Email sending failed: {str(email_error)}")
                return False, f"Failed to send verification email: {str(email_error)}", None

            if emails_sent > 0:
                # Set rate limiting (5 minutes)
                cache.set(cache_key, timezone.now().isoformat(), 300)

                logger.info(f"Verification email sent successfully to: {user.email}")
                return True, "Verification email sent successfully", verification
            else:
                logger.error(f"Failed to send verification email to: {user.email}")
                return False, "Failed to send verification email", None

        except Exception as e:
            logger.error(f"Error sending verification email to {user.email}: {str(e)}")
            return False, "Failed to send verification email", None

    @staticmethod
    def resend_verification_email(email):
        """
        Resend verification email for a user.

        Args:
            email: User email address

        Returns:
            tuple: (success: bool, message: str)
        """
        from django.contrib.auth import get_user_model

        User = get_user_model()

        try:
            user = User.objects.get(email=email)

            if user.is_active and user.is_email_verified:
                return False, "Account is already verified"

            # Send verification email (rate limiting is handled in send_verification_email)
            success, message, verification = EmailService.send_verification_email(user)

            if success:
                return True, "Verification email sent successfully"
            else:
                return False, message

        except User.DoesNotExist:
            # Don't reveal if email exists or not for security
            return False, "If this email is registered, a verification email will be sent"
        except Exception as e:
            logger.error(f"Failed to resend verification email: {e}")
            return False, "Failed to send verification email"

    @staticmethod
    def verify_email(token):
        """
        Verify email using verification token.

        Args:
            token: Verification token (UUID string)

        Returns:
            tuple: (success: bool, user: User or None, message: str)
        """
        try:
            # Get valid verification token
            verification = EmailVerification.get_valid_token(token)

            if not verification:
                return False, None, "Invalid or expired verification token"

            # Verify the token
            success = verification.verify()

            if success:
                logger.info(f"Email verified successfully for user: {verification.user.email}")
                return True, verification.user, "Email verified successfully"
            else:
                return False, None, "Failed to verify email"

        except Exception as e:
            logger.error(f"Error verifying email token {token}: {str(e)}")
            return False, None, "Verification failed"

    @staticmethod
    def _build_verification_url(token):
        """
        Build verification URL for email template.

        Args:
            token: Verification token

        Returns:
            str: Complete verification URL
        """
        # In production, this should be the frontend URL
        base_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        return f"{base_url}/verify-email/{token}"

    @staticmethod
    def _render_verification_email_html(context):
        """
        Render HTML email template for verification.

        Args:
            context: Template context

        Returns:
            str: Rendered HTML content
        """
        # Basic HTML template since we don't have template files yet
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Verify Your Email</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background-color: #f9f9f9; }}
                .button {{ display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }}
                .footer {{ padding: 20px; text-align: center; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{context['site_name']}</h1>
                </div>
                <div class="content">
                    <h2>Welcome{' ' + context['user'].first_name if context['user'].first_name else ''}!</h2>
                    <p>Thank you for registering with {context['site_name']}. To complete your registration, please verify your email address by clicking the button below:</p>
                    
                    <p style="text-align: center;">
                        <a href="{context['verification_url']}" class="button">Verify Email Address</a>
                    </p>
                    
                    <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; background-color: #f0f0f0; padding: 10px; border-radius: 4px;">
                        {context['verification_url']}
                    </p>
                    
                    <p><strong>Important:</strong> This verification link will expire on {context['expires_at'].strftime('%B %d, %Y at %I:%M %p UTC')}.</p>
                    
                    <p>If you didn't create an account with us, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2024 {context['site_name']}. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_content

    @staticmethod
    def _render_verification_email_text(context):
        """
        Render plain text email template for verification.

        Args:
            context: Template context

        Returns:
            str: Rendered plain text content
        """
        text_content = f"""
{context['site_name']} - Email Verification

Welcome{' ' + context['user'].first_name if context['user'].first_name else ''}!

Thank you for registering with {context['site_name']}. To complete your registration, please verify your email address by visiting the following link:

{context['verification_url']}

Important: This verification link will expire on {context['expires_at'].strftime('%B %d, %Y at %I:%M %p UTC')}.

If you didn't create an account with us, please ignore this email.

---
{context['site_name']}
        """
        return text_content.strip()

    @staticmethod
    def send_security_alert(user, alert_type, details, ip_address=None):
        """
        Send security alert email to user.

        Args:
            user: User instance
            alert_type: Type of security alert
            details: Alert details
            ip_address: IP address if relevant

        Returns:
            bool: Success status
        """
        try:
            context = {
                'user': user,
                'alert_type': alert_type,
                'details': details,
                'ip_address': ip_address,
                'timestamp': timezone.now(),
                'site_name': 'Sansaar Event Universe',
            }

            subject = f"Security Alert - {context['site_name']}"

            # Basic security alert template
            message = f"""
Security Alert for {user.email}

Alert Type: {alert_type}
Details: {details}
Time: {context['timestamp'].strftime('%B %d, %Y at %I:%M %p UTC')}
{f'IP Address: {ip_address}' if ip_address else ''}

If this was not you, please secure your account immediately by changing your password.

---
{context['site_name']} Security Team
            """

            from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@sansaar.com')
            success = send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=[user.email],
                fail_silently=False
            )

            if success:
                logger.info(f"Security alert sent to: {user.email}")
            else:
                logger.error(f"Failed to send security alert to: {user.email}")

            return success

        except Exception as e:
            logger.error(f"Error sending security alert to {user.email}: {str(e)}")
            return False