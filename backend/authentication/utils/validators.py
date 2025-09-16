"""
Custom validators for authentication app.
"""
import re
import requests
from django.core.exceptions import ValidationError
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


class DisposableEmailValidator:
    """
    Validator to check against disposable email services.
    """

    # Extended list of disposable email domains
    DISPOSABLE_DOMAINS = {
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.org',
        'temp-mail.org', 'throwaway.email', 'yopmail.com', 'maildrop.cc',
        'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net', 'spam4.me',
        'bccto.me', 'chacuo.net', 'dispostable.com', 'spambox.us', 'trbvm.com',
        'wegwerfmail.de', 'zehnminutenmail.de', 'zetmail.com', '33mail.com',
        'getnada.com', 'mailnesia.com', 'trashmail.com', 'fakeinbox.com',
        'mohmal.com', 'mytrashmail.com', 'no-spam.ws', 'nospam.ze.tc',
        'nowmymail.com', 'objectmail.com', 'obobbo.com', 'odnorazovoe.ru',
        'one-time.email', 'onetime.email', 'onetimemail.com', 'online.ms',
        'opayq.com', 'ordinaryamerican.net', 'otherinbox.com', 'ovpn.to',
        'owlpic.com', 'pancakemail.com', 'pcusers.otherinbox.com', 'pjkpjk.com',
        'plexvenet.net', 'pookmail.com', 'privacy.net', 'proxymail.eu',
        'prtnx.com', 'putthisinyourspamdatabase.com', 'quickinbox.com',
        'rcpt.at', 'reallymymail.com', 'recode.me', 'recursor.net',
        'reliable-mail.com', 'rhyta.com', 'rmqkr.net', 'royal.net',
        'rppkn.com', 'rtrtr.com', 'rudymail.com', 's0ny.net', 'safe-mail.net',
        'safersignup.de', 'safetymail.info', 'safetypost.de', 'sandelf.de',
        'saynotospams.com', 'schafmail.de', 'secretemail.de', 'secure-mail.biz',
        'senseless-entertainment.com', 'services391.com', 'sharklasers.com',
        'shieldedmail.com', 'shitmail.me', 'shitware.nl', 'shmeriously.com',
        'shortmail.net', 'sibmail.com', 'sinnlos-mail.de', 'siteposter.net',
        'skeefmail.com', 'slaskpost.se', 'smashmail.de', 'smellfear.com',
        'snakemail.com', 'sneakemail.com', 'snkmail.com', 'sofimail.com',
        'sofort-mail.de', 'sogetthis.com', 'soodonims.com', 'spam.la',
        'spamail.de', 'spambob.net', 'spambob.org', 'spambog.com',
        'spambog.de', 'spambog.ru', 'spambox.info', 'spambox.irishspringtours.com',
        'spambox.us', 'spamcannon.com', 'spamcannon.net', 'spamcon.org',
        'spamcorptastic.com', 'spamcowboy.com', 'spamcowboy.net', 'spamcowboy.org',
        'spamday.com', 'spamex.com', 'spamfree24.com', 'spamfree24.de',
        'spamfree24.eu', 'spamfree24.net', 'spamfree24.org', 'spamgoes.com',
        'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org', 'spamhole.com',
        'spamify.com', 'spaminator.de', 'spamkill.info', 'spaml.com',
        'spaml.de', 'spammotel.com', 'spamobox.com', 'spamoff.de',
        'spamslicer.com', 'spamspot.com', 'spamthis.co.uk', 'spamthisplease.com',
        'spamtrail.com', 'spamtroll.net', 'speed.1s.fr', 'spoofmail.de',
        'stuffmail.de', 'super-auswahl.de', 'supergreatmail.com', 'supermailer.jp',
        'superrito.com', 'superstachel.de', 'suremail.info', 'talkinator.com',
        'teewars.org', 'teleworm.com', 'teleworm.us', 'temp-mail.org',
        'temp-mail.ru', 'tempalias.com', 'tempe-mail.com', 'tempemail.biz',
        'tempemail.com', 'tempinbox.co.uk', 'tempinbox.com', 'tempmail.eu',
        'tempmail2.com', 'tempmaildemo.com', 'tempmailer.com', 'tempmailer.de',
        'tempomail.fr', 'temporarily.de', 'temporarioemail.com.br', 'temporaryemail.net',
        'temporaryforwarding.com', 'temporaryinbox.com', 'temporarymailaddress.com',
        'tempthe.net', 'thanksnospam.info', 'thankyou2010.com', 'thc.st',
        'thelimestones.com', 'thisisnotmyrealemail.com', 'thismail.net',
        'throwawayemailaddresses.com', 'tilien.com', 'tittbit.in', 'tizi.com',
        'tmailinator.com', 'toomail.biz', 'topranklist.de', 'tradermail.info',
        'trash-amil.com', 'trash-mail.at', 'trash-mail.com', 'trash-mail.de',
        'trash2009.com', 'trashdevil.com', 'trashemail.de', 'trashmail.at',
        'trashmail.com', 'trashmail.de', 'trashmail.me', 'trashmail.net',
        'trashmail.org', 'trashmail.ws', 'trashmailer.com', 'trashymail.com',
        'trashymail.net', 'trbvm.com', 'trialmail.de', 'trillianpro.com',
        'tryalert.com', 'turual.com', 'twinmail.de', 'twoweirdtricks.com',
        'tyldd.com', 'uggsrock.com', 'umail.net', 'upliftnow.com',
        'uplipht.com', 'uroid.com', 'us.af', 'venompen.com', 'veryrealemail.com',
        'viditag.com', 'viewcastmedia.com', 'viewcastmedia.net', 'viewcastmedia.org',
        'vomoto.com', 'vpn.st', 'vsimcard.com', 'vubby.com', 'walala.org',
        'walkmail.net', 'webemail.me', 'weg-werf-email.de', 'wegwerf-emails.de',
        'wegwerfadresse.de', 'wegwerfemail.com', 'wegwerfemail.de', 'wegwerfmail.de',
        'wegwerfmail.info', 'wegwerfmail.net', 'wegwerfmail.org', 'wetrainbayarea.com',
        'wetrainbayarea.org', 'wh4f.org', 'whatiaas.com', 'whatpaas.com',
        'whatsaas.com', 'whopy.com', 'willhackforfood.biz', 'willselldomain.com',
        'winemaven.info', 'wronghead.com', 'wuzup.net', 'wuzupmail.net',
        'www.e4ward.com', 'www.gishpuppy.com', 'www.mailinator.com', 'wwwnew.eu',
        'x.ip6.li', 'xagloo.com', 'xemaps.com', 'xents.com', 'xmaily.com',
        'xoxy.net', 'yapped.net', 'yeah.net', 'yep.it', 'yogamaven.com',
        'yopmail.com', 'yopmail.fr', 'yopmail.net', 'youmailr.com', 'yourdomain.com',
        'ypmail.webredirect.org', 'yuurok.com', 'zehnminutenmail.de', 'zetmail.com',
        'zippymail.info', 'zoaxe.com', 'zoemail.org', 'zomg.info'
    }

    def __call__(self, value):
        """
        Validate that the email domain is not a disposable email service.
        """
        if '@' not in value:
            return  # Let other validators handle invalid email format

        domain = value.split('@')[1].lower()

        if domain in self.DISPOSABLE_DOMAINS:
            raise ValidationError(
                'Registration with disposable email addresses is not allowed.',
                code='disposable_email'
            )

        # Check for suspicious domain patterns
        if self._is_suspicious_domain(domain):
            raise ValidationError(
                'This email domain appears to be temporary or suspicious.',
                code='suspicious_domain'
            )

    def _is_suspicious_domain(self, domain):
        """
        Check if domain appears suspicious using heuristics.
        """
        # Check for domains with excessive numbers
        if len(re.findall(r'\d', domain)) > len(domain) * 0.5:
            return True

        # Check for very short domains (less than 4 characters before TLD)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2 and len(domain_parts[0]) < 4:
            return True

        # Check for suspicious TLDs commonly used by disposable services
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw'}
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True

        return False


class PasswordStrengthValidator:
    """
    Advanced password strength validator with entropy calculation.
    """

    def __init__(self, min_entropy=50):
        self.min_entropy = min_entropy

    def __call__(self, password):
        """
        Validate password strength.
        """
        errors = []

        # Check minimum length
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")

        # Check maximum length
        if len(password) > 128:
            errors.append("Password must be no more than 128 characters long.")

        # Check for character variety
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter.")

        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter.")

        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number.")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character.")

        # Check for common patterns
        if self._contains_common_patterns(password):
            errors.append("Password contains common patterns that are not secure.")

        # Check entropy
        entropy = self._calculate_entropy(password)
        if entropy < self.min_entropy:
            errors.append(f"Password is not complex enough (entropy: {entropy:.1f}, required: {self.min_entropy}).")

        if errors:
            raise ValidationError(errors, code='weak_password')

    def _contains_common_patterns(self, password):
        """
        Check for common password patterns.
        """
        password_lower = password.lower()

        # Common weak passwords
        common_passwords = {
            'password', '123456', 'qwerty', 'abc123', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'master',
            'shadow', 'superman', 'batman', 'princess', 'football'
        }

        if password_lower in common_passwords:
            return True

        # Keyboard patterns
        keyboard_patterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '0987654321'
        ]

        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True

        return False

    def _calculate_entropy(self, password):
        """
        Calculate password entropy.
        """
        import math

        # Determine character set size
        charset_size = 0

        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            charset_size += 20

        if charset_size == 0:
            return 0

        # Calculate entropy: log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)

        # Reduce entropy for repeated characters
        unique_chars = len(set(password))
        if unique_chars < len(password):
            repetition_penalty = unique_chars / len(password)
            entropy *= repetition_penalty

        return entropy


class NameValidator:
    """
    Validator for first and last names to prevent fake or inappropriate entries.
    """

    FAKE_PATTERNS = {
        'test', 'fake', 'dummy', 'admin', 'null', 'undefined',
        'asdf', 'qwerty', '123', 'abc', 'xxx', 'user', 'name',
        'firstname', 'lastname', 'john', 'jane', 'doe', 'smith'
    }

    def __call__(self, value):
        """
        Validate name for fake patterns and inappropriate content.
        """
        if not value:
            return  # Allow empty names

        value_lower = value.lower().strip()

        # Check for fake patterns
        if value_lower in self.FAKE_PATTERNS:
            raise ValidationError(
                'Please enter a valid name.',
                code='fake_name'
            )

        # Check for excessive numbers
        if len(re.findall(r'\d', value)) > len(value) * 0.3:
            raise ValidationError(
                'Name contains too many numbers.',
                code='invalid_name_format'
            )

        # Check for repeated characters
        if len(set(value_lower)) <= 2 and len(value) > 3:
            raise ValidationError(
                'Please enter a valid name.',
                code='invalid_name_pattern'
            )

        # Check for minimum length (at least 2 characters)
        if len(value.strip()) < 2:
            raise ValidationError(
                'Name must be at least 2 characters long.',
                code='name_too_short'
            )

        # Check for maximum length
        if len(value) > 50:
            raise ValidationError(
                'Name must be no more than 50 characters long.',
                code='name_too_long'
            )

        # Check for valid characters (letters, spaces, hyphens, apostrophes)
        if not re.match(r"^[a-zA-Z\s\-']+$", value):
            raise ValidationError(
                'Name can only contain letters, spaces, hyphens, and apostrophes.',
                code='invalid_name_characters'
            )


def check_password_breach(password):
    """
    Check if password has been found in known data breaches using HaveIBeenPwned API.
    This is an optional check that can be enabled in production.
    """
    try:
        import hashlib
        import requests

        # Hash the password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Check cache first
        cache_key = f"pwned_check_{prefix}"
        cached_result = cache.get(cache_key)

        if cached_result is not None:
            return suffix in cached_result

        # Query HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            # Cache the result for 1 hour
            cache.set(cache_key, response.text, 3600)
            return suffix in response.text

    except Exception as e:
        logger.warning(f"Password breach check failed: {e}")

    return False  # If check fails, don't block the password