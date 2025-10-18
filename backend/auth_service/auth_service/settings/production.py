"""
Django settings for sansaar project (Production environment).
"""

from .base import *
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.celery import CeleryIntegration

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = config(
    'ALLOWED_HOSTS',
    default='',
    cast=lambda v: [s.strip() for s in v.split(',') if s.strip()]
)

# Database - PostgreSQL for production (Neon.tech compatible)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT'),
        'OPTIONS': {
            'sslmode': config('DB_SSLMODE', default='require'),
        },
        'CONN_MAX_AGE': 600,  # Connection pooling
    }
}

# Session Configuration - Secure for production
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_DOMAIN = config('SESSION_COOKIE_DOMAIN', default=None)

# Security Settings - Strict for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=True, cast=bool)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# CSRF Protection
CSRF_COOKIE_SECURE = True
CSRF_TRUSTED_ORIGINS = config(
    'CSRF_TRUSTED_ORIGINS',
    default='',
    cast=lambda v: [s.strip() for s in v.split(',') if s.strip()]
)

# CORS - Strict for production
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='',
    cast=lambda v: [s.strip() for s in v.split(',') if s.strip()]
)

# Email - SMTP another_backend for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Static files - Use WhiteNoise for serving static files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Sentry Configuration for Error Tracking (optional)
SENTRY_DSN = config('SENTRY_DSN', default='')
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(
                transaction_style='url',
                middleware_spans=True,
                signals_spans=True,
            ),
            RedisIntegration(),
            CeleryIntegration(monitor_beat_tasks=True),
        ],
        traces_sample_rate=0.1,  # Adjust based on your needs
        send_default_pii=False,
        environment=config('ENVIRONMENT', default='production'),
        release=config('RELEASE_VERSION', default='1.0.0'),
    )

# Logging Configuration - Production-ready (Console + Sentry)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': '{{"level": "{levelname}", "time": "{asctime}", "module": "{module}", "message": "{message}"}}',
            'style': '{',
        },
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        'sentry': {
            'level': 'ERROR',
            'class': 'sentry_sdk.integrations.logging.EventHandler',
        },
    },
    'root': {
        'handlers': ['console', 'sentry'] if SENTRY_DSN else ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'sentry'] if SENTRY_DSN else ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'authentications': {
            'handlers': ['console', 'sentry'] if SENTRY_DSN else ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console', 'sentry'] if SENTRY_DSN else ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
    },
}

# Cache Configuration - Production Redis settings
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 20,
                'retry_on_timeout': True,
            },
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
        }
    }
}

# Django REST Framework - Production throttling
REST_FRAMEWORK.update({
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'login': '5/min',  # Strict login rate limiting
        'register': '3/min',  # Strict registration rate limiting
    }
})

# Production-specific authentication settings
MAX_LOGIN_ATTEMPTS = 3  # Stricter for production
ACCOUNT_LOCKOUT_DURATION = 60  # Longer lockout for production

# Performance Settings
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000
DATA_UPLOAD_MAX_NUMBER_FILES = 20

# Admin Security
ADMIN_URL = config('ADMIN_URL', default='admin/')  # Allow custom admin URL

# Health Check Settings
HEALTH_CHECK_ENABLED = config('HEALTH_CHECK_ENABLED', default=True, cast=bool)