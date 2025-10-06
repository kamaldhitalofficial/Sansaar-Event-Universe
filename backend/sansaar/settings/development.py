"""
Django settings for sansaar project (Development environment).
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-pgwe8@0%nh$m$jgs(145m*yr&%f_$y3y22imzpnjlom)0hm!nb'

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='sansaar_event_universe'),
        'USER': config('DB_USER', default='sansaar_user'),
        'PASSWORD': config('DB_PASSWORD', default='sansaar-universe'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': 'prefer',
        },
        'CONN_MAX_AGE': 600,
        'ATOMIC_REQUESTS': True,
    }
}

# CORS settings for development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React development server
    "http://localhost:8080",  # Flutter web development
    "http://127.0.0.1:8000",  # Django development server
    "http://localhost:5000",  # Flutter desktop
]


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'kamaldhitalofficial@gmail.com'
EMAIL_HOST_PASSWORD = 'zlaf fgkv bxda wlnw'
DEFAULT_FROM_EMAIL = 'Sansaar Event Universe <kamaldhitalofficial@gmail.com>'
EMAIL_TIMEOUT = 30


# Temporary for testing
# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# DEFAULT_FROM_EMAIL = 'noreply@sansaar.com'


# Account Security Settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 30  # minutes
EMAIL_VERIFICATION_TIMEOUT = 24  # hours

import warnings
warnings.filterwarnings(
    "ignore",
    message="cache backend django.core.cache.backends.locmem.LocMemCache is not officially supported",
)
