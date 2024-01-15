import os.path
import os
import sys
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [os.environ.get("ALLOWED_HOSTS"),'localhost', '127.0.0.1', '192.168.0.2']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'MapApp',
    'Mapapi',
    'crispy_forms',
    'crispy_bootstrap4',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.facebook',
    'allauth.socialaccount.providers.apple',
    # 'allauth.socialaccount.providers.linkedin',
    # 'allauth.socialaccount.providers.twitter_oauth2',

]

CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap4"

CRISPY_TEMPLATE_PACK = "bootstrap4"

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',

]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'template')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'
ACCOUNT_USER_MODEL_USERNAME_FIELD = None
# ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
SOCIALACCOUNT_QUERY_EMAIL = True


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    'default': {
        #'ENGINE': 'django.db.backends.sqlite3',
        #'NAME': BASE_DIR / 'db.sqlite3',
        'ENGINE': 'django.db.backends.postgresql',
        'HOST': os.environ.get("DB_HOST"),
        'NAME': os.environ.get("POSTGRES_DB"),
        'USER': os.environ.get("POSTGRES_USER"),
        'PASSWORD': os.environ.get("POSTGRES_PASSWORD"),
        'PORT': os.environ.get("PORT"),
    },
    'test': {
        'ENGINE': 'django.db.backends.postgresql',
        'HOST': os.environ.get("DB_HOST"),
        'NAME': os.environ.get("TEST_POSTGRES_DB"),
        'USER': os.environ.get("POSTGRES_USER"),
        'PASSWORD': os.environ.get("POSTGRES_PASSWORD"),
        'PORT': os.environ.get("PORT"),
    },
}

print(os.environ.get("PORT"))

if 'test' in sys.argv:
    DATABASES['default'] = DATABASES['test']


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static")


# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SOCIALACCOUNT_PROVIDERS = {
'facebook': {
'METHOD': 'oauth2', # Set to 'js_sdk' to use the Facebook connect SDK
'SDK_URL': '//connect.facebook.net/{locale}/sdk.js',
'SCOPE': ['email', 'public_profile'],
'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
'INIT_PARAMS': {'cookie': True},
'FIELDS': [
'id',
'first_name',
'last_name',
'middle_name',
'name',
'name_format',
'picture',
'short_name'
],
'EXCHANGE_TOKEN': True,
'LOCALE_FUNC': 'path.to.callable',
'VERIFIED_EMAIL': False,
'VERSION': 'v13.0',
'GRAPH_API_URL': 'https://graph.facebook.com/v13.0',
}
}
# Enregistrement pour l'application web
SOCIALACCOUNT_PROVIDERS = {
'google': {
'APP': {
'client_id': os.environ.get('web_client_id'),
'secret': os.environ.get('web_client_secret'),
'key': '',
}
}
}

# Enregistrement pour l'application Android
SOCIALACCOUNT_PROVIDERS = {
'google': {
'APP': {
'client_id': os.environ.get('android_client_id'),
'secret': ('android_client_secret'),
'key': '',
}
}
}

# Enregistrement pour l'application iOS
SOCIALACCOUNT_PROVIDERS = {
'google': {
'APP': {
'client_id': os.environ.get('ios_client_id'),
'secret': 'ios_client_secret',
'key': '',
}
}
}

AUTH_USER_MODEL = 'Mapapi.User'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'map-action.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'contact@map-action.com'
EMAIL_HOST_PASSWORD = 'Equipes55'