
import os
from pathlib import Path
import environ
import dj_database_url

# 1. Initialize django-environ
env = environ.Env(
    # Set default values. DEBUG will be False if the environment variable is not set.
    DEBUG=(bool, False)
)

# 2. Define the base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# 3. Read the .env file if it exists (this is for your local development)
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# 4. Core Security Settings
SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')

# 5. Allowed Hosts Configuration (with Render failsafe)
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1', 'localhost'])
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)
print(f"--- [INFO] Allowed Hosts: {ALLOWED_HOSTS}")

# 6. Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic',
    'django.contrib.staticfiles',
    
    # 3rd Party Apps
    'rest_framework',
    'corsheaders',
    'rest_framework_simplejwt',

    # Local Apps
    'users',
    'appointments',
    'core',
    'admin_panel',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'hospital_project.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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
WSGI_APPLICATION = 'hospital_project.wsgi.application'

# 7. Database Configuration
db_url_raw = os.environ.get('DATABASE_URL') or env('DATABASE_URL', default=None)
if db_url_raw:
    db_url_clean = str(db_url_raw).strip().strip("'").strip('"')
    try:
        DATABASES = {
            'default': dj_database_url.parse(db_url_clean, conn_max_age=600)
        }
    except Exception:
        import re
        from urllib.parse import unquote
        match = re.match(r'^(?:postgres|postgresql)://([^:]+):(.*)@([^:/]+)(?::(\d+))?/(.*)$', db_url_clean)
        if match:
            u_user, u_pass, u_host, u_port, u_db = match.groups()
            if u_db and '?' in u_db:
                u_db = u_db.split('?')[0]
            DATABASES = {
                'default': {
                    'ENGINE': 'django.db.backends.postgresql',
                    'NAME': u_db or 'postgres',
                    'USER': unquote(u_user),
                    'PASSWORD': unquote(u_pass),
                    'HOST': u_host,
                    'PORT': u_port or '5432',
                }
            }
        else:
            DATABASES = {
                'default': dj_database_url.config(default=db_url_clean)
            }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# 8. Authentication
AUTH_USER_MODEL = 'users.User'
AUTHENTICATION_BACKENDS = [
    'users.backends.EmailOrPhoneBackend',
    'django.contrib.auth.backends.ModelBackend',
]
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# 9. Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# 10. Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 11. CORS (Cross-Origin Resource Sharing)
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=['http://localhost:3000', 'http://127.0.0.1:3000'])
print(f"--- [INFO] CORS Allowed Origins: {CORS_ALLOWED_ORIGINS}")

# 12. Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = f"Titiksha Hospitals <{env('EMAIL_HOST_USER')}>"

# 13. Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': ('rest_framework_simplejwt.authentication.JWTAuthentication',),
    'DEFAULT_PERMISSION_CLASSES': ('rest_framework.permissions.IsAuthenticated',)
}

# 14. Simple JWT (Optional: Customize token lifetime)
from datetime import timedelta
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
}