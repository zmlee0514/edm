from datetime import timedelta
import os

# Base configuration
ENV = "base"
DEBUG = False
TESTING = False
SECRET_KEY = "secretkey"
SECURITY_PASSWORD_SALT = "passwordsalt"
INVITATION_EMAIL_EXPIRE_SECONDS = 3600
MAIL_SERVER = "smtp.gmail.com"
MAIL_PROT = 587
MAIL_USE_TLS = True
JSON_SORT_KEYS = False
JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=8)
JWT_BLACKLIST_ENABLED = True
JWT_BLACKLIST_TOKEN_CHECKS = ["refresh"]
REDIS_URL = "redis://localhost:6379/0"
ALLOWED_UPLOAD_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp', 'tiff'}
SQLALCHEMY_TRACK_MODIFICATIONS = False

# differ across environments
JWT_SECRET_KEY = os.urandom(64).hex()
SECRET_KEY = os.urandom(64).hex()
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://user:pass@localhost:3306/db"
MAIL_USERNAME = "sender@example.com"
MAIL_PASSWORD = "application password"  # application password
MAIL_SENDER_NAME = "sender name"
DOMAIN = "example.domain.com"

BCRYPT_LOG_ROUNDS = 13
WTF_CSRF_ENABLED = True
DEBUG_TB_ENABLED = False
DEBUG_TB_INTERCEPT_REDIRECTS = False