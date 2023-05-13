
import os
basedir = os.path.abspath(os.path.dirname(__file__))


class BaseConfig(object):
    """Base configuration."""
    ENV = "base"
    DEBUG = False
    TESTING = False
    
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'my_precious'

class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    ENV = "development"
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://edm:edm@localhost:3306/edm'
    
    WTF_CSRF_ENABLED = False
    DEBUG_TB_ENABLED = True


class TestingConfig(BaseConfig):
    """Testing configuration."""
    ENV = "testing"
    DEBUG = True
    TESTING = True
    
    BCRYPT_LOG_ROUNDS = 1
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite://'


class ProductionConfig(BaseConfig):
    """Production configuration."""
    ENV = "production"
    DEBUG = False
    
    SQLALCHEMY_DATABASE_URI = 'postgresql://localhost/example'
    DEBUG_TB_ENABLED = False
    STRIPE_SECRET_KEY = 'foo'
    STRIPE_PUBLISHABLE_KEY = 'bar'