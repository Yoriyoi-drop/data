"""
Sentry Error Tracking Integration
"""
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from app.core.config import settings

def init_sentry():
    """Initialize Sentry error tracking"""
    if not settings.DEBUG and hasattr(settings, 'SENTRY_DSN'):
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            integrations=[
                FastApiIntegration(auto_enabling_integrations=False),
                SqlalchemyIntegration(),
                RedisIntegration(),
            ],
            traces_sample_rate=0.1,
            environment="production" if not settings.DEBUG else "development",
            release=settings.VERSION,
        )

def capture_exception(error: Exception, extra_data: dict = None):
    """Capture exception with additional context"""
    with sentry_sdk.configure_scope() as scope:
        if extra_data:
            for key, value in extra_data.items():
                scope.set_extra(key, value)
        sentry_sdk.capture_exception(error)