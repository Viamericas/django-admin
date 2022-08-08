# accounts.utils
import datetime
import jwt
from django.conf import settings
import logging


logger = logging.getLogger('admin_login')


def generate_access_token(user):
    access_token = None
    access_token_payload = {
        'user_email': user.email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.SESSION_COOKIE_AGE),
        'iat': datetime.datetime.utcnow(),
    }
    try:
        access_token = jwt.encode(access_token_payload,
                                  settings.ACCESS_TOKEN_SECRET_KEY, algorithm='HS256')
    except Exception as error:
        logger.error(error)
    return access_token
