# accounts.utils
import datetime
import jwt
from django.conf import settings


def generate_access_token(user):

    access_token_payload = {
        'user_email': user.email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.SESSION_COOKIE_AGE),
        'iat': datetime.datetime.utcnow(),
    }
    access_token = jwt.encode(access_token_payload,
                              settings.SECRET_KEY, algorithm='HS256')
    return access_token
