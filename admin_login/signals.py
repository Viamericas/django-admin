from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.conf import settings
from admin_login.utils import generate_access_token
from django.http import HttpResponse


def user_logged_in_hook(sender, user, request, **kwargs):
    access_token = generate_access_token(user)
    response = HttpResponse()
    response.set_cookie(
        key='accesstoken',
        value=access_token,
        httponly=True,
        domain=settings.ACCESS_TOKEN_COOKIE_DOMAIN,
    )
    return response


def user_logged_out_hook(sender, user, request, **kwargs):
    response = HttpResponse()
    response.delete_cookie(
        key='accesstoken',
        domain=settings.ACCESS_TOKEN_COOKIE_DOMAIN,
    )
    return response


user_logged_in.connect(user_logged_in_hook)
user_logged_out.connect(user_logged_out_hook)