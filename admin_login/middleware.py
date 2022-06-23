import jwt
import logging

from django.contrib.auth.models import AnonymousUser, User
from django.conf import settings
from django.contrib.auth.middleware import get_user
from jwt.exceptions import ExpiredSignatureError
from admin_login.utils import generate_access_token
from django.contrib.auth.views import auth_login
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ObjectDoesNotExist


class JWTAuthenticationMiddleware(MiddlewareMixin):
    logger = logging.getLogger('admin_login')

    def get_jwt_user(self, request):
        user_jwt = get_user(request)
        token = request.COOKIES.get('accesstoken', None)
        if token is not None:
            try:
                user_jwt = jwt.decode(
                    token,
                    settings.ACCESS_TOKEN_SECRET_KEY,
                    algorithms=['HS256'],
                    options={
                        'verify_exp': True
                    }
                )
                user_jwt = User.objects.get(
                    email=user_jwt['user_email']
                )
                self.logger.info('Find user by token')
            except ExpiredSignatureError as error:
                self.logger.error(error)
                self.logger.info('Token is incorrect')
            except ObjectDoesNotExist as error:
                self.logger.error(error)
                self.logger.info('Not find user by token')
        return user_jwt

    def process_request(self, request):
        if request.user.is_anonymous and settings.SESSION_COOKIE_NAME not in request.COOKIES:
            user = self.get_jwt_user(request)
            if not user.is_anonymous:
                auth_login(request, user)
                self.logger.info(f'Login user by token')

    def process_response(self, request, response):
        user = request.user
        if 'admin/login' in request.path and user.is_authenticated:
            access_token = generate_access_token(user)
            response.set_cookie(
                key='accesstoken',
                value=access_token,
                httponly=True,
                domain=settings.ACCESS_TOKEN_COOKIE_DOMAIN,
            )
            self.logger.info(f'Create access token')

        if 'admin/logout' in request.path:
            response.delete_cookie(
                key='accesstoken',
                domain=settings.ACCESS_TOKEN_COOKIE_DOMAIN,
            )
            self.logger.info(f'Delete access token')
        return response


