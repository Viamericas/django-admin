import jwt
import logging

from django.contrib.auth.models import AnonymousUser, User
from django.conf import settings
from django.contrib.auth.middleware import get_user
from jwt.exceptions import ExpiredSignatureError
from django.contrib.auth.views import auth_login
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ObjectDoesNotExist


class JWTAuthenticationMiddleware(MiddlewareMixin):
    logger = logging.getLogger('admin_login')

    def get_jwt_user(self, request):
        user_jwt = get_user(request)
        if user_jwt.is_authenticated:
            return user_jwt
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
        self.logger.info(f'USER AUTHENTICATED IS {request.user.is_authenticated}')
        if not request.user.is_anonymous and settings.SESSION_COOKIE_NAME not in request.COOKIES:
            auth_login(request, request.user)
            self.logger.info(f'Login user by token')
