import jwt
import logging

from django.conf import settings
from jwt.exceptions import ExpiredSignatureError
from admin_login.utils import generate_access_token
from django.contrib.auth.views import auth_login
from django.utils.deprecation import MiddlewareMixin
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model


class JWTAuthenticationMiddleware(MiddlewareMixin):
    logger = logging.getLogger('admin_login')

    def process_request(self, request):
        if request.user.is_anonymous:
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
                    user_model = get_user_model()
                    user_jwt = user_model.objects.get(
                        email=user_jwt['user_email']
                    )
                    self.logger.info('Find user by token')
                    auth_login(request, user_jwt)
                    self.logger.info(f'Login user by token')
                except ExpiredSignatureError as error:
                    self.logger.error(error)
                    self.logger.info('Token is incorrect')
                except ObjectDoesNotExist as error:
                    self.logger.error(error)
                    self.logger.info('Not find user by token')

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


