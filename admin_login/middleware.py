import jwt
from django.contrib.auth.models import AnonymousUser, User
from django.conf import settings
from django.contrib.auth.middleware import get_user
from jwt.exceptions import ExpiredSignatureError
from admin_login.utils import generate_access_token
from django.contrib.auth.views import auth_login
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject


class JWTAuthenticationMiddleware(MiddlewareMixin):

    @staticmethod
    def get_jwt_user(request):
        user_jwt = get_user(request)
        if user_jwt.is_authenticated:
            return user_jwt
        token = request.COOKIES.get('accesstoken', None)
        user_jwt = AnonymousUser()
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
            except ExpiredSignatureError as e:
                return user_jwt
        return user_jwt

    def process_request(self, request):
        user = self.get_jwt_user(request)
        if not user.is_anonymous:
            auth_login(request, user)
        request.user = SimpleLazyObject(lambda: get_user(request))

    def process_response(self, request, response):
        if not request.user.is_anonymous and not request.COOKIES.get('accesstoken'):
            access_token = generate_access_token(request.user)
            response.set_cookie(key='accesstoken', value=access_token, httponly=True,
                                domain=settings.SESSION_COOKIE_DOMAIN)

        if request.resolver_match.url_name and request.resolver_match.url_name == 'logout':
            response.delete_cookie(key='accesstoken', domain=settings.SESSION_COOKIE_DOMAIN)
        return response


