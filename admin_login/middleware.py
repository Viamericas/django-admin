import jwt
from django.utils.functional import SimpleLazyObject
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser, User
from django.conf import settings
from django.contrib.auth.middleware import get_user
from jwt.exceptions import ExpiredSignatureError


class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.user = SimpleLazyObject(lambda: self.__class__.get_jwt_user(request))

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
                    settings.SECRET_KEY,
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

