from admin_login.utils import generate_access_token
from django.http.response import HttpResponseRedirect
from django.contrib.auth.views import LoginView, auth_login, LogoutView
from django.conf import settings


class CustomloginView(LoginView):
    def form_valid(self, form, *args, **kwargs):
        user = form.get_user()
        auth_login(self.request, user)
        response = HttpResponseRedirect(self.get_success_url())

        access_token = generate_access_token(user)

        response.set_cookie(key='accesstoken', value=access_token, httponly=True, domain=settings.SESSION_COOKIE_DOMAIN)

        return response


class CustomLogoutView(LogoutView):
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        response.delete_cookie(key='accesstoken', domain=settings.SESSION_COOKIE_DOMAIN)
        return response