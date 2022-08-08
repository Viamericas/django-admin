Quick start
-----------
``install``::

	pip install git+https://github.com/ivanbat1/django-admin.git@0.0.28

1. Add "admin_login" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'admin_login',
    ]
2. add to your middleware ::

	...
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'admin_login.middleware.JWTAuthenticationMiddleware', <-- this that your need
	...

3. Set variables to settings ::

	ACCESS_TOKEN_SECRET_KEY = your_key
	ACCESS_TOKEN_COOKIE_DOMAIN = your_domain
