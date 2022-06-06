from django.contrib.auth.models import User
from django.test import TestCase
import jwt
from django.conf import settings
# Create your tests here.


class LogInTest(TestCase):
    def setUp(self):
        self.credentials = {
            'username': 'testuser',
            'password': 'secret',
            'email': 'test@gmail.com'
        }
        self.user = User.objects.create_superuser(**self.credentials)

    def test_login(self):
        response = self.client.get('/admin/', follow=True)
        self.assertRedirects(response, '/admin/login/?next=/admin/')
        self.assertEquals(response.status_code, 200)

        response = self.client.post('/admin/login/', self.credentials, follow=True)
        token = response.client.cookies.get('accesstoken').value
        self.assertIsNotNone(token)
        user_jwt = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=['HS256'],
            options={
                'verify_exp': True
            }
        )
        self.assertEqual(self.user.email, user_jwt['user_email'])
        self.assertEquals(response.status_code, 200)

    def test_logout(self):
        self.client.login(**self.credentials)

        response = self.client.get('/admin/', follow=True)
        self.assertEquals(response.status_code, 200)

        response = self.client.post('/admin/logout/', follow=True)
        self.assertEquals(response.status_code, 200)

        response = self.client.get('/admin/', follow=True)
        self.assertRedirects(response, '/admin/login/?next=/admin/')
