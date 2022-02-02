from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()
verify_url = reverse('jw-nx-verify')
login_url = reverse('jw-nx-login')
refresh_url = reverse('jw-nx-refresh')
logout_current_url = reverse('jw-nx-logout')
logout_other_url = reverse('jw-nx-logout-other')
logout_all_url = reverse('jw-nx-logout-all')
average_per_user_url = reverse('admin-average-all-per-user')
average_expired_per_user_url = reverse('admin-average-expired-per-user')
average_active_per_user_url = reverse('admin-average-active-per-user')
delete_expired_tokens_url = reverse('admin-delete-expired-tokens')


class BaseTest(APITestCase):
    user_count = 0
    password = "TestPasswordForAllUsers123"

    def create_test_user(self):
        """ Adds the default user to the database """
        user = User.objects.create_user(username=f'user{self.user_count}',
                                        email=f"user{self.user_count}@test.com",
                                        password=self.password)
        self.user_count += 1
        return user

    def create_test_admin(self):
        """ Adds the default admin to the database """
        admin = User.objects.create_superuser(username=f"admin{self.user_count}",
                                              email='admin@test.gmail', is_staff=True,
                                              password=self.password)
        self.user_count += 1
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.is_staff)
        return admin

    def with_token(self, token):
        if not token:
            self.client.credentials(HTTP_AUTHORIZATION=None)
            return self

        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
        return self

    def login(self, user=None):
        user = user if user is not None else self.create_test_user()
        payload = {
            'username': user.username,
            'password': self.password
        }
        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user by authentication credentials
             2- Create knox token in `validate` method of LoginSerializer
            """
            response = self.client.post(login_url, data=payload, format='json')
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        access = response.data['access_token']
        refresh = response.data['refresh_token']

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(access)
        self.assertIsNotNone(refresh)

        self.assertTrue(user.is_authenticated)
        return access, refresh