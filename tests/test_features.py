import datetime
from datetime import timedelta

from tests.base import *
from jw_nx.tokens import AccessToken, RefreshToken
from jw_nx.settings import api_settings


class TestFeatures(BaseTest):

    def test_invalid_algorithm(self):
        """ Test setting invalid algorithm is raising error """
        ac, re = self.login()
        default_value = api_settings.JW_NX_ALGORITHM

        api_settings.JW_NX_ALGORITHM = 'invalid'
        response = self.with_token(ac).client.post(verify_url)
        api_settings.JW_NX_ALGORITHM = default_value

        self.assertIn('Unrecognized algorithm type', str(response.data['detail']))
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def test_verify_with_expired_access_token_and_leeway(self):
        """ Test that expired token is valid in leeway time """
        ac, re = self.login()
        # Update expiration time
        access = AccessToken()
        access.payload = access.decode(ac)
        access.payload['exp'] -= 24 * 60 * 60  # On day ago
        api_settings.JW_NX_LEEWAY = timedelta(days=1, seconds=10)

        with self.assertNumQueries(1):
            response = self.with_token(str(access)).client.post(verify_url)
            api_settings.JW_NX_LEEWAY = 0

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_return_expiration(self):
        """ Test that setting JW_NX_RETURN_EXPIRATION = True, login endpoint is return expiration """
        user = self.create_test_user()
        payload = {'username': user.username, 'password': self.password}

        api_settings.JW_NX_RETURN_EXPIRATION = True
        response = self.client.post(login_url, data=payload, format='json')
        api_settings.JW_NX_RETURN_EXPIRATION = False
        check_response = self.client.post(login_url, data=payload, format='json')

        self.assertIn('access_token_expiration', response.data)
        self.assertIn('refresh_token_expiration', response.data)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ####### check_response assertion
        self.assertNotIn('access_token_expiration', check_response.data)
        self.assertNotIn('refresh_token_expiration', check_response.data)
        self.assertIn('access_token', check_response.data)
        self.assertIn('refresh_token', check_response.data)
        self.assertEqual(check_response.status_code, status.HTTP_200_OK)

    def test_last_login(self):
        """ Test that setting JW_NX_UPDATE_LAST_LOGIN = True, after logging user in, last_update of user is update  """
        user = self.create_test_user()
        before_login_time = user.last_login or datetime.datetime.now()
        payload = {'username': user.username, 'password': self.password}

        api_settings.JW_NX_UPDATE_LAST_LOGIN = True
        response = self.client.post(login_url, data=payload, format='json')
        api_settings.JW_NX_UPDATE_LAST_LOGIN = False
        user.refresh_from_db()

        self.assertNotEqual(before_login_time, user.last_login)
        self.assertGreater(user.last_login, before_login_time)

    def test_refresh_expiration(self):
        """ Test that refresh_token expiration time, is equal to `JW_NX_REFRESH_TOKEN_LIFETIME` """
        user = self.create_test_user()
        payload = {'username': user.username, 'password': self.password}
        default_value = api_settings.JW_NX_REFRESH_TOKEN_LIFETIME

        api_settings.JW_NX_REFRESH_TOKEN_LIFETIME = timedelta(seconds=100)
        response = self.client.post(login_url, data=payload, format='json')
        api_settings.JW_NX_REFRESH_TOKEN_LIFETIME = default_value

        refresh = RefreshToken()
        payload = refresh.decode(response.data['refresh_token'])
        expiration_second = payload['exp'] - payload['iat']

        self.assertEqual(expiration_second, 100)

    def test_access_expiration(self):
        """ Test that access_token expiration time, is equal to `JW_NX_ACCESS_TOKEN_LIFETIME` """
        user = self.create_test_user()
        payload = {'username': user.username, 'password': self.password}
        default_value = api_settings.JW_NX_REFRESH_TOKEN_LIFETIME

        api_settings.JW_NX_ACCESS_TOKEN_LIFETIME = timedelta(minutes=0.5)
        response = self.client.post(login_url, data=payload, format='json')
        api_settings.JW_NX_REFRESH_TOKEN_LIFETIME = default_value

        access = AccessToken()
        refresh_payload = access.decode(response.data['refresh_token'])
        access_payload = access.decode(response.data['access_token'])
        expiration_second = access_payload['exp'] - refresh_payload['iat']

        self.assertEqual(expiration_second, timedelta(minutes=0.5).total_seconds())
