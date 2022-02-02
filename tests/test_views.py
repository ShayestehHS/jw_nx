import string
import random
from datetime import timedelta

from django.db.models import F
from knox.models import AuthToken

from jw_nx.tokens import AccessToken, RefreshToken
from tests.base import *


class TestViews(BaseTest):
    def test_login(self):
        """ Test that login view is creating access_token and refresh_token """
        user = self.create_test_user()
        ac, re = self.login(user)

    def test_login_invalid_password(self):
        """ Test login user with invalid password """
        user = self.create_test_user()
        payload = {
            'username': user.username,
            'password': 'invalid password'
        }

        with self.assertNumQueries(1):
            """
             Expected queries:
             1. Retrieve user by `username`(Password is check with python not DataBase)
            """
            response = self.client.post(login_url, data=payload, format='json')

        self.assertEqual(str(response.data['detail']), 'Unable to log in with provided credentials.')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify(self):
        """ Test 'verify' endpoint """
        user = self.create_test_user()
        ac, re = self.login(user)

        with self.assertNumQueries(1):
            """
             Expected queries:
             1- Retrieve user and knox token in validate_jkt
            """
            response = self.with_token(ac).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_verify_without_bearer(self):
        """ Test that authentication without bearer header is fail """
        with self.assertNumQueries(0):
            response = self.client.post(verify_url)

        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_with_wrong_jkt(self):
        """ Test verify endpoint with invalid knox_token(jkt claim) """
        ac, re = self.login()
        # Update jkt claim value
        access = AccessToken()
        access.payload = access.decode(ac)
        access.payload['jkt'] = ''.join(random.choice(string.ascii_lowercase) for x in range(64))

        with self.assertNumQueries(1):
            """
             Expected queries:
             1- Retrieve user and knox by invalid jkt token_key
            """
            response = self.with_token(str(access)).client.post(verify_url)

        self.assertEqual(str(response.data['detail']), 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_with_short_jkt(self):
        """ Test that verify endpoint with short 'jkt' claim """
        ac, re = self.login()
        # Update jkt claim value
        access = AccessToken()
        access.payload = access.decode(ac)
        access.payload['jkt'] = ''.join(random.choice(string.ascii_lowercase) for x in range(8))

        with self.assertNumQueries(0):
            response = self.with_token(str(access)).client.post(verify_url)

        self.assertEqual(str(response.data['detail']), "Invalid 'jtk' claim")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_with_expired_token(self):
        """ Test that expired knox token is not valid """
        user = self.create_test_user()
        ac, re = self.login(user)
        AuthToken.objects.filter(user=user).update(expiry=F('expiry') - (F('expiry') + timedelta(days=1)))

        response = self.with_token(ac).client.post(verify_url)

        self.assertEqual(str(response.data['detail']), 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_with_expired_access_token(self):
        """ Test that expired access token is not valid """
        ac, re = self.login()

        # Update expiration time
        access = AccessToken()
        access.payload = access.decode(ac)
        access.payload['exp'] -= 60 * 60 * 24  # One day ago

        with self.assertNumQueries(0):
            response = self.with_token(str(access)).client.post(verify_url)

        self.assertEqual(str(response.data['detail']), 'Signature has expired.')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_with_invalid_access_token(self):
        """ Test verify endpoint with invalid access token """
        ac, re = self.login()
        ac += '0'
        with self.assertNumQueries(0):
            response = self.with_token(ac).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(str(response.data['detail']), 'Error decoding signature.')

    def test_refresh(self):
        """ Test refresh endpoint with valid refresh_token that should return `new` and `valid` access_token """
        user = self.create_test_user()
        ac, re = self.login(user)
        payload = {"refresh_token": re}
        response = self.client.post(refresh_url, data=payload, format='json')

        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        check_response = self.with_token(response.data['access_token']).client.get(verify_url)
        self.assertEqual(check_response.status_code, status.HTTP_204_NO_CONTENT)

    def test_refresh_invalid(self):
        """ Test that refresh endpoint with invalid refresh token is not return access token """
        user = self.create_test_user()
        ac, re = self.login(user)
        re = f"{re}invalid"

        with self.assertNumQueries(0):
            payload = {'refresh_token': re}
            response = self.client.post(refresh_url, data=payload, format='json')

        self.assertEqual(str(response.data['detail']), 'Error decoding signature.')
        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_invalid_user_id(self):
        """ Test that refresh token with invalid user_id claim is not valid """
        ac, re = self.login()
        refresh = RefreshToken()
        refresh.validate_token(re)
        refresh.payload['user_id'] = 123

        with self.assertNumQueries(1):
            """
             Expected queries:
             1- Get knox token based on 'jkt', 'user_id' claim
            """
            payload = {'refresh_token': str(refresh)}
            response = self.client.post(refresh_url, data=payload, format='json')

        self.assertEqual(str(response.data['detail']), 'Invalid token')
        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_invalid_jtk(self):
        """ Test that refresh token with short `jtk` claim is not valid """
        ac, re = self.login()
        refresh = RefreshToken()
        refresh.validate_token(re)
        refresh.payload['jkt'] = ''.join(random.choice(string.ascii_lowercase) for x in range(64))

        with self.assertNumQueries(1):
            """
             Expected queries:
             1- Get knox token based on 'jkt', 'user_id' claim
            """
            payload = {'refresh_token': str(refresh)}
            response = self.client.post(refresh_url, data=payload, format='json')

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_short_jtk(self):
        """ Test that refresh token with short `jtk` claim is not valid """
        ac, re = self.login()
        refresh = RefreshToken()
        refresh.validate_token(re)
        refresh.payload['jkt'] = ''.join(random.choice(string.ascii_lowercase) for x in range(8))

        with self.assertNumQueries(0):
            payload = {'refresh_token': str(refresh)}
            response = self.client.post(refresh_url, data=payload, format='json')

        self.assertEqual(str(response.data['detail']), "Invalid 'jtk' claim")
        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_current(self):
        """ Test that logout endpoint is working correctly """
        ac, re = self.login()

        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user and knox token by 'jtk' claim
             2- Delete knox token from database
            """
            response = self.with_token(ac).client.post(logout_current_url)
        check_response = self.with_token(ac).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(check_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_other(self):
        """ Test that logout other endpoint is working correctly """
        user = self.create_test_user()
        ac1, re1 = self.login(user)
        ac2, re2 = self.login(user)
        ac3, re3 = self.login(user)

        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user and knox token by 'jtk' claim
             2- Delete excluded knox tokens
            """
            response = self.with_token(ac1).client.post(logout_other_url)
        response_check1 = self.with_token(ac1).client.post(verify_url)
        response_check2 = self.with_token(ac2).client.post(verify_url)
        response_check3 = self.with_token(ac3).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_check1.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response_check2.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_check3.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_all(self):
        """ Test that logout all endpoint is working correctly """
        user = self.create_test_user()
        ac1, re1 = self.login(user)
        ac2, re2 = self.login(user)
        ac3, re3 = self.login(user)

        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user and knox token by 'jtk' claim
             2- Delete excluded knox tokens
            """
            response = self.with_token(ac1).client.post(logout_all_url)
        response_check1 = self.with_token(ac1).client.post(verify_url)
        response_check2 = self.with_token(ac2).client.post(verify_url)
        response_check3 = self.with_token(ac3).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_check1.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_check2.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_check3.status_code, status.HTTP_401_UNAUTHORIZED)
