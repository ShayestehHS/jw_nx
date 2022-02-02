import random
from datetime import timedelta

from django.db.models import F
from knox.models import AuthToken
from rest_framework.test import APITestCase

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status

from jw_nx.tokens import AccessToken, RefreshToken

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


class APIAuthTest(APITestCase):
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

    def test_login(self):
        """ Test that login view is creating access_token and refresh_token """
        with self.assertNumQueries(3):
            """
             Expected queries:
             1- Create user
             2- Retrieve user by authentication credentials
             3- Create knox token in validate method of LoginSerializer
            """
            user = self.create_test_user()
            ac, re = self.login(user)

    def test_verify(self):
        """ Test 'verify' endpoint """
        user = self.create_test_user()
        ac, re = self.login(user)

        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user by authentication credentials
             2- Retrieve knox token in validate_jkt
            """
            response = self.with_token(ac).client.post(verify_url)

            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_verify_without_bearer(self):
        """ Test that authentication without bearer header is fail """
        response = self.client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].title(), "Authentication Credentials Were Not Provided.")

    def test_verify_with_invalid_access_token(self):
        """ Test verify endpoint with invalid access token """
        user = self.create_test_user()
        ac, re = self.login(user)
        ac += '0'
        with self.assertNumQueries(0):
            response = self.with_token(ac).client.post(verify_url)

            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            self.assertEqual(response.data['detail'].title().lower(), 'Error decoding signature.'.lower())

    def test_verify_with_wrong_jkt(self):
        """ Test verify endpoint with invalid knox_token(jkt claim) """
        user = self.create_test_user()
        ac, re = self.login(user)
        # Update jkt claim value
        access = AccessToken()
        access.payload = access.decode(ac)
        access.payload['jkt'] = 'Invalid1Knox2Token'

        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user by authentication credentials
             2- Retrieve knox by invalid jkt token_key
            """
            response = self.with_token(str(access)).client.post(verify_url)

            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            self.assertEqual(response.data['detail'].title().lower(), 'Invalid Token'.lower())

    def test_verify_with_expired_token(self):
        """ Test that expired knox token is not valid """
        user = self.create_test_user()
        ac, re = self.login(user)
        AuthToken.objects.filter(user=user).update(expiry=F('expiry') - (F('expiry') + timedelta(days=1)))

        response = self.with_token(ac).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].title().lower(), 'Invalid Token'.lower())

    def test_verify_with_expired_access_token(self):
        """ Test that expired access token is not valid """
        user = self.create_test_user()
        ac, re = self.login(user)

        # Update expiration time
        access = AccessToken()
        access.payload = access.decode(ac)
        access.payload['exp'] -= 60 * 60 * 24  # One day ago

        with self.assertNumQueries(0):
            response = self.with_token(str(access)).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'].title().lower(), 'Signature has expired.'.lower())

    def test_refresh(self):
        """ Test refresh endpoint with valid refresh_token that should return `new` and `valid` access_token """
        user = self.create_test_user()
        ac, re = self.login(user)
        payload = {"refresh_token": re}
        response = self.client.post(refresh_url, data=payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)

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

        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.data['detail'].title(), 'Token Is Invalid Or Expired')
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

        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.data['detail'].title(), 'Invalid Token')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_invalid_jtk(self):
        """ Test that refresh token with invalid `jtk` claim is not valid """
        ac, re = self.login()
        refresh = RefreshToken()
        refresh.validate_token(re)
        refresh.payload['jkt'] = 'Invalid1Token2Key3'

        with self.assertNumQueries(1):
            """
             Expected queries:
             1- Get knox token based on 'jkt', 'user_id' claim
            """
            payload = {'refresh_token': str(refresh)}
            response = self.client.post(refresh_url, data=payload, format='json')

        self.assertNotIn('access_token', response.data)
        self.assertEqual(response.data['detail'].title(), 'Invalid Token')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_current(self):
        """ Test that logout endpoint is working correctly """
        user = self.create_test_user()
        ac, re = self.login(user)

        with self.assertNumQueries(5):
            """
             Expected queries:
             1- Retrieve user by authentication credentials
             2- Retrieve knox token by 'jtk' claim
             3- Delete knox token from database
             ----------
             4- Retrieve user by authentication credentials
             5- Retrieve knox token by 'jkt' claim
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

        with self.assertNumQueries(3):
            """
             Expected queries:
             1- Retrieve user by authentication credentials
             2- Retrieve knox token by 'jtk' claim
             3- Delete excluded knox tokens
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

        with self.assertNumQueries(3):
            """
             Expected queries:
             1- Retrieve user by authentication credentials
             2- Retrieve knox token by 'jtk' claim
             3- Delete excluded knox tokens
            """
            response = self.with_token(ac1).client.post(logout_all_url)
        response_check1 = self.with_token(ac1).client.post(verify_url)
        response_check2 = self.with_token(ac2).client.post(verify_url)
        response_check3 = self.with_token(ac3).client.post(verify_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_check1.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_check2.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response_check3.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_expired_tokens(self):
        """ Test that all expired tokens are deleting by this endpoint """
        user = self.create_test_user()
        self.login(user)
        self.login(user)
        self.login(user)
        admin = self.create_test_admin()
        ac, re = self.login(admin)

        # expire all tokens that belong to this user
        AuthToken.objects.filter(user_id=user.id).update(expiry=F('expiry') - (F('expiry') + timedelta(hours=10)))

        response = self.with_token(ac).client.post(delete_expired_tokens_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.data['Count'], 3)

    def test_average_per_user(self):
        """ Test average_per_user endpoint that is working correctly """
        users_token_count = {}
        expiry = timedelta(minutes=10)

        for i in range(0, random.randint(1, 20)):  # Create user
            user = self.create_test_user()
            users_token_count.update({user.username: 0})
            for j in range(0, random.randint(1, 50)):
                AuthToken.objects.create(user, expiry)
                users_token_count[user.username] += 1

        admin = self.create_test_admin()  # This line is create 1 user and 1 extra token
        ac, re = self.login(admin)
        with self.assertNumQueries(3):
            """
             Expected queries:
             1- Retrieve user by ID from 'user_id' claim
             2- Retrieve knox token by 'jtk' claim
             3- Get average of expired counts of tokens for every user
            """
            response = self.with_token(ac).client.get(average_per_user_url)

        # Calculating average
        filtered_vals = [value for name, value in users_token_count.items()]
        average = (sum(filtered_vals) + 1) / (len(filtered_vals) + 1)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['Average'], average)

    def test_average_expired_per_user(self):
        """ Test that 'average expired per user' endpoint is getting average count of expired tokens per user"""
        users_list = []  # ['username1', 'username2', .. ]
        users_tokens = {}  # {'username' :[id1, id2, id3, ...]},{},{}
        expiry = timedelta(minutes=10)
        users_count = random.randint(1, 20)
        for i in range(0, users_count):  # Create user
            user = self.create_test_user()
            users_list.append(user.username)
            users_tokens.update({user.username: []})
            pks = []
            for j in range(0, random.randint(1, 50)):
                instance, _ = AuthToken.objects.create(user, expiry)
                pks.append(instance.pk)
            users_tokens[user.username] = pks

        users_expired_token_pks = {}  # {'username1': ['pk1', 'pk2', 'pk3'], 'username2': [.....]}
        for username in users_list:  # Expire random token of users
            users_expired_token_pks.update({username: []})
            all_tokens_of_user = users_tokens[username]
            expired_tokens_of_user = users_expired_token_pks[username]
            random_list = random.sample(range(0, len(all_tokens_of_user)), random.randint(1, len(all_tokens_of_user)))
            for random_index in random_list:
                chosen_pk_of_user = all_tokens_of_user[random_index]
                expired_tokens_of_user.append(chosen_pk_of_user)
                # Expire token
                AuthToken.objects \
                    .filter(pk=chosen_pk_of_user) \
                    .update(expiry=F('expiry') - (F('expiry') + timedelta(hours=1)))
            users_expired_token_pks.update({username: expired_tokens_of_user})

        admin = self.create_test_admin()  # This line is create 1 user and 1 extra token
        ac, re = self.login(admin)
        with self.assertNumQueries(3):
            """
             Expected queries:
             1- Retrieve user by ID from 'user_id' claim
             2- Retrieve knox token by 'jtk' claim
             3- Get average of counts of created tokens for every user
            """
            response = self.with_token(ac).client.get(average_expired_per_user_url)

        # Calculating average
        expired_token_len_per_user = [len(pks) for name, pks in users_expired_token_pks.items()]
        average = sum(expired_token_len_per_user) / users_count

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['Average expired'], average)

    def test_average_active_per_user(self):
        """ Test that 'average active per user' endpoint is getting average count of active tokens per user"""
        users_list = []  # ['username1', 'username2', .. ]
        users_tokens = {}  # {'username' :[id1, id2, id3, ...]},{},{}
        expiry = timedelta(hours=10)
        users_count = random.randint(1, 20)
        for i in range(0, users_count):  # Create user
            user = self.create_test_user()
            users_list.append(user.username)
            pks = []
            for j in range(0, random.randint(1, 50)):
                instance, _ = AuthToken.objects.create(user, expiry)
                pks.append(instance.pk)

            users_tokens.update({user.username: pks})

        for username in users_list:  # Expire random token of users
            active_tokens_of_user = users_tokens[username]
            random_index = random.sample(range(0, len(active_tokens_of_user)), random.randint(1, len(active_tokens_of_user)))
            for index in sorted(random_index, reverse=True):
                chosen_pk_of_user = active_tokens_of_user.pop(index)
                # Expire token
                AuthToken.objects \
                    .filter(pk=chosen_pk_of_user) \
                    .update(expiry=F('expiry') - (F('expiry') + timedelta(hours=1)))
            if len(active_tokens_of_user) == 0:
                del users_tokens[username]
                users_list.remove(username)

        admin = self.create_test_admin()  # This line is create 1 user and 1 extra token
        ac, re = self.login(admin)
        with self.assertNumQueries(3):
            """
             Expected queries:
             1- Retrieve user by ID from 'user_id' claim
             2- Retrieve knox token by 'jtk' claim
             3- Get average of active token counts for every user
            """
            response = self.with_token(ac).client.get(average_active_per_user_url)

        # Calculating average
        active_token_len_per_user = [len(pks) for name, pks in users_tokens.items()]
        average = sum(active_token_len_per_user) / len(users_list)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['Average active'], average)
