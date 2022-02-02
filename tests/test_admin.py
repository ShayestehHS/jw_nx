import random
from datetime import timedelta

from django.db.models import F
from knox.models import AuthToken

from tests.base import *

class AdminTest(BaseTest):
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
        with self.assertNumQueries(2):
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
        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user and knox token by 'jtk' claim
             2- Get average of expired counts of tokens for every user
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
        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve user and knox token by 'jtk' claim
             2- Get average of counts of created tokens for every user
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
        with self.assertNumQueries(2):
            """
             Expected queries:
             1- Retrieve knox token by 'jtk' claim
             2- Get average of active token counts for every user
            """
            response = self.with_token(ac).client.get(average_active_per_user_url)

        # Calculating average
        active_token_len_per_user = [len(pks) for name, pks in users_tokens.items()]
        average = sum(active_token_len_per_user) / len(users_list)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['Average active'], average)