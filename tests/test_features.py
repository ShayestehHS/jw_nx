from datetime import timedelta

from jw_nx.settings import api_settings
from jw_nx.tokens import AccessToken
from tests.base import *


class TestFeatures(BaseTest):

    def test_invalid_algorithm(self):
        """ Test setting invalid algorithm is raising error """
        ac, re = self.login()
        api_settings.JW_NX_ALGORITHM = 'Invalid'

        response = self.with_token(ac).client.post(verify_url)
        api_settings.JW_NX_ALGORITHM = 'HS256'

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