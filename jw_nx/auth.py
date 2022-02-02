from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from knox.settings import CONSTANTS
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from jw_nx.settings import api_settings
from jw_nx.tokens import AccessToken

User = get_user_model()
jwt_decode_handler = api_settings.JW_NX_DECODE_HANDLER


class JSONWebTokenKnoxAuthentication(BaseAuthentication):
    """
    Clients should authenticate by passing the JWT token in the "Authorization"
    HTTP header, prepended with the `Bearer`. For example:

      Authorization: Bearer abc.def.ghi
    """
    www_authenticate_realm = 'api'

    @staticmethod
    def validate_auth(auth):
        auth_len = len(auth)
        if auth_len != 2:
            if auth_len == 1:
                msg = _('Invalid Authorization header')
                raise exceptions.AuthenticationFailed(msg)
            elif auth_len > 2:
                msg = _('Invalid Authorization header. Credentials string should contain no spaces.')
                raise exceptions.AuthenticationFailed(msg)

        if auth[0] != b'Bearer':
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[0], auth[1]

    @staticmethod
    def validate_exp(payload):
        exp = payload.get('exp')
        if not exp:
            msg = _("Access token doesn't have expiration time.")
            raise exceptions.AuthenticationFailed(msg)
        if not isinstance(exp, int):
            msg = _("Invalid expiration type.")
            raise exceptions.AuthenticationFailed(msg)

    def authenticate_credentials(self, payload):
        """ Returns an active user that matches the payload's user id and token. """
        user_id = payload.get(f'user_id')

        if user_id is None:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            msg = _('Invalid signature.')
            raise exceptions.AuthenticationFailed(msg)

        if not user.is_active:
            msg = _('User inactive or deleted.')
            raise exceptions.AuthenticationFailed(msg)

        return user

    def authenticate(self, request):
        auth = get_authorization_header(request).split()  # [PREFIX, KEY]
        if len(auth) == 0:
            return None
        prefix, token = self.validate_auth(auth)
        access = AccessToken()
        access.validate_token(token)

        return access.user, access.payload['jkt'][:CONSTANTS.TOKEN_KEY_LENGTH]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of WWW-Authenticate
        header in a 401 Unauthorized response, or None if the
        authentication scheme should return 403 Permission Denied response.
        """

        return f'Bearer realm="{self.www_authenticate_realm}"'
