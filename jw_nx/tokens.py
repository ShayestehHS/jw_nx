import jwt
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from binascii import Error as binascii_Error

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from knox.crypto import hash_token
from knox.models import AuthToken
from knox.settings import CONSTANTS
from rest_framework import exceptions

from jw_nx.backends import TokenBackend
from jw_nx.exceptions import TokenBackendError, TokenError
from jw_nx.settings import api_settings
from jw_nx.utils import aware_utc_now, datetime_to_unix, datetime_from_unix

USER = get_user_model()
USER_ID_FIELD = api_settings.JW_NX_USER_ID_FIELD
try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        return a == b


class Token:
    """
    A class which validates and wraps an existing JWT or can be used to build a
    new JWT.
    """
    token_type = NotImplemented
    lifetime = NotImplemented
    claims = NotImplemented

    def __init__(self, current_time=None, *args, **kwargs):
        """
        !!!! IMPORTANT !!!! MUST raise a TokenError with a user-facing error
        message if the given token is invalid, expired, or otherwise not safe
        to use.
        """
        self.current_time = current_time if current_time is not None else aware_utc_now()
        self.token_backend = self.get_token_backend()
        self.payload = {}

    def __repr__(self):
        return repr(self.payload)

    def __getitem__(self, key):
        return self.payload[key]

    def __setitem__(self, key, value):
        self.payload[key] = value

    def __delitem__(self, key):
        del self.payload[key]

    def __contains__(self, key):
        return key in self.payload

    def get(self, key, default=None):
        return self.payload.get(key, default)

    @staticmethod
    def get_token_backend():
        return TokenBackend(api_settings.JW_NX_ALGORITHM, api_settings.JW_NX_SIGNING_KEY,
                            api_settings.JW_NX_VERIFYING_KEY, api_settings.JW_NX_AUDIENCE,
                            api_settings.JW_NX_ISSUER, api_settings.JW_NX_JWK_URL,
                            api_settings.JW_NX_LEEWAY)

    def __str__(self):
        """ Signs and returns a token as a base64 encoded string. """
        return self.token_backend.encode(self.payload)

    def verify_payload(self):
        for claim in self.payload:
            if claim not in self.claims:
                msg = _(f"Invalid claims in payload: {claim}")
                raise TokenError(msg)

    def verify_token_type(self):
        """
        Ensures that the token type claim is present and has the correct value.
        """
        try:
            token_type = self.payload['token_type']
        except KeyError:
            raise TokenError(_('Token has no type'))

        if self.token_type != token_type:
            raise TokenError(_('Token has wrong type'))

    def verify_exp(self):
        """
        Verify whether a timestamp value in the given claim has passed (since
        the given datetime value in `self.current_time`).
        Raises a TokenError with a user-facing error message if so.
        """
        claim = 'exp'
        try:
            claim_value = self.payload[claim]
        except KeyError:
            msg = _(f"Token has no '{claim}' claim")
            raise TokenError(msg)

        claim_time = datetime_from_unix(claim_value)
        if claim_time <= self.current_time:
            msg = _(f"Token '{claim}' claim has expired")
            raise TokenError(msg)

    def verify_user_id_field(self):
        user_id = self.payload['user_id']

        if not isinstance(user_id, int) or user_id < 1:
            msg = _(f"Invalid 'user_id' claim")
            raise TokenError(msg)

    def verify_jkt(self):
        knox_token = self.get('jkt')
        if isinstance(knox_token, str): knox_token = bytes(knox_token, 'utf-8')
        matched_token = None
        token = knox_token.decode()
        auth_tokens = AuthToken.objects \
            .filter(token_key=token[:CONSTANTS.TOKEN_KEY_LENGTH],
                    expiry__gte=aware_utc_now(), user_id=self.get('user_id'))
        for auth_token in auth_tokens:
            try:
                digest = hash_token(token, auth_token.salt)
            except (TypeError, binascii_Error):
                msg = _('Error in getting hash token')
                raise TokenError(msg)
            if digest == auth_token.digest:
                matched_token = auth_token
                break

        if matched_token is None:
            msg = _("Invalid token")
            raise TokenError(msg)
        return matched_token

    def set_token_type(self, claim='token_type'):
        self.payload[claim] = self.token_type

    def set_exp(self, claim='exp'):
        """
        Updates the expiration time of a token.

        See here:
        https://tools.ietf.org/html/rfc7519#section-4.1.4
        """
        lifetime: timedelta = self.lifetime
        from_time: datetime = self.current_time
        self.payload[claim] = datetime_to_unix(from_time + lifetime)

    def set_iat(self, claim='iat'):
        """
        Updates the time at which the token was issued.

        See here:
        https://tools.ietf.org/html/rfc7519#section-4.1.6
        """
        self.payload[claim] = datetime_to_unix(self.current_time)

    def set_jkt(self, user, jkt=None, claim='jkt'):
        """ Set JwtKnoxToken=jkt to payload """
        if jkt is None:
            _, jkt = AuthToken.objects.create(user, expiry=self.lifetime)
            bytes(jkt, 'utf-8')

        self.payload[claim] = jkt

    def set_user_id_field(self, user_id):
        """
        Set user_id to payload
        """
        self.payload[f'user_id'] = user_id

    @staticmethod
    def decode(token):
        try:
            payload = api_settings.JW_NX_DECODE_HANDLER(token)
        except jwt.ExpiredSignatureError:
            msg = _('Signature has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            msg = _('Invalid token error')
            raise exceptions.AuthenticationFailed(msg)
        except Exception as e:
            msg = _(f'Unknown error. Detail: {e}')
            raise exceptions.AuthenticationFailed(msg)

        if payload is None:
            msg = _('Error getting payload.')
            raise exceptions.AuthenticationFailed(msg)
        return payload


class AccessToken(Token):
    token_type = 'access'
    lifetime = api_settings.JW_NX_ACCESS_TOKEN_LIFETIME
    claims = ('token_type', 'exp', f'user_id', 'jti', 'jkt')

    def set_jti(self):
        """
        Populates the configured jti claim of a token with a string where there
        is a negligible probability that the same string will be chosen at a
        later time.

        See here:
        https://tools.ietf.org/html/rfc7519#section-4.1.7
        """
        self.payload['jti'] = uuid4().hex

    def verify_jti(self):
        try:
            UUID(self.payload['jti'], version=4)
        except KeyError:
            msg = _(f"Token has no 'jti' claim")
            raise TokenError(msg)
        except ValueError:
            msg = _("Invalid 'jti' claim")
            raise TokenError(msg)

    def verify_user(self, user):
        if self.payload['user_id'] != user.id:
            msg = _("User with user_id claim is not match together")
            raise TokenError(msg)

    def create_token(self, user, jkt):
        self.set_token_type()
        self.set_exp()
        self.set_jti()
        self.set_user_id_field(user.id)
        self.set_jkt(user, jkt)

    def validate_token(self, token, user):
        self.payload = self.decode(token)
        self.verify_payload()
        self.verify_token_type()
        self.verify_user_id_field()
        self.verify_user(user)
        self.verify_exp()
        self.verify_jti()
        self.verify_jkt()


class RefreshToken(Token):
    token_type = 'refresh'
    lifetime = api_settings.JW_NX_REFRESH_TOKEN_LIFETIME
    claims = ('token_type', 'exp', 'iat', 'jkt', f'user_id')
    is_verified: bool = False

    def verify_iat(self):
        try:
            claim_value = self.payload['iat']
        except KeyError:
            msg = _(f"Token has no 'iat' claim")
            raise TokenError(msg)
        if not isinstance(claim_value, int):
            msg = _("Invalid 'iat' claim")
            raise TokenError(msg)

    def create_token(self, user):
        self.user = user
        self.set_token_type()
        self.set_exp()
        self.set_iat()
        self.set_user_id_field(user.id)
        self.set_jkt(user)
        self.is_verified = True

    def validate_token(self, token):
        self.payload = self.decode(token)
        self.verify_token_type()
        self.verify_user_id_field()
        self.verify_exp()
        self.verify_iat()
        self.verify_jkt()
        self.is_verified = True

    @property
    def access_token(self):
        if not self.is_verified:
            raise TokenBackendError("Refresh token is not verified.")
        if not hasattr(self, 'user'):
            self.user = USER.objects.filter(id=self.payload['user_id']).only('id').first()
        access = AccessToken(current_time=self.current_time)
        access.create_token(self.user, self.payload['jkt'])
        return access

    def create_r_a(self, user):
        """ Create refresh token and access token at the same time """
        self.create_token(user)
        access = self.access_token
        return self, access
