from datetime import timedelta

from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'JW_NX', None)


DEFAULTS = {
    'JW_NX_LEEWAY': 0,
    'JW_NX_ISSUER': None,
    'JW_NX_JWK_URL': None,
    'JW_NX_AUDIENCE': None,
    'JW_NX_ALGORITHM': 'HS256',
    'JW_NX_VERIFYING_KEY': None,
    'JW_NX_RETURN_EXPIRATION': False,
    'JW_NX_UPDATE_LAST_LOGIN': False,
    'JW_NX_SECRET_KEY': settings.SECRET_KEY,
    'JW_NX_SIGNING_KEY': settings.SECRET_KEY,
    'JW_NX_REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'JW_NX_ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'JW_NX_ENCODE_HANDLER': 'jw_nx.utils.jwt_encode_handler',
    'JW_NX_DECODE_HANDLER': 'jw_nx.utils.jwt_decode_handler',
    'JW_NX_PAYLOAD_HANDLER': 'jw_nx.utils.jwt_payload_handler',
    'JW_NX_RESPONSE_PAYLOAD_HANDLER': 'jw_nx.utils.jwt_response_payload_handler',
    'JW_NX_LOGIN_AUTHENTICATION_CLASSES': ['rest_framework.authentication.BasicAuthentication',
                                           'rest_framework.authentication.SessionAuthentication']

}

IMPORT_STRINGS = (
    'JW_NX_LOGIN_AUTHENTICATION_CLASSES',
    'JW_NX_ENCODE_HANDLER',
    'JW_NX_DECODE_HANDLER',
    'JW_NX_PAYLOAD_HANDLER',
    'JW_NX_PAYLOAD_GET_USERNAME_HANDLER',
    'JW_NX_PAYLOAD_GET_TOKEN_HANDLER',
    'JW_NX_RESPONSE_PAYLOAD_HANDLER',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
