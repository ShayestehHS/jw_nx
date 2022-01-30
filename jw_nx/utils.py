from typing import Optional

from django.conf import settings
from django.utils.functional import lazy
from django.utils.module_loading import import_string
from django.utils.timezone import is_naive, make_aware, utc
from jwt import encode as jwt_encode, decode as jwt_decode
from uuid import UUID
from calendar import timegm
from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from knox.models import AuthToken, User

from jw_nx.settings import api_settings

sha = import_string('cryptography.hazmat.primitives.hashes.SHA512')


def make_utc(dt):
    if settings.USE_TZ and is_naive(dt):
        return make_aware(dt, timezone=utc)

    return dt


def aware_utc_now():
    return make_utc(datetime.utcnow())


def datetime_to_unix(dt):
    return timegm(dt.utctimetuple())


def datetime_from_unix(ts):
    return make_utc(datetime.utcfromtimestamp(ts))


def jwt_encode_handler(payload):
    return jwt_encode(payload, api_settings.JW_NX_SECRET_KEY, api_settings.JW_NX_ALGORITHM)


def jwt_join_header_and_token(token):
    return f"Bearer {token}"


def jwt_response_payload_handler(token):
    return {'token': jwt_join_header_and_token(token), }


def get_username_field():
    try:
        return get_user_model().USERNAME_FIELD
    finally:
        return 'username'


def get_username(user):
    try:
        return user.get_username()
    finally:
        return user.username


def create_auth_token(user, expiry: timedelta):
    _, token = AuthToken.objects.create(user=user, expiry=expiry)  # Create knox token
    payload = jwt_payload_handler(user, token, expiry)

    return jwt_encode_handler(payload)


def jwt_decode_handler(token):
    options = {'verify_exp': True, }

    return jwt_decode(
        token,
        api_settings.JW_NX_SECRET_KEY,
        algorithms=api_settings.JW_NX_ALGORITHM,
        options=options,
        leeway=api_settings.JW_NX_LEEWAY,
        audience=api_settings.JW_NX_AUDIENCE,
        issuer=api_settings.JW_NX_ISSUER,
    )


def jwt_payload_handler(user: User, token: str, expiry: Optional[timedelta]):
    username_field = get_username_field()
    username = get_username(user)
    now = datetime.utcnow()
    payload = {
        username_field: username,
        'iat': timegm(now.utctimetuple()),  # Issued At Time => unix timestamp
        'jti': token,
        # OPTIONALS
        # More info => https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#payload-claims
        # user_id : user.pk
        # exp : now + expiry
        # aud : JWT_AUDIENCE
        # iss : JWT_ISSUER
    }

    if expiry:
        payload['exp'] = now + expiry

    if isinstance(user.pk, UUID):
        payload['user_id'] = str(user.pk)

    jwt_audience = api_settings.JW_NX_AUDIENCE
    if jwt_audience is not None:
        payload['aud'] = jwt_audience

    jwt_issuer = api_settings.JW_NX_ISSUER
    if jwt_issuer is not None:
        payload['iss'] = jwt_issuer

    return payload


def format_lazy(s, *args, **kwargs):
    return s.format(*args, **kwargs)


format_lazy = lazy(format_lazy, str)
