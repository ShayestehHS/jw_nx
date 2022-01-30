from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, exceptions

from jw_nx.settings import api_settings
from jw_nx.tokens import RefreshToken
from jw_nx.utils import get_username_field

User = get_user_model()
USERNAME_FIELD = get_username_field()


class PasswordField(serializers.CharField):
    def __init__(self, **kwargs):
        kwargs.setdefault('style', {})

        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True

        super().__init__(**kwargs)


class LoginSerializer(serializers.Serializer):
    default_error_messages = {'no_active_account': _('No active account found with the given credentials')}

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)

        self.fields[USERNAME_FIELD] = serializers.CharField()
        self.fields['password'] = PasswordField()

    @staticmethod
    def validate_user(user):
        if user is None:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)
        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.ValidationError(msg)

    def validate(self, attrs):
        auth_payload = {
            'request': self.context['request'],
            USERNAME_FIELD: attrs[USERNAME_FIELD],
            'password': attrs['password']
        }

        user = authenticate(**auth_payload)
        self.validate_user(user)
        refresh, access = RefreshToken().create_r_a(user)
        data = {'refresh_token': str(refresh), 'access_token': str(access)}

        if api_settings.JW_NX_UPDATE_LAST_LOGIN:
            update_last_login(None, user)

        if getattr(api_settings, 'JW_NX_RETURN_EXPIRATION', False):
            data.update({
                'access_token_expiration': access.get('exp'),
                'refresh_token_expiration': refresh.get('exp')
            })

        return data
