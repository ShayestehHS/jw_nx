from django.db.models import Avg, Count
from django.utils.datetime_safe import datetime
from knox.models import AuthToken
from knox.settings import CONSTANTS
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.request import ForcedAuthentication
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from jw_nx.auth import JSONWebTokenKnoxAuthentication
from jw_nx.serializers import LoginSerializer
from jw_nx.settings import api_settings
from jw_nx.tokens import RefreshToken

response_payload_handler = api_settings.JW_NX_RESPONSE_PAYLOAD_HANDLER


class PerViewAuthenticatorMixin(object):
    authentication_classes = (JSONWebTokenKnoxAuthentication,)

    @staticmethod
    def get_authenticators_for_view(view_name):
        raise NotImplementedError("Must implement `get_authenticators_for_view` method for `JWTKnoxAPIViewSet` subclasses")

    def initialize_request(self, request, *args, **kwargs):
        """
        Returns the initial request object.
        """
        request = super(PerViewAuthenticatorMixin, self).initialize_request(request, *args, **kwargs)
        if not any([isinstance(auth, ForcedAuthentication) for auth in request.authenticators]):
            request.authenticators = self.get_authenticators()
        return request

    def get_authenticators(self):
        """
        First tries to get the specific authenticators for a view by
        calling `.get_authenticators_for_view`, but falls back on the
        class's authenticators.
        """
        authenticators = self.authentication_classes or ()

        if hasattr(self, 'action'):
            # action gets populated on the second time we are called
            per_view = self.get_authenticators_for_view(self.action)
            if per_view is not None:
                authenticators = per_view

        return [auth() for auth in authenticators]


class JWTKnoxAPIViewSet(PerViewAuthenticatorMixin, ViewSet):
    """This API endpoint set enables authentication via **JSON Web Tokens** (JWT).

    The provided JWTs are meant for a single device only and to be
    kept secret. The tokens may be set to expire after a certain time
    (see `get_token`). The tokens may be revoked in the server via the
    diverse logout endpoints. The JWTs are database-backed and may be
    revoked at any time.
    """
    permission_classes = (IsAuthenticated,)

    @staticmethod
    def get_authenticators_for_view(view_name):
        if view_name in ('login', 'refresh'):
            return api_settings.JW_NX_LOGIN_AUTHENTICATION_CLASSES

    def get_permissions(self):
        if self.action in ('login', 'refresh'):
            return [AllowAny()]
        return super(JWTKnoxAPIViewSet, self).get_permissions()

    def get_authenticators(self):
        """
        First tries to get the specific authenticators for a view by
        calling `.get_authenticators_for_view`, but falls back on the
        class's authenticators.
        """
        authenticators = self.authentication_classes or ()

        if hasattr(self, 'action'):
            # action gets populated on the second time we are called
            per_view = self.get_authenticators_for_view(self.action)
            if per_view is not None:
                authenticators = per_view
        return [auth() for auth in authenticators]

    # @action(methods=('get',), detail=False)
    # def debug_verify(self, request):
    #     """
    #     This view returns internal data on the token, the user and the current
    #     request.
    #
    #     **NOT TO BE USED IN PRODUCTION.**
    #     """
    #     token = request.auth[0]
    #     return Response(
    #         response_payload_handler(token, request.user, request),
    #         status=status.HTTP_200_OK)

    @action(methods=['post', ], detail=False)
    def login(self, request):
        """
        This view authenticate user via USERNAME_FIELD and password
        If credential is valid => Return token
        """
        serializer = LoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data)

    @action(methods=('get', 'post'), detail=False)
    def verify(self, request):
        """
        This view allows a third party to verify a web token.
            if 401_UNAUTHORIZED => Token is not valid
            if 204_NO_CONTENT   => Token is valid
        """
        return Response(None, status=status.HTTP_204_NO_CONTENT)

    @action(methods=('post',), detail=False)
    def refresh(self, request):
        """ Get and validate refresh_token from request and send new access token to user """
        token = request.data['refresh_token']
        refresh = RefreshToken()
        refresh.validate_token(token)
        access = refresh.access_token
        return Response({"access_token": str(access), "refresh_token": str(refresh)})

    @action(methods=('post',), detail=False)
    def logout(self, request):
        """
        Invalidates the current token, so that it cannot be used anymore
        for authentication.
        """
        AuthToken.objects.filter(token_key=request.auth).delete()
        return Response(None, status=status.HTTP_204_NO_CONTENT)

    @action(methods=('post',), detail=False)
    def logout_other(self, request):
        """
        Invalidates all the tokens except the current one, so that all other
        remaining open sessions get closed and only the current one is still
        open.
        """
        deleted_tokens = AuthToken.objects \
            .filter(user_id=request.user.id) \
            .exclude(token_key=request.auth[:CONSTANTS.TOKEN_KEY_LENGTH]) \
            .delete()

        return Response({"Deleted tokens": deleted_tokens[0]})

    @action(methods=('post',), detail=False)
    def logout_all(self, request):
        """
        Invalidates all currently valid tokens for the user, including the
        current session. This endpoint invalidates the current token, and you
        will need to authenticate again.
        """
        deleted_tokens = AuthToken.objects.filter(user_id=request.user.id).delete()
        return Response({"Deleted tokens": deleted_tokens[0]})


class AdminAPIViewSet(PerViewAuthenticatorMixin, ViewSet):
    permission_classes = [IsAdminUser]

    @staticmethod
    def get_authenticators_for_view(view_name):
        return None

    @action(methods=('post',), detail=False)
    def delete_expired_tokens(self, request):
        del_count = AuthToken.objects \
            .filter(expiry__lt=datetime.now()) \
            .delete()[0]
        return Response({'Count': del_count}, status.HTTP_204_NO_CONTENT)

    @action(methods=('get',), detail=False)
    def average_all_per_user(self, request):
        """ Get average knox token per user """
        subquery = AuthToken.objects \
            .values('user') \
            .annotate(count=Count('token_key')) \
            .aggregate(avg=Avg('count'))
        return Response({'Average': subquery['avg']})

    @action(methods=('get',), detail=False)
    def average_active_per_user(self, request):
        average = AuthToken.objects \
            .filter(expiry__gt=datetime.now()) \
            .exclude(user_id=self.request.user.id) \
            .values('user') \
            .annotate(count=Count('pk')) \
            .aggregate(avg=Avg('count'))
        return Response({'Average active': average['avg']})

    @action(methods=('get',), detail=False)
    def average_expired_per_user(self, request):
        average = AuthToken.objects \
            .filter(expiry__lt=datetime.now()) \
            .values('user') \
            .annotate(count=Count('pk')) \
            .aggregate(avg=Avg('count'))
        return Response({'Average expired': average['avg']})
