from rest_framework.exceptions import APIException, AuthenticationFailed


class TokenError(AuthenticationFailed):
    pass


class TokenBackendError(APIException):
    pass
