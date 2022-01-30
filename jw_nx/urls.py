from django.urls import include, path
from rest_framework import routers
from rest_framework_simplejwt.views import token_obtain_pair

from jw_nx.views import JWTKnoxAPIViewSet, AdminAPIViewSet

router = routers.SimpleRouter(trailing_slash=False)
router.register(r'', JWTKnoxAPIViewSet, basename='jw-nx')
router.register(r'', AdminAPIViewSet, basename='admin')

urlpatterns = [
    path('', include(router.urls)),
    path('login/', token_obtain_pair, name='login'),
]
