from django.urls import include, path
from rest_framework import routers

from jw_nx.views import JWTKnoxAPIViewSet, AdminAPIViewSet

router = routers.SimpleRouter(trailing_slash=False)
router.register(r'', JWTKnoxAPIViewSet, basename='jw-nx')
router.register(r'', AdminAPIViewSet, basename='admin')

urlpatterns = [
    path('', include(router.urls)),
]
