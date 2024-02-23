from django.urls import re_path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenBlacklistView,
    TokenVerifyView,
)

urlpatterns = [
    re_path('signup', views.signup, name='signup'),
    re_path('login', TokenObtainPairView.as_view(), name='login'),
    re_path('logout', TokenBlacklistView.as_view(), name='logout'),
    re_path('token_test', TokenVerifyView.as_view(), name='token_test'),
    re_path('token_refresh', TokenRefreshView.as_view(), name='token_refresh'),
]