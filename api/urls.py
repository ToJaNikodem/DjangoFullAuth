from django.urls import re_path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenBlacklistView,
)

urlpatterns = [
    re_path('signup', views.signup, name='signup'),
    re_path('login', TokenObtainPairView.as_view(), name='login'),
    re_path('logout', TokenBlacklistView.as_view(), name='logout'),
    re_path('token_test', views.token_test, name='token_test'),
    re_path('token_refresh', TokenRefreshView.as_view(), name='token_refresh'),
    re_path('user_delete', views.user_delete, name="user_delete"),
]