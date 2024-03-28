from . import views
from django.urls import re_path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenBlacklistView,
)

urlpatterns = [
    re_path('signup', views.signup, name='signup'), 
    re_path('login', TokenObtainPairView.as_view(), name='login'), 
    re_path('logout', TokenBlacklistView.as_view(), name='logout'),
    re_path('user_delete', views.user_delete, name="user_delete"),
    re_path('token_test', views.token_test, name='token_test'), 
    re_path('token_refresh', TokenRefreshView.as_view(), name='token_refresh'),
    re_path('email_verification', views.email_verification, name='email_verification'), 
    re_path('resend_verification_email', views.resend_verification_email, name='resend_verification_email'), 
    re_path('nickname_change', views.nickname_change, name='nickname_change'), 
    re_path('password_change', views.password_change, name='password_change'), 
    re_path('send_password_reset', views.send_password_reset, name='send_password_reset'),
    re_path('password_reset', views.password_reset, name='password_reset'),
]