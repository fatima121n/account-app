from django.urls import path
from . views import PasswordResetRequestView, RegisterUserView, PasswordResetVerifyView



urlpatterns = [
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/password/reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('auth/password/reset/verify/', PasswordResetVerifyView.as_view(), name='password-reset-verify')   
]


