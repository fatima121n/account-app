from django.urls import path
from . views import HomePageView, \
    PasswordResetRequestView, RegisterUserView, \
    PasswordResetVerifyView, PasswordResetConfirmView, \
    LoginView, HomePageView, TOTPEnableDisableView, \
    LogoutView, GenerateQRCodeView



urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/password/reset/request', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('auth/password/reset/verify/', PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('auth/enable-disable-2fa/', TOTPEnableDisableView.as_view(), name='enable-disable-2fa'),
    path('auth/qrcode/', GenerateQRCodeView.as_view(), name='qr-code'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
]


