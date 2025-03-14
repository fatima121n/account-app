from django.urls import path
from . views import GenerateQRCodeView, HomePageView, \
    PasswordResetRequestView, RegisterUserView, \
    PasswordResetVerifyView, PasswordResetConfirmView, \
    LoginView, GenerateQRCodeView, VerifyTOTPView, HomePageView, TOTPEnableDisableView, TOTPSetUpView, \
    LogoutView, hello



urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/password/reset/request', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('auth/password/reset/verify/', PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('auth/2fa/generate-qr/', GenerateQRCodeView.as_view(), name='generate-qrcode'),
    path('auth/2fa/verify/', VerifyTOTPView.as_view(), name='totp-verify'),
    path('auth/enable-disable-2fa/', TOTPEnableDisableView.as_view(), name='enable-disable-2fa'),
    path('auth/setup-totp/', TOTPSetUpView.as_view(), name='setup-totp'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('api/hello/', hello, name='hello')
]


