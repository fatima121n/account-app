from django.urls import path
from . views import GenerateQRCodeView, PasswordResetRequestView, RegisterUserView, \
    PasswordResetVerifyView, PasswordResetConfirmView, LoginView, GenerateQRCodeView, VerifyTOTPView



urlpatterns = [
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/password/reset/request', PasswordResetRequestView.as_view(), name='password-reset'),
    path('auth/password/reset/verify/', PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('auth/2fa/generate-qr/', GenerateQRCodeView.as_view(), name='generate-qrcode'),
    path('auth/2fa/verify/', VerifyTOTPView.as_view(), name='totp-verify'),
]


