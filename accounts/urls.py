from django.urls import path
from . views import PasswordResetRequestView, RegisterUserView


urlpatterns = [
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/password/reset/', PasswordResetRequestView.as_view(), name='password-reset'),
   
]


