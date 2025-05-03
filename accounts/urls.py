from django.urls import path
from . views import HomePageView, \
    PasswordResetRequestView, RegisterUserView, \
    PasswordResetConfirmView, \
    LoginView, HomePageView,LogoutView


urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/password/reset/request', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

]


