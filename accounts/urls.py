from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . views import UserViewSet, LoginViewSet
from django.contrib.auth import views as auth_views 


router = DefaultRouter()
router.register('register', UserViewSet, basename='register')
router.register('login', LoginViewSet, basename='login')


urlpatterns = [
    path('auth/', include(router.urls)),
    path('auth/password/reset/confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('auth/password/reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('auth/password/reset/complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('auth/', include('dj_rest_auth.urls')),
]

