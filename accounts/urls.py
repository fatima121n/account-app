from django.conf import settings
from django.urls import path
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView
from . views import HomePageView, \
    PasswordResetRequestView, RegisterUserView, \
    PasswordResetConfirmView, \
    LoginView, HomePageView,LogoutView, UserProfileView, FollowUserView, UnfollowUserView

urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/password/reset/request', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/profile/', UserProfileView.as_view(), name='user-profile'),
    path('auth/follow/<str:username>/', FollowUserView.as_view(), name='follow-user'), 
    path('auth/unfollow/<str:username>/', UnfollowUserView.as_view(), name='unfollow-user'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

