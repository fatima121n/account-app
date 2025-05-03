import logging
from django.urls import reverse
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import login, logout
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import RetrieveUpdateAPIView
from .serializers import PasswordResetRequestSerializer,\
    UserRegistrationSerializer,\
    PasswordResetConfirmSerializer, LoginSerializer, UserSerializer


logger = logging.getLogger(__name__)

class UserProfileView(RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

class HomePageView(APIView):
    def get(self, request):
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            health_status = "healthy"
            health_message = "All Systems Operational."
        except Exception as e:
            health_status = "Unhealthy"
            health_message = f"Service Disruption: {str(e)}"

        routes = [
            {'name': 'Home', 'url': request.build_absolute_uri(reverse('home'))},
            {'name': 'Register', 'url': request.build_absolute_uri(reverse('register'))},
            {'name': 'Login', 'url': request.build_absolute_uri(reverse('login'))},
            {'name': 'Password Reset Request', 'url': request.build_absolute_uri(reverse('password-reset-request'))},
            {'name': 'Password Reset Confirm', 'url': request.build_absolute_uri(reverse('password-reset-confirm'))},
            {'name': 'Logout', 'url': request.build_absolute_uri(reverse('logout'))},
        ]

        return Response({
            'status': health_status,
            'message': health_message,
            'routes': routes
        })


class RegisterUserView(CreateAPIView):
    serializer_class = UserRegistrationSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user =serializer.save()
            logger.info(f"User registered successfullt: {user.email}")
            return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)
        logger.error(f"User registration failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PasswordResetRequestView(CreateAPIView):
    serializer_class = PasswordResetRequestSerializer
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.save()
            user = data['user']
            token = data['token']

            try:
                send_mail(
                    subject='Password Reset Token',
                    message=f'Your reset token is: {token}',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                )
            except Exception as e:
                return Response({'message': 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response({'message': 'Reset token sent to your email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class PasswordResetConfirmView(CreateAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LoginView(CreateAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        login(request, user)

        print(f"Session ID: {request.session.session_key}")
        return Response({'message': 'Login successful.'}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # If using token authentication, delete the token
        if hasattr(request.user, 'auth_token'):
            request.user.auth_token.delete()

        # Log out the user
        logout(request)

        # Return a success response
        return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)
    