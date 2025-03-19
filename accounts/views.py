from django.http import HttpResponse
from django.urls import reverse
from django.core.mail import send_mail
from django.contrib.auth import login, logout
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
import logging
import qrcode.constants
from . models import PasswordResetToken, User
from .serializers import PasswordResetRequestSerializer,\
    UserRegistrationSerializer,PasswordResetVerifySerializer,\
    PasswordResetConfirmSerializer, LoginSerializer, TOTPEnableDisableSerializer
import pyotp
import qrcode
from io import BytesIO
import base64


logger = logging.getLogger(__name__)


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
            {'name': 'Password Reset Verify', 'url': request.build_absolute_uri(reverse('password-reset-verify'))},
            {'name': 'Password Reset Confirm', 'url': request.build_absolute_uri(reverse('password-reset-confirm'))},
            {'name': 'Enable/Disable 2FA', 'url': request.build_absolute_uri(reverse('enable-disable-2fa'))},
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
    
    
# Test this!
class PasswordResetVerifyView(CreateAPIView):
    serializer_class = PasswordResetVerifySerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        if not PasswordResetToken.objects.filter(user=user).exists():
            return Response({"token": "Already used."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "Token is valid."}, status=status.HTTP_200_OK)


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

        return Response({'message': 'Login successful.'}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    def post(self, request):
        """
        Logs out the currently authenticated user.
        """
        # If using token authentication, delete the token
        if hasattr(request.user, 'auth_token'):
            request.user.auth_token.delete()

        # Log out the user
        logout(request)

        # Return a success response
        return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)
    

    

class TOTPEnableDisableView(CreateAPIView):
    serializer_class = TOTPEnableDisableSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()
        return Response({"status": "2FA Enabled" if user.is_2fa_enabled else "2FA Disabled"}, 
                            status=status.HTTP_200_OK)
        
    

class GenerateQRCodeView(APIView):
    def post(self, request):
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if not user.is_2fa_enabled:
            return Response({"error": "2FA is not enabled for this user."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.totp_key:
            user.totp_key = pyotp.random_base32()
            user.save()

        totp = pyotp.TOTP(user.totp_key)
        uri = totp.provisioning_uri(name=email, issuer_name="Accounts")

        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return Response({
            "provisioning_uri": uri,
            "qr_code": f"data:image/png;base64,{qr_base64}"
        }, status=status.HTTP_200_OK)

    
class VerifyOTPCodeView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        if not user.is_2fa_enabled:
            return Response({"error": "2FA is not enabled for this user."}, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(user.totp_key)
        if totp.verify(otp):
            return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "OTP is invalid."}, status=status.HTTP_400_BAD_REQUEST)