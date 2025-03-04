from django.urls import reverse
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.contrib.auth import login
from django.http import HttpResponse
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
import pyotp
import base64
import qrcode
import io
import logging
import qrcode.constants
from . models import PasswordResetToken, User
from .serializers import PasswordResetRequestSerializer,\
    UserRegistrationSerializer,PasswordResetVerifySerializer,\
    PasswordResetConfirmSerializer, LoginSerializer, VerifyTOTPSerializer, TOTPEnableDisableSerializer,\
    TOTPSetUpSerializer, DummySerializer


class HomePageView(APIView):
    def get(self, request):
        try:
            # Check if the database is reachable
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
            {'name': 'Generate QR Code', 'url': request.build_absolute_uri(reverse('generate-qrcode'))},
            {'name': 'Verify TOTP', 'url': request.build_absolute_uri(reverse('totp-verify'))},
            {'name': 'Enable/Disable 2FA', 'url': request.build_absolute_uri(reverse('enable-disable-2fa'))},
            {'name': 'Set Up TOTP', 'url': request.build_absolute_uri(reverse('setup-totp'))},
        ]

        return Response({
            'status': health_status,
            'message': health_message,
            'routes': routes
        })

logger = logging.getLogger(__name__)

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


# Test this too
class GenerateQRCodeView(CreateAPIView):
    serializer_class = DummySerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        if not email:
            return HttpResponse("User email is required.", status=status.HTTP_400_BAD_REQUEST)
        
        user = get_object_or_404(User, email=email)

        if not user.totp_key:
            user.totp_key = pyotp.random_base32()
            user.save()

        otp_auth_url = f"otpauth://totp/Accounts:{user.email}?secret={user.totp_key}&issuer=Accounts"   
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(otp_auth_url)
        qr.make(fit=True)

        # Convert QR code to an image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
           
        return Response({"qr_code": qr_base64}, status=status.HTTP_200_OK)

    
class VerifyTOTPView(CreateAPIView):
    serializer_class = VerifyTOTPSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp_code']

        try:
            user = get_object_or_404(User, email=email)
            totp = pyotp.TOTP(user.totp_key)

            if totp.verify(otp_code):
                return Response({"message": "TOTP code is valid."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid TOTP code."}, status=status.HTTP_400_BAD_REQUEST)
            
        except User.DoesNotExist:
            return Response({"message": "No user found."}, status=status.HTTP_404_NOT_FOUND)
        
class TOTPEnableDisableView(CreateAPIView):
    serializer_class = TOTPEnableDisableSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()
        return Response({"status": "2FA Enabled" if user.is_2fa_enabled else "2FA Disabled"}, 
                            status=status.HTTP_200_OK)
        
    

class TOTPSetUpView(CreateAPIView):
    serializer_class = TOTPSetUpSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.save()
        
        return Response(data, status=status.HTTP_200_OK)
    
