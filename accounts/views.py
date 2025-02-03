import base64
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
import qrcode
import io
import qrcode.constants
from . models import User
from .serializers import PasswordResetRequestSerializer,\
      UserRegistrationSerializer,PasswordResetVerifySerializer,\
      PasswordResetConfirmSerializer, LoginSerializer, VerifyTOTPSerializer



class RegisterUserView(CreateAPIView):
    serializer_class = UserRegistrationSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)
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
    
    

class PasswordResetVerifyView(CreateAPIView):
    serializer_class = PasswordResetVerifySerializer
    def post(self, request):
        serializer = PasswordResetVerifySerializer(data=request.data)

        if serializer.is_valid():
            return Response({'message': 'Token is valid'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PasswordResetConfirmView(CreateAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# Modifying Login View for 2FA
class LoginView(CreateAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        requires_otp = serializer.validated_data['requires_otp']

        if requires_otp:
            otp_code = request.data.get('otp_code')
            if not otp_code:
                return Response({"message": "OTP code is required."}, status=status.HTTP_400_BAD_REQUEST)

            totp = pyotp.TOTP(user.totp_key)
            if not totp.verify(otp_code):
                return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)
            
        
        # Log the user in immediately if OTP is not required
        login(request, user)
        return Response({"message": "Login successful."}, status=status.HTTP_200_OK)



# For two step verification
class GenerateQRCodeView(APIView):    
    def get(self, request):
        email = request.GET.get('email')
        if not email:
            return HttpResponse("User email is required.", status=400)
        
        user = get_object_or_404(User, email=email)

        if not user.totp_key:
            user.totp_key = pyotp.random_base32()
            user.save()

        # print("User TOTP key:", user.totp_key)

        otp_auth_url = f"otpauth://totp/Accounts:{user.email}?secret={user.totp_key}&issuer=Accounts"
        # print("OTP auth URL:", otp_auth_url)
   
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

        # Encode QR code as Base64
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
           
        # Return Base64 data as json
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
        
    