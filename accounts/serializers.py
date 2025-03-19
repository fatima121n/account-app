from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import authenticate
from rest_framework import serializers
import pyotp
from . models import PasswordResetToken, User, generate_token


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}, 'email': {'required': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()     

    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def save(self):
        email = self.validated_data['email']
        try:
            user = User.objects.get(email=email)
            PasswordResetToken.objects.filter(user=user).delete()
            token = generate_token()
            reset_token = PasswordResetToken.objects.create(user=user, token=token)

            return {"user": user, "token": token}
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")



class PasswordResetVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=6) 


    def validate(self, data):
        email = data['email']
        token = data['token']

        try:
           user = User.objects.get(email=email)
           reset_token = PasswordResetToken.objects.get(user=user, token=token)
        except ObjectDoesNotExist:
           raise serializers.ValidationError("Invalid email or token.")
       
        token_status = reset_token.verify_token(token)
        
        if token_status != "Valid":
            raise serializers.ValidationError({
                "token": token_status
            })
        
        return data


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=6) 
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data['email']
        token = data['token']
        new_password = data['new_password']
        
        try:
            user = User.objects.get(email=email)
            reset_token = PasswordResetToken.objects.get(user=user, token=token)
        except ObjectDoesNotExist:
            raise serializers.ValidationError("Invalid email or token.")
       
        if not reset_token.verify_token(token):
            raise serializers.ValidationError({
                "token": "Invalid or expired token."
            })
        return data
        
    

    def save(self):
        email = self.validated_data['email']
        new_password = self.validated_data['new_password']

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
           
            PasswordResetToken.objects.filter(user=user).delete()
            return user
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        user = authenticate(email=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email or password.")
        

        data['user'] = user
        return data
    
class TOTPEnableDisableSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    enable = serializers.BooleanField(required=True)

    def validate(self, data):
        email = data['email']
        enable = data['enable']

        user = User.objects.get(email=email)
        if user.is_2fa_enabled == enable:
            raise serializers.ValidationError(f"2FA is already {'enabled' if enable else 'disabled'}")
        return data

    
    def save(self):
        email = self.validated_data['email']
        enable = self.validated_data['enable']
        
        try:
            user = User.objects.get(email=email)
            user.is_2fa_enabled = enable
            user.save()
            return user
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        
