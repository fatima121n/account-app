from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import authenticate
from rest_framework import serializers
from . models import PasswordResetToken, User, generate_token
from rest_framework.exceptions import AuthenticationFailed

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
            # Delete old tokens
            PasswordResetToken.objects.filter(user=user).delete()
            # Generate and save a new token
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

        if not email:
            raise serializers.ValidationError("Email is required.")
        if not token:
            raise serializers.ValidationError("Token is required.")

        try:
           user = User.objects.get(email=email)
           reset_token = PasswordResetToken.objects.get(user=user)
        except ObjectDoesNotExist:
           raise serializers.ValidationError("Invalid email or token.")
       
        token_status = reset_token.verify_token(token)
        error_message = {
            "Expired": "Token has expired.",
            "Invalid": "Token is invalid."
        }

        if token_status == "Valid":
            return data
        else:
            raise serializers.ValidationError(error_message.get(token_status), "Invalid token status.")
        


# New class for confirming password reset and changing the password
class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(max_length=6) 
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data['email']
        token = data['token']
        new_password = data['new_password']

        if not email:
            raise serializers.ValidationError("Email is required.")
        if not token:
            raise serializers.ValidationError("Token is required.")
        if not new_password:
            raise serializers.ValidationError("New Password is required.")
        
        try:
            user = User.objects.get(email=email)
            reset_token = PasswordResetToken.objects.get(user=user)
        except ObjectDoesNotExist:
            raise serializers.ValidationError("Invalid email or token.")

        token_status = reset_token.verify_token(token)
        error_message = {
            "Expired": "Token has expired.",
            "Invalid": "Token is invalid.",
        }

        if token_status == "Valid":
            return data
        else:
            raise serializers.ValidationError(error_message.get(token_status), "Invalid token status.")

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
        email = data['email']
        password = data['password']

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                raise AuthenticationFailed("Invalid credentials.")
        else:
            raise serializers.ValidationError("Email and password are required.")
        
        data['user'] = user
        return data

