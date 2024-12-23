from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
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
    token = serializers.IntegerField()

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
        # Changed from here.
        error_message = {
            "Expired": "Token has expired.",
            "Invalid": "Token is invalid."
        }

        if token_status == "Valid":
            return data
        else:
            raise serializers.ValidationError(error_message.get(token_status), "Invalid token status.")
        
        