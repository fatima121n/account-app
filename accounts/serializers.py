from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from . models import PasswordResetToken, User, generate_token



class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

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
        except ObjectDoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        # Using the generate_token function from the models
        token = generate_token()
        PasswordResetToken.objects.update_or_create(user=user, defaults={'token': token})
        
        return {"user": user, "token": token}


# New
class PasswordResetVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.IntegerField()

    def validate(self, data):
        email = data['email']
        token = data['token']

        try:
           user = User.objects.get(email=email)
           reset_token = PasswordResetToken.objects.get(user=user)
        except ObjectDoesNotExist():
           raise serializers.ValidationError("Invalid email or token.")
       
        token_status = reset_token.verify_token(token)
        if token_status == "Valid":
            return data
        elif token_status == "Expired":
            raise serializers.ValidationError("Token has expired.")
        else:
            raise serializers.ValidationError("Token is invalid.")



       






        
    

