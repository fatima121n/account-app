from django.utils.timezone import now 
from django.contrib.auth import authenticate
from rest_framework import serializers
from . models import PasswordResetToken, User
from django.core.exceptions import ObjectDoesNotExist
import random



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
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value
    
    def save(self):
        email = self.validated_data['email']
        try:
            user = User.objects.get(email=email)  # Fetch the user object
        except ObjectDoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        token = random.randint(100000, 999999)  # Generate a 6-digit token
        PasswordResetToken.objects.update_or_create(user=user, defaults={'token': token})
        
        return {"user": user, "token": token}


    
       






        
    

