from rest_framework import serializers
from . models import Notification

class NotificationSerializer(serializers.ModelSerializer):
    sender_username = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            'id',
            'notification_type',
            'sender_username',
            'post',
            'comment',
            'is_read',
            'created_at'
        ]

    def get_sender_username(self, obj):
        return obj.sender.username if obj.sender else None