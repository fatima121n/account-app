from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from posts.models import Like, Comment
from accounts.models import Follow
from . models import Notification

User = settings.AUTH_USER_MODEL

# Follow notification
@receiver(post_save, sender=Follow)
def create_follow_notification(sender, instance, created, **kwargs):   
    if created and instance.follower != instance.following:
        Notification.objects.create(
            recipient=instance.following,
            sender=instance.follower,
            notification_type='follow'
        )

# Like Notification
@receiver(post_save, sender=Like)
def create_like_notification(sender, instance, created, **kwargs):
    if created and instance.user != instance.post.user:
        Notification.objects.create(
            recipient=instance.post.user,
            sender=instance.user,
            post=instance.post,
            notification_type='like'
        )

# Comment Notification
@receiver(post_save, sender=Comment)
def create_comment_notification(sender, instance, created, **kwargs):
    if created and instance.user != instance.post.user:
        Notification.objects.create(
            recipient=instance.post.user,
            sender=instance.user,
            post=instance.post,
            comment=instance,
            notification_type='comment'          
        ) 
