# Generated by Django 5.1.4 on 2025-01-06 07:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_user_otp_secret'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='otp_secret',
        ),
    ]
