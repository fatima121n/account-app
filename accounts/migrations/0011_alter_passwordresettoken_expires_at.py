# Generated by Django 5.1.7 on 2025-05-29 13:37

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_alter_passwordresettoken_expires_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passwordresettoken',
            name='expires_at',
            field=models.DateTimeField(default=datetime.datetime(2025, 5, 30, 13, 37, 19, 95185, tzinfo=datetime.timezone.utc)),
        ),
    ]
