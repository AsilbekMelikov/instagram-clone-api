# Generated by Django 5.1.2 on 2024-10-18 18:44

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("post", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="post",
            name="caption_en",
            field=models.TextField(
                null=True, validators=[django.core.validators.MaxLengthValidator(2000)]
            ),
        ),
        migrations.AddField(
            model_name="post",
            name="caption_uz",
            field=models.TextField(
                null=True, validators=[django.core.validators.MaxLengthValidator(2000)]
            ),
        ),
    ]