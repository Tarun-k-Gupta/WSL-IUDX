# Generated by Django 4.1.7 on 2023-08-08 12:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('consent_service', '0017_statements'),
    ]

    operations = [
        migrations.AddField(
            model_name='policybigtable',
            name='policy_id',
            field=models.TextField(default=1, max_length=100),
        ),
    ]