# Generated by Django 4.1 on 2023-06-14 07:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "consent_service",
            "0013_rename_condition_type_policybigtable_artifact_and_more",
        ),
    ]

    operations = [
        migrations.RemoveField(model_name="jurisdiction", name="jurisdiction_name",),
        migrations.RemoveField(model_name="jurisdiction", name="predicate",),
        migrations.AddField(
            model_name="jurisdiction",
            name="event",
            field=models.TextField(max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name="jurisdiction",
            name="event_type",
            field=models.TextField(max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="jurisdiction",
            name="condition",
            field=models.TextField(max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="jurisdiction",
            name="modality",
            field=models.TextField(max_length=1000, null=True),
        ),
    ]
