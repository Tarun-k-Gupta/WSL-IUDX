from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class APD(models.Model):
    apd_name = models.CharField(max_length=64, null=False, unique=True)
    template_roles = models.JSONField(null=True, blank=True)
    apd_admin = models.ForeignKey(
        User, default=1, verbose_name="User Id", on_delete=models.SET_DEFAULT)

    def __str__(self):
        return self.name


class PolicyBigTable(models.Model):
    apd_name = models.TextField(null=False, max_length=1000)
    modality = models.TextField(null=True, max_length=1000)
    event = models.TextField(null=True, max_length=1000)
    artifact = models.TextField(null=True, max_length=1000)
    condition = models.TextField(null=True, max_length=1000)
    event_type = models.TextField(null=True,max_length=1000)
    action = models.TextField(null=True,max_length=1000)
    Source = models.TextField(null=True, max_length=1000)
    policy_id = policy_id = models.TextField(default=1, max_length=100)
    # def __str__(self):
    # return self.user.name


class Resource(models.Model):
    documents = models.FileField(upload_to='document/')
    document_type = models.TextField(null=True)
    document_name = models.TextField(null=True)
    consent_artefact = models.TextField(null=True, blank=True)
    resource_apd = models.TextField(max_length=1000)
    resource_inode = models.JSONField(null=True, blank=True)


class Jurisdiction(models.Model):
    event = models.TextField(null=True, max_length=1000)
    event_type = models.TextField(null=True,max_length=1000)
    condition = models.TextField(null=True, max_length=1000)
    action = models.TextField(null=True,max_length=1000)
    modality = models.TextField(null=True, max_length=1000)
    Source = models.TextField(null=True, max_length=1000)

class user_role_info(models.Model):
    user = models.ForeignKey(
        User, default=1, verbose_name="User Id", on_delete=models.SET_DEFAULT)
    # username = models.TextField(max_length=100, unique=True)
    # password = models.TextField(max_length=100)
    role = models.TextField(max_length=100)
    # is_admin = models.BooleanField()
    # apd = models.TextField(max_length= 100, null=True)


class Template(models.Model):
    template_name = models.CharField(max_length=64, null=False, unique=True)
    # The JSON will be in the form of "predicate":"Role Name"
    template_roles = models.JSONField(null=True, blank=True)

class Statements(models.Model):
    policy_id = models.TextField(max_length=100)
    statements = models.TextField(max_length=2000)
    modality = models.TextField(default='N',max_length=50)

class Regulations(models.Model):
    reg_id = models.TextField(max_length=100)
    statements = models.TextField(max_length=2000)
    modality = models.TextField(default='N',max_length=50)
