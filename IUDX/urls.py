"""IUDX URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from consent_service import views as c_views

urlpatterns = [
    path('', c_views.index),
    path('home', c_views.home),
    path('apd/<apd_name>', c_views.apd),
    path('apd/<apd_name>/consent_dashboard', c_views.consent_dashboard),
    path('apd/<apd_name>/policy_dashboard', c_views.policy_dashboard),
    path('apd/<apd_name>/role_dashboard', c_views.role_dashboard),
    path('apd/<apd_name>/jurisdiction_dashboard', c_views.jurisdiction_dashboard),
    path('obligation-portal', c_views.obligation),
    path('signup', c_views.signup),
    path('admin/', admin.site.urls),
    path('create_APD/<name>/<apd_admin>', c_views.create_APD),
    path('create_policy/<name>/<modality>/<artifact>/<event>/<event_type>/<condition>/<action>/<source>',
         c_views.create_policy),
    path('access_resource/<role_capacity>/<apd_name>/<res_id>', c_views.access_resource),
    path('get_regulations/<jurisdiction_name>', c_views.get_regulations),
    path('create_regulation/<source>/<event>/<event_type>/<modality>/<condition>/<action>',
         c_views.create_regulation),
    path('inherit_jurisdiction/<jurisdiction_name>/<world_name>',
         c_views.inherit_jurisdiction),
    path('create_template/<template_name>', c_views.create_template),
    path('inherit_roles/<template_name>/<apd_name>',
         c_views.inherit_roles),
    path('create_template/<template_name>', c_views.create_template),
    path('create_User/<firstname>/<lastname>/<username>/<email>/<password>', c_views.create_User),
    path('assign_role/<userId>/<apd_name>/<role>', c_views.AssignRole),
    path('deassign_role/<userId>/<apd_name>/<role>', c_views.DeassignRole),
    path('create_admin/<userId>/<apd_name>', c_views.create_admin),
    path('view_APD_info/', c_views.view_APD_info),
    path('view_APD_policies/<apd_name>', c_views.view_APD_policies),
    path('view_regulations/', c_views.view_regulations),
    path('view_all_users/', c_views.view_all_users),
    path('view_all_templates/', c_views.view_all_templates),
    path('delete_policy/<policy_id>', c_views.delete_policy),
    path('delete_regulation/<reg_id>', c_views.delete_regulation),
    path('delete_user/<user_id>', c_views.delete_user),
    path('delete_apd/<apd_name>', c_views.delete_apd),
    path('applicable_policy/<res_name>', c_views.applicable_policies)
]
