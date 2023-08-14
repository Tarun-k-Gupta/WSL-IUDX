from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.core.serializers import serialize
import re
import json
from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
import base64
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .models import *
import xml.etree.ElementTree as et
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, Comment
import time
from django.template.response import TemplateResponse

# Create your views here.


class mandate:
    all_mandates = []  # It is of the form policy ID:mandate_name
    current_APD = []

    def __init__(self):
        self.obligation_role = []
        self.mandate_status = False
        self.predicate_constituents = {}
        
        self.applicable_policy_ids = []
        self.obligated_policies = []
        self.permitted_roles = []
        self.forbidden_roles = []

        self.obligation_tracker = {}
        self.accessible_resources = []

all_policies_checker = {}

@csrf_exempt
def create_APD(request, name, apd_admin):
    if request.method == 'POST':
        user = User.objects.all()
        for i in user.iterator():
            if(i.id == int(apd_admin)):
                w = APD(apd_name=name, apd_admin=i)
                w.save()
        if user_role_info.objects.filter(user_id=apd_admin).exists():
            c = user_role_info.objects.filter(user_id=int(apd_admin))[0].role
            if isinstance(c, str):
                c = eval(c)
            c[f'{name}'] = ['admin']
            updater = user_role_info.objects.filter(user_id=int(apd_admin)).update(role=c)
        else:
            role = user_role_info(user_id=apd_admin,role={f'{name}':['admin']})
            role.save()
    return HttpResponse(status=201)


@csrf_exempt
def create_policy(request, name, modality, artifact,event,event_type,condition, action, source):
    if request.method == "POST":
        # name = request.GET.get('name')
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            all_apd = APD.objects.get(apd_name=name)
        else:
            return HttpResponse("Invalid Login", status=401)

        if (user is not None) and (all_users.id == all_apd.apd_admin_id):
            p = PolicyBigTable(apd_name=name, modality=modality, artifact=artifact,event=event,event_type=event_type,
                               condition=condition, action = action, Source=source)
            p.save()
            return HttpResponse("OK", status=201)
        else:
            return HttpResponse("Not Authorised Admin of APD "+name, status=401)



# @csrf_exempt
# def check_policy(request,all_policies_checker):
    

#     def check_location(policy):
#             conditions = policy.condition.split(';')
#             print(conditions)
#             for i in conditions:
#                 # i.replace('\n\r',"")
#                 print(i)
#                 # check_property(i)  

def negation(modality):
    match(modality):
        case 'P':
            modality = 'F'
        case 'O':
            modality = 'P'
        case 'F':
            modality = 'P'
    return modality
        

def match_keyword(condition,key,value,obg_tracker):
        keyword = condition.split(':')[1]
        param1 = condition.split(':')[2]
        if keyword == "has":
            has(param1,key,obg_tracker,condition)
        elif keyword == "has_tag":
            has_tag(param1,value,obg_tracker,condition)
        elif keyword =="match":
            param2 = condition.split(':')[3]
            if key and value:
                match_params(param1,key,param2,value,obg_tracker,condition)
        elif keyword =="not_match":
            param2 = condition.split(':')[3]
            if key and value:
                not_match_params(param1,key,param2,value,obg_tracker,condition)
            else:
                obg_tracker[condition] = 'True'
        else:
            print("Invalid Keyword")
        return obg_tracker

def has(param1,key,obg_tracker,condition):
        if(param1 == key):
            obg_tracker[condition] = 'True'
        return obg_tracker

def has_tag(param1,tag,obg_tracker,condition):
        # print(param1,val2)
        if param1 == tag or param1 in tag:
            print(condition)
            obg_tracker[condition] = 'True'
            print("Tag has matched")
        else:
            print("Not matched")
        return obg_tracker

def match_params(param1,key,param2,value,obg_tracker,condition):
        # print(param1,param2,key,value)
        if param1 == key and param2 == value:
            print("At match_params",param1,param2,key,value)
            obg_tracker[condition] = 'True'
        if param1 == 'role':
            print("At role check")
            obg_tracker[condition] = 'True'
        return obg_tracker

def not_match_params(param1,key,param2,value,obg_tracker,condition):
        # print(param1,param2,key,value)
        if param1 == key and param2 == value:
            obg_tracker[condition] = 'False'
        else:
            obg_tracker[condition] = 'True'
        return obg_tracker


def check_condition(request,res_inode,role_condition_list):
    obg_tracker = {}
    for j in role_condition_list:
        condition_list = j.split(';')
        condition_list.pop()

        for i in condition_list:
            obg_tracker[i] = 'False'
            print(i)
            location = i.split(':')[0]
            keyword = i.split(':')[1]
            param1 = i.split(':')[2]
            if location == "request" or location == " request":
                #check purpose code value, role value, data seeking form, check value for a key matches value for a condition
                 # print("At request check")
                if keyword == "match" and param1 == "role":
                    obg_tracker[i] = 'True'
                    continue
                body_unicode = request.body.decode('utf-8')
                body = json.loads(body_unicode)
                for key,value in body.items():
                    match_keyword(i,key,value)
            elif location == "artifact" or location == " artifact":
                print("At artifact")
                print(res_inode)
                match_keyword(i,keyword,res_inode)
            elif location == "apd" or location == " apd":
                print("At apd")
            else:
                continue
    return obg_tracker   

def generate_consent(obg_fulfilled,res_name,apd_name,role_capacity):
    #generates a consent template for the applicable policies
        post_policy_ids = []
        policy_ids = PolicyBigTable.objects.filter(apd_name=apd_name)
        res = Resource.objects.filter(document_name=res_name,resource_apd=apd_name)
        res_id = res[0].id
        for i in res.iterator():
            # res_name = i.document_name
            inode = i.resource_inode
            if isinstance(inode,str):
                inode = eval(inode)
            # for key,value in inode.items():
            #     res_inode=inode['tag']
        # all_policies_checker = serialize('json', all_policies)
        for i in policy_ids.iterator():
            if i.event_type == 'post':
                artifact = i.artifact
                # print(artifact)
                if res_name == artifact:
                    post_policy_ids.append(i)
                    print(i)
                    continue
        consent_template = create_consent_xml(post_policy_ids,res_id,obg_fulfilled,role_capacity)
        res = Resource.objects.get(id=res_id)
        res.consent_artefact = consent_template
        res.save() 
        return consent_template

def access_resource(request, role_capacity, apd_name, res_id):
    total_list = []
    role_cond_list = []
    policy_evaluation = {}
    policy_ids = []
    instructions = []

    auth = request.META['HTTP_AUTHORIZATION'].split()
    auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
    username, password = auth_decoded.split(":")
    user = authenticate(username=username, password=password)
    user_roles = []
    condition_list = []
    post_policy_ids = []
    # reg_list = []
    if (user is not None):
        user = User.objects.get(username=username)
        role_dict = user_role_info.objects.filter(user_id = user.id)[0].role
        if isinstance(role_dict, str):
            role_dict = eval(role_dict)
        all_users_role_info = role_dict[f'{apd_name}']
        user_roles.extend(all_users_role_info)
        print(user_roles)
        if(f'{role_capacity}' in user_roles):
            all_policies = PolicyBigTable.objects.filter(apd_name=apd_name)
            res = Resource.objects.filter(id=res_id)
            for i in res.iterator():
                res_name = i.documents
                res_tag = i.resource_inode
                if isinstance(res_tag, str):
                    res_tag = eval(res_tag)
                res_tag = res_tag['tag']
                print("Resource Tag type",res_tag)
                            # all_policies_checker = serialize('json', all_policies)
                for i in all_policies.iterator():
                    if i.event_type == 'pre':
                        # if i.Source == None:
                        artifact = i.artifact
                        if artifact == res_name:
                            condition_list.append(i.condition)
                            policy_ids.append(i.id)
                            policy_evaluation[f'{i.id}'] = i.modality
                                
                                
                            
                        # else:
                        #     artifact = i.artifact.split(':')[1]
                        #     if artifact == res_name:
                        #         reg_list.append(i.condition)
                            
                    # print("Regulation Conditions : ", reg_list)
                    print("Policy Conditions : ", condition_list)

                
                for j in condition_list:
                   
                    total_list = j.split(';')
                    total_list.pop()
                    for i in total_list:
                        location = i.split(':')[0]
                        keyword = i.split(':')[1]
                        param1 = i.split(':')[2]
                        print(i)
                        if param1 == 'role':
                            param2 = i.split(':')[3]
                            if param2 == role_capacity:
                                role_cond_list.append(j)
                            else:
                                continue
                        else:
                            continue
                
                if len(role_cond_list) == 0:
                    return HttpResponse("Role Forbidden",status=403)
                # role_cond_list += reg_list
                print("Role conditions list :", role_cond_list)
                obg_tracker = check_condition(request,res_tag,role_cond_list)
                print(obg_tracker)
                
                for k in policy_ids:
                    policy = PolicyBigTable.objects.filter(id = k)[0]
                    conditions = policy.condition.split(';')
                    conditions.pop()
                    true_counter = 0
                    false_counter = 0
                    for condition in conditions:
                        if condition in obg_tracker:
                            if(obg_tracker[f'{condition}'] == 'True'):
                                true_counter += 1
                            elif(obg_tracker[f'{condition}'] == 'False'):
                                false_counter += 1
                            
                    if true_counter == len(conditions):
                        policy_evaluation[f'{policy.id}'] = policy.modality
                    elif true_counter + false_counter == len(conditions):
                        policy_evaluation[f'{policy.id}'] = f'{negation(policy.modality)}'
                    else:
                        policy_evaluation.pop(f'{policy.id}')

                    if f'{policy.id}' in policy_evaluation and policy_evaluation[f'{policy.id}'] == 'O':
                        policy = PolicyBigTable.objects.filter(id = k)[0]
                        conditions = policy.condition.split(';')
                        conditions.pop()
                        for condition in conditions:
                            location = condition.split(':')[0]
                            keyword = condition.split(':')[1]
                            param1 = condition.split(':')[2]
                            if(location == ' request' and keyword == 'not_match'):
                                instructions.append(param1)
                            elif(location == 'request' and keyword == 'not_match'):
                                instructions.append(param1)
                print(policy_evaluation)


            
                template = "display.html"
                success_template = "popup.html"
                context = obg_tracker
                for key,value in obg_tracker.items():
                    if value == 'True':
                        obg_fulfilled= True
                    else:
                        obg_fulfilled = False
                        # print(obg_fulfilled)
                        consent_template = generate_consent(obg_fulfilled,res_name,apd_name,role_capacity)
                        return TemplateResponse(request,template,{"obg_tracker":obg_tracker , "policy_evaluation":policy_evaluation , "instructions":instructions})
                    # return HttpResponse("Obligation Not fulfilled")   
                consent_template = generate_consent(obg_fulfilled,res_name,apd_name,role_capacity)     
                if obg_fulfilled:
                    return HttpResponse(consent_template,content_type='application/xml')
                    # return render(request,success_template)
            # return HttpResponse("OK", status=201)
        else:
            return HttpResponse("Role Not Found", status=403)
    

def has_tag(tag):
    all_resources = Resource.objects.filter(resource_apd=mandate.current_APD)
    filtered_resources = []
    for i in all_resources.iterator():
        for j in i.resource_inode.keys():
            if(j == tag):
                filtered_resources.append(i)
    print(filtered_resources)
    return filtered_resources


@csrf_exempt
def create_regulation(request, source, event, event_type, condition, action, modality):
    if request.method == "POST":
        j = Jurisdiction(Source=source, event=event, event_type=event_type, action=action, modality=modality, condition=condition)
        j.save()

    return HttpResponse("OK", status=201)


@csrf_exempt
def get_regulations(request, jurisdiction_name):
    # create jurisdiction world
    # returns the regulations of the world
    requested_jurisdiction = Jurisdiction.objects.filter(
        jurisdiction_name=jurisdiction_name)
    response_data = serialize('json', requested_jurisdiction)
    return HttpResponse(json.dumps(response_data), content_type='application/json')
    # return HttpResponse('OK', status=201)


@csrf_exempt
def inherit_jurisdiction(request, jurisdiction_name, world_name):
    # take the world name and jurisdiction name
    # fetch the policies from the jurisdiction table and add it to this world's policy table
    auth = request.META['HTTP_AUTHORIZATION'].split()
    auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
    username, password = auth_decoded.split(":")
    user = authenticate(username=username, password=password)

    if user is not None:
        all_users = User.objects.get(username=username)
        all_apd = APD.objects.get(apd_name=world_name)
    else:
        return HttpResponse("Invalid Login", status=401)

    if (user is not None) and (all_users.id == all_apd.apd_admin_id):
        j = Jurisdiction.objects.filter(jurisdiction_name=jurisdiction_name)
        for i in j.values():
            regulation_source = i['jurisdiction_name']
            modality = i['modality']
            predicate = i['predicate']
            condition = i['condition']
            action = i['action']
            p = PolicyBigTable(apd_name=world_name, modality=modality, predicate=predicate,
                            condition=condition, action=action, RegulationSource=regulation_source)
            p.save()
        all_policies = PolicyBigTable.objects.filter(apd_name=world_name)
        response_data = serialize('json', all_policies)
        return HttpResponse(json.dumps(response_data), content_type='application/json')
    else:
        return HttpResponse("Not Authorised Admin of APD "+world_name, status=401)
    # return HttpResponse('OK', status=201)


@csrf_exempt
def create_template(request, template_name):
    if request.method == 'POST':
        roles = {}
        rcvd_json = json.loads(request.body.decode('utf-8'))
        roles = rcvd_json['Roles']
        print(roles)
        t = Template(template_name=template_name,
                     template_roles=roles)
        t.save()
        template_info = Template.objects.filter(template_name=template_name)
        response_data = serialize('json', template_info)
    return HttpResponse(json.dumps(response_data), content_type='application/json')


@csrf_exempt
def inherit_roles(request, template_name, apd_name):
    
    auth = request.META['HTTP_AUTHORIZATION'].split()
    auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
    username, password = auth_decoded.split(":")
    user = authenticate(username=username, password=password)

    if user is not None:
        all_users = User.objects.get(username=username)
        all_apd = APD.objects.get(apd_name=apd_name)
    else:
        return HttpResponse("Invalid Login", status=401)

    if (user is not None) and (all_users.id == all_apd.apd_admin_id):
        t = Template.objects.filter(template_name=template_name)
        roles = []
        for i in t.values():
            roles = i['template_roles']
        apd = APD.objects.filter(apd_name=apd_name)
        for i in apd.values():
            items = i['template_roles']
        if items != None:
            for x in roles:
                items.append(x)
            apd = APD.objects.filter(
                apd_name=apd_name).update(template_roles=items)

        else:
            apd = APD.objects.filter(
                apd_name=apd_name).update(template_roles=roles)
        print(items)
        # response_data = serialize('json', apd)
        return HttpResponse('OK', status=201)
    else:
        return HttpResponse("Not Authorised Admin of APD "+apd_name, status=401)

@csrf_exempt
def create_User(request,firstname,lastname,username,email,password):
    if request.method == 'POST':
        u = User.objects.create_user(first_name=firstname,last_name=lastname,email=email,username=username, password=password, is_superuser=0)
        u.save()
    return HttpResponse(status=201)


@csrf_exempt
def AssignRole(request, userId, apd_name, role):
    if request.method == "PUT":
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            all_apd = APD.objects.get(apd_name=apd_name)
        else:
            return HttpResponse("Invalid Login", status=401)

        if (user is not None) and (all_users.id == all_apd.apd_admin_id):
            apd = APD.objects.filter(apd_name=apd_name)
            roles = []
            user_roles = []
            for i in apd.values():
                roles = i['template_roles']
            if role in roles:
                if user_role_info.objects.filter(user_id=userId).exists():
                    user_role = user_role_info.objects.filter(user_id=userId)[0].role
                    if isinstance(user_role, str):
                        user_role = eval(user_role)
                    if(f'{apd_name}' not in user_role):
                        user_role[f'{apd_name}'] = [f'{role}']
                        updater = user_role_info.objects.filter(user_id=userId).update(
                            user_id=userId, role=user_role)
                        return HttpResponse(status=201)
                    else:
                        for i in user_role[f'{apd_name}']:
                            user_roles.append(i)
                        if(f'{role}' not in user_roles):
                            user_roles.append(f'{role}')
                            user_role[f'{apd_name}'] = user_roles
                            updater = user_role_info.objects.filter(user_id=userId).update(role=user_role)
                            return HttpResponse(status=201)
                        else:
                                return HttpResponse("Role is already assigned to the user", status=403)
                else:
                    role_list = []
                    role_list.append(f'{role}')
                    new_role = user_role_info.objects.create(user_id=userId,role={f'{apd_name}':role_list})
                    new_role.save()
                    return HttpResponse(status=201)
            else:
                return HttpResponse("Role doesn't exist in APD", status=401)
        else:
            return HttpResponse("Not Authorised Admin of APD "+apd_name, status=401)

@csrf_exempt
def DeassignRole(request, userId, apd_name, role):
    if request.method == "PUT":
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            all_apd = APD.objects.get(apd_name=apd_name)
        else:
            return HttpResponse("Invalid Login", status=401)

        role_dict = user_role_info.objects.filter(user_id=userId)[0].role
        if isinstance(role_dict, str):
            role_dict = eval(role_dict)
        role_dict[f'{apd_name}'].remove(f'{role}')
        updater = user_role_info.objects.filter(user_id=userId).update(user_id=userId, role=role_dict)
    return HttpResponse(status=201)


@csrf_exempt
def create_admin(request, userId, apd_name):
    if request.method == "PUT":
        apd = APD.objects.filter(
            apd_name=apd_name).update(apd_admin=userId)
        #apd.save()
        return HttpResponse(status=201)
    return HttpResponse(status=404)

# Functions for Viewing Existing Data

@csrf_exempt
def view_APD_info(request):
    response_data = {}
    apd = APD.objects.all()
    response_data = serialize('json', apd)
    return HttpResponse(response_data, content_type='application/json')


@csrf_exempt
def view_APD_policies(request, apd_name):
    response_data = {}
    apd = PolicyBigTable.objects.filter(apd_name=apd_name)
    response_data = serialize('json', apd)
    return render(request, "view_policy.html", {"apd_name":apd_name, "all_policy":apd})

@csrf_exempt
def view_all_users(request):
    response_data = {}
    apd = User.objects.all()
    response_data = serialize('json', apd)
    return HttpResponse(response_data, content_type='application/json')


@csrf_exempt
def view_all_templates(request):
    response_data = {}
    apd = Template.objects.all()
    response_data = serialize('json', apd)
    return HttpResponse(response_data, content_type='application/json')


@csrf_exempt
def view_regulations(request):
    response_data = {}
    apd = Jurisdiction.objects.all()
    response_data = serialize('json', apd)
    return HttpResponse(response_data, content_type='application/json')

# Delete functions for policies, regulations, and users


@csrf_exempt
def delete_policy(request, policy_id):
    if request.method == "POST":
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            # all_apd = APD.objects.get(apd_name=apd_name)
        else:
            return HttpResponse("Invalid Login", status=401)
        
    policy = PolicyBigTable.objects.filter(id=policy_id).delete()
    return HttpResponse("OK", status=201)


@csrf_exempt
def delete_regulation(request, reg_id):
    policy = Jurisdiction.objects.filter(id=reg_id).delete()
    return HttpResponse("OK", status=201)


@csrf_exempt
def delete_user(request, user_id):
    if request.method == "POST":
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            # all_apd = APD.objects.get(apd_name=apd_name)
        else:
            return HttpResponse("Invalid Login", status=401)
        
    all_apd = APD.objects.all()
    for apd in all_apd:
        if(user_id == apd.apd_admin_id):
            return HttpResponse("User is the Admin of APD "+ apd.apd_name + "\nEither change the admin Or Delete the apd first.", status=401)
    deleter = user_role_info.objects.filter(user_id=user_id).delete()
    policy = User.objects.filter(id=user_id).delete()
    return HttpResponse("OK", status=201)

@csrf_exempt
def delete_apd(request, apd_name):
    if request.method == "POST":
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            # all_apd = APD.objects.get(apd_name=apd_name)
        else:
            return HttpResponse("Invalid Login", status=401)
        
    policy = PolicyBigTable.objects.filter(apd_name=apd_name).delete()
    users = user_role_info.objects.all()
    for user in users:
        if(f'{apd_name}' in user.role):
            role_dict = user.role
            if isinstance(role_dict, str):
                role_dict = eval(role_dict)
            del role_dict[f'{apd_name}']
            updater = user_role_info.objects.filter(user_id=user.user_id).update(role=role_dict)
    apd = APD.objects.filter(apd_name=apd_name).delete()
    return HttpResponse("OK", status=201)

def create_consent_xml(policy_ids,res_id,obg_status,role_capacity):
    obg_status = str(obg_status)
    res = Resource.objects.filter(id=res_id)
    for i in res.values():
        doc_type=i['document_type']
        inode = i['resource_inode']
        if isinstance(inode,str):
            inode = eval(inode)
        inode = inode['tag']
    root = Element('Consent')
    consent_time = time.ctime()
    root.set('timestamp', consent_time)
    root.set('xmlns', "http://meity.gov.in")
    p = Element('DataRequester')
    p.set("value", " ")
    p.set('type', "URI")
    root.append(p)
    c1 = SubElement(p, 'Notify')
    p.set("value", " ")
    p.set('type', "URI")
    p.set('event', "REVOKE")
    # p.append(c1)
    c2 = SubElement(p, 'Role')
    c2.text = role_capacity
    # p.append(c2)
    p = Element('DataProvider')
    root.append(p)
    c1 = SubElement(p, 'Notify')
    # p.append(c1)
    revoker = Element('Revoker')
    root.append(revoker)
    data_items = Element('Data-Items')
    data = SubElement(data_items, 'Data')
    data.set('type', doc_type)
    data.set('tag', inode)
    data.set('resource_id',f'{res_id}')
    root.append(data_items)
    consent_validity = SubElement(data_items, 'ConsentValidity')
    comment = Comment('how long can consumer is allowed to store data')
    consent_validity.append(comment)
    consent_validity.set('value', '')
    consent_validity.set('unit', '')
    cond_type = SubElement(data, 'preCondition')
    cond_type.text = obg_status
    cond_type = SubElement(data, 'postCondition')
    
    for i in policy_ids:
        print(i)
        modality = i.modality
        condition = i.condition
        action = i.action
        mod = SubElement(cond_type, modality)
        cond = SubElement(mod, 'cond')
        cond.text = condition
        act = SubElement(mod, 'action')
        act.text = action
    
    purpose = Element('Purpose')
    comment = Comment("Purpose attributes")
    purpose.append(comment)
    purpose.text = " "
    root.append(purpose)
    sign = Element('Signature')
    comment = Comment("User Signature Block")
    sign.append(comment)
    sign.text = " "
    root.append(sign)
    sign = Element('Signature')
    comment = Comment("Consent Collector Signature Block")
    sign.append(comment)
    sign.text = " "
    root.append(sign)

    tree = et.ElementTree(root)
    xmlstr = minidom.parseString(et.tostring(root)).toprettyxml(indent=" ")
    with open('consent_demo.xml', "wb") as f:
        f.write(xmlstr.encode('utf-8'))
    return xmlstr


@csrf_exempt
def revoke_consent(request, res_id,apd_name):
    if request.method == "PUT":
        # name = request.GET.get('name')
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
        username, password = auth_decoded.split(":")
        user = authenticate(username=username, password=password)

        if user is not None:
            all_users = User.objects.get(username=username)
            all_apd = APD.objects.get(apd_name=apd_name)
        else:
            return HttpResponse("Invalid Login", status=401)

        if (user is not None) and (all_users.id == all_apd.apd_admin_id):
            res = Resource.objects.filter(id=res_id).update(consent_artefact=None)
            return HttpResponse("OK", status=201)
        else:
            return HttpResponse("Not authorised to revoke consent", status=403)
    else:
        return HttpResponse("Change request type", status=403)
    
@csrf_exempt
def upload_file(request,apd_name):
    if request.method == 'POST':
        form = Resource(documents = request.FILES['file'],document_type='Doc',consent_artefact=None,resource_apd=apd_name,resource_inode=None)
        # if form.is_valid():
        #     # file is saved
        form.save()
        return HttpResponse('OK',status=201)
    else:
    #     form = ModelFormWithFileField()
        return HttpResponse("Not Ok",status=403)
    
@csrf_exempt
def update_file(request,res_id):
    if request.method == 'POST':
        form = Resource.objects.filter(id=res_id).update(documents = request.FILES['file'])
        print(form)
        # form = Resource(documents = request.FILES['file'],document_type='Doc',consent_artefact=None,resource_apd=apd_name,resource_inode=None)
        # if form.is_valid():
        #     # file is saved
        return HttpResponse('OK',status=201)
    else:
    #     form = ModelFormWithFileField()
        return HttpResponse("Not Ok",status=403)
    

# INTEGRATING THE BACKEND AND FRONTEND
def index(request):
    # Authenticating the user into the website
    if request.method == 'POST':
        errors = []
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            global user_id
            user_apds = None
            request.session['username'] = username
            user_id = User.objects.filter(username=username)[0].id
            if user_role_info.objects.filter(user_id=user_id).exists():
                user_apds = user_role_info.objects.filter(user_id=user_id)[0].role
                if isinstance(user_apds, str):
                    user_apds = eval(user_apds)
                request.session['user_apds'] = user_apds
                return redirect(home)
            else:
                request.session['user_apds'] = user_apds
                return redirect(home)
        else:
            errors.append('Invalid login credentials')
            return render(request, 'index.html',{'errors':errors})
    else:
        return render(request, 'index.html')

def signup(request):
    # Using the create_user api function to sign up a new user
    if request.method == 'POST':
        errors = []
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        cpassword = request.POST['cpassword']

        if User.objects.filter(username=username).exists():
            errors.append('Username already exists! Try logging in')
            return render(request, 'SignUp.html',{'errors':errors})
        elif cpassword == password:
            u = User.objects.create_user(first_name=firstname,last_name=lastname,email=email,username=username, password=password, is_superuser=0)
            u.save()
            user_apds = None
            request.session['username'] = username
            request.session['user_apds'] = user_apds
            return redirect(home)
        elif cpassword != password:
            errors.append('Passwords does not match')
            return render(request, 'SignUp.html',{'errors':errors})
        else:
            errors.append('An unknown error occurred. Please try again!')
            return render(request, 'SignUp.html',{'errors':errors})
    else:
        return render(request, 'SignUp.html')

def home(request):
    # Using the view_APD_info api function to display the APDs that the user is a part of
    username = request.session['username']
    user_apds = request.session['user_apds']
    if user_apds is not None:
        return render(request, 'welcome.html', {'username':username,'user_apds':user_apds})
    else:
        return render(request, 'welcome.html', {'username':username})


def apd(request,apd_name):
    # Displaying all the resources present in the apd and allowing the users to select role for requesting resources
    global chosen_role
    username = request.session['username']
    apd_resources = Resource.objects.filter(resource_apd=apd_name)
    user_id = User.objects.filter(username=username)[0].id
    user_info = user_role_info.objects.filter(user_id=user_id)[0].role
    if isinstance(user_info, str):
        user_info = eval(user_info)
    user_roles = user_info[f'{apd_name}']
    if request.method == "POST" and 'role' not in request.POST:
        response = list(request.POST.items())
        role_capacity = response[1][1]
        res_name = response[2][1]
        request.session['apd_name'] = apd_name
        request.session['res_name'] = res_name
        request.session['role_capacity'] = role_capacity
        return redirect(obligation)
    if 'role' in request.POST :
        chosen_role = request.POST['role']
        policies_for_artifact = {}
        apd_policies = PolicyBigTable.objects.filter(apd_name=apd_name)
        for policy in apd_policies:
            if policy.artifact in policies_for_artifact:
                policies_for_artifact[f'{policy.artifact}'].append(policy.id)
            else:
                policies_for_artifact[f'{policy.artifact}'] = [(policy.id)]
            
        return render(request, 'apd.html', {'user_id':user_id,'user_roles':user_roles, 'apd_name':apd_name, 'resources':apd_resources, 'chosen_role':chosen_role, 'policies_for_artifact':policies_for_artifact})
    else:
        return render(request, 'apd.html', {'user_id':user_id,'user_roles':user_roles, 'apd_name':apd_name, 'resources':apd_resources})

def applicable_policies(request,res_name):
        username = request.session['username']
        apd_name = request.session['apd_name']
        print("The session is ", request.session['apd_name'])
        if request.method == "POST":
            response = list(request.POST.items())
            role_capacity = response[1][1]
            res_name = response[2][1]
        policy_statements = []
        policy_statements_ids = []
        new_policies = []
        policies = PolicyBigTable.objects.filter(artifact=res_name)
        policies = set(policies)
        print(policies)
        for policy in policies:
            policy_statements_ids.append(policy.policy_id)
        policy_statements_ids = set(policy_statements_ids)
        print(policy_statements_ids)
        policy_statement =  Statements.objects.all()
        for i in policy_statements_ids:  
            for j in policy_statement:
                print(i)
                if i == j.policy_id:
                    print(j.policy_id)
                    new_policies.append(j)
                else:
                    continue
        print("New Policies", new_policies)
            # for i in policy_statement:
            #     statement = i.statements
            #     policy_statements.append(statement)
        # print(policy_statements)
        return render(request, 'statements.html', {'policies':new_policies})

def generate_consent(obg_fulfilled,res_name,apd_name,role_capacity):
    #generates a consent template for the applicable policies
        post_policy_ids = []
        policy_ids = PolicyBigTable.objects.filter(apd_name=apd_name)
        res = Resource.objects.filter(document_name=res_name,resource_apd=apd_name)
        res_id = res[0].id
        for i in res.iterator():
            # res_name = i.document_name
            inode = i.resource_inode
            if isinstance(inode,str):
                inode = eval(inode)
            # for key,value in inode.items():
            #     res_inode=inode['tag']
        # all_policies_checker = serialize('json', all_policies)
        for i in policy_ids.iterator():
            if i.event_type == 'post':
                artifact = i.artifact
                # print(artifact)
                if res_name == artifact:
                    post_policy_ids.append(i)
                    print(i)
                    continue
        consent_template = create_consent_xml(post_policy_ids,res_id,obg_fulfilled,role_capacity)
        res = Resource.objects.get(id=res_id)
        res.consent_artefact = consent_template
        res.save() 
        return consent_template
   
def obligation(request):
    # Using the access_resource, check_condition and create_consent_template api functions in the below mentioned evaluate function to authorize resource to the user
    username = request.session['username']
    apd_name = request.session['apd_name']
    role_capacity = request.session['role_capacity']
    res_name = request.session['res_name']

    # def call_consent(obg_fulfilled):
    #     post_policy_ids = []
    #     policy_ids = PolicyBigTable.objects.filter(apd_name=apd_name)
    #     res = Resource.objects.filter(document_name=res_name,resource_apd=apd_name)
    #     res_id = res[0].id
    #     for i in res.iterator():
    #         # res_name = i.document_name
    #         inode = i.resource_inode
    #         if isinstance(inode,str):
    #             inode = eval(inode)
    #         # for key,value in inode.items():
    #         #     res_inode=inode['tag']
    #     # all_policies_checker = serialize('json', all_policies)
    #     for i in policy_ids.iterator():
    #         if i.event_type == 'post':
    #             artifact = i.artifact
    #             # print(artifact)
    #             if res_name == artifact:
    #                 post_policy_ids.append(i)
    #                 print(i)
    #                 continue
    #     consent_template = create_consent_template(post_policy_ids,res_id,obg_fulfilled,role_capacity)
    #     res = Resource.objects.get(id=res_id)
    #     res.consent_artefact = consent_template
    #     res.save() 
    #     return consent_template
    

    artifact = PolicyBigTable.objects.filter(artifact=res_name)
    if artifact.exists():
        
        condition_list = []
        policy_evaluation = {}
        policy_ids = []
        role_cond_list = []
        obligations = []


        res_inode = Resource.objects.filter(resource_apd=apd_name,document_name=res_name)[0].resource_inode
        if isinstance(res_inode, str):
            res_inode = eval(res_inode)
        res_tag = res_inode['tag']
        policies = PolicyBigTable.objects.filter(apd_name=apd_name,artifact=res_name,event_type='pre')
        for i in policies.iterator():
            condition_list.append(i.condition)
            policy_ids.append(i.id)
            policy_evaluation[f'{i.id}'] = i.modality

        for j in condition_list:
            total_list = j.split(';')
            total_list.pop()
            for i in total_list:
                location = i.split(':')[0]
                keyword = i.split(':')[1]
                param1 = i.split(':')[2]
                if param1 == 'role':
                    param2 = i.split(':')[3]
                    if param2 == role_capacity:
                        role_cond_list.append(j)
                    else:
                        continue
                else:
                    continue

        if len(role_cond_list) == 0:
            return render(request, 'result.html', {'message':'Role forbidden!'})
        
        for j in role_cond_list:
            total_list = j.split(';')
            total_list.pop()
            for i in total_list:
                location = i.split(':')[0]
                keyword = i.split(':')[1]
                param1 = i.split(':')[2]
                if(location == ' request' and keyword == 'not_match'):
                    if param1 not in obligations:
                        obligations.append(param1)
                elif(location == 'request' and keyword == 'not_match'):
                    if param1 not in obligations:
                        obligations.append(param1)

        if len(obligations) == 0:
            return render(request, 'result.html', {'message':'Role forbidden!'})

        if request.method == "POST":
            user_input = {}
            for obg in obligations:
                user_input[f'{obg}'] = request.POST[f'{obg}']

            evaluated_policies = evaluate(res_tag,role_cond_list,user_input,policy_ids,policy_evaluation)
            
            if 'O' in evaluated_policies.values():
                remarks = 'Obligations are not filled correctly!'
            elif 'F' in evaluated_policies.values():
                remarks = 'The resource is forbidden according to the policies! Please recheck the policies.'
            else:
                obg_fulfilled = 'True'
                remarks = 'Your request is granted!'
                consent_template = generate_consent(obg_fulfilled,res_name,apd_name,role_capacity)
                return HttpResponse(consent_template,content_type='application/xml')

            # return render(request, 'obligation.html',{'username':username, 'apd_name':apd_name, 'role_capacity':role_capacity, 'res_name':res_name, 'obligations':obligations, 'role_cond_list':role_cond_list, 'evaluated_policies':evaluated_policies,'remarks':remarks})
            return render(request, 'result.html', {'message':remarks})
        

    else:
        return render(request, 'result.html', {'message':'Request approved.'})
    return render(request, 'obligation.html',{'username':username, 'apd_name':apd_name, 'role_capacity':role_capacity, 'res_name':res_name, 'obligations':obligations, 'role_cond_list':role_cond_list})

def negation(modality):
    match(modality):
        case 'P':
            modality = 'F'
        case 'O':
            modality = 'P'
        case 'F':
            modality = 'P'
    return modality
        

def match_keyword(condition,key,value,obg_tracker):
        keyword = condition.split(':')[1]
        param1 = condition.split(':')[2]
        if keyword == "has":
            has(param1,key,obg_tracker,condition)
        elif keyword == "has_tag":
            has_tag(param1,value,obg_tracker,condition)
        elif keyword =="match":
            param2 = condition.split(':')[3]
            if key and value:
                match_params(param1,key,param2,value,obg_tracker,condition)
        elif keyword =="not_match":
            param2 = condition.split(':')[3]
            if key and value:
                not_match_params(param1,key,param2,value,obg_tracker,condition)
            else:
                obg_tracker[condition] = 'True'
        else:
            print("Invalid Keyword")

def has(param1,key,obg_tracker,condition):
        if(param1 == key):
            obg_tracker[condition] = 'True'

def has_tag(param1,tag,obg_tracker,condition):
        # print(param1,val2)
        if param1 == tag or param1 in tag:
            print(condition)
            obg_tracker[condition] = 'True'
            print("Tag has matched")
        else:
            print("Not matched")

def match_params(param1,key,param2,value,obg_tracker,condition):
        # print(param1,param2,key,value)
        if param1 == key and param2 == value:
            print("At match_params",param1,param2,key,value)
            obg_tracker[condition] = 'True'
        if param1 == 'role':
            print("At role check")
            obg_tracker[condition] = 'True'

def not_match_params(param1,key,param2,value,obg_tracker,condition):
        # print(param1,param2,key,value)
        if param1 == key and param2 == value:
            obg_tracker[condition] = 'False'
        else:
            obg_tracker[condition] = 'True'
        
def evaluate(res_tag,role_cond_list,user_input,policy_ids,policy_evaluation):
    # def negation(modality):
    #     if modality == 'P':
    #         return 'F'
    #     else:
    #         return 'P'
    obg_tracker = {}
    # def match_keyword(i,key,value):
    #     keyword = i.split(':')[1]
    #     param1 = i.split(':')[2]
    #     if keyword == "has":
    #         has(param1,key)
    #     elif keyword == "has_tag":
    #         has_tag(param1,value)
    #     elif keyword =="match":
    #         param2 = i.split(':')[3]
    #         if key and value:
    #             match_params(param1,key,param2,value)
    #     elif keyword =="not_match":
    #         param2 = i.split(':')[3]
    #         if key and value:
    #             not_match_params(param1,key,param2,value)
    #         else:
    #             obg_tracker[i] = 'True'
    #     else:
    #         print("Invalid Keyword")
    # def has(param1,key):
    #     if(param1 == key):
    #         obg_tracker[i] = 'True'
        
    #     # print('At has')

    # def has_tag(param1,tag):
    #     # print(param1,val2)
    #     if param1 == tag or param1 in tag:
    #         print(i)
    #         obg_tracker[i] = 'True'
    #         print("Tag has matched")
    #     else:
    #         print("Not matched")
    # def match_params(param1,key,param2,value):
    #     # print(param1,param2,key,value)
    #     if param1 == key and param2 == value:
    #         print("At match_params",param1,param2,key,value)
    #         obg_tracker[i] = 'True'
    #     if param1 == 'role':
    #         print("At role check")
    #         obg_tracker[i] = 'True'
    # def not_match_params(param1,key,param2,value):
    #     # print(param1,param2,key,value)
    #     if param1 == key and param2 == value:
    #         obg_tracker[i] = 'False'
    #     else:
    #         obg_tracker[i] = 'True'


    for j in role_cond_list:
        condition_list = j.split(';')
        condition_list.pop()

        for i in condition_list:
            obg_tracker[i] = 'False'
            location = i.split(':')[0]
            keyword = i.split(':')[1]
            param1 = i.split(':')[2]
            if location == "request" or location == " request":
                #check purpose code value, role value, data seeking form, check value for a key matches value for a condition
                 # print("At request check")
                if keyword == "match" and param1 == "role":
                    obg_tracker[i] = 'True'
                    continue
                elif keyword == "match" or keyword == "not_match":
                    if param1 in user_input:
                        key = param1
                        value = user_input[f'{param1}']
                        match_keyword(i,key,value,obg_tracker)
                    else:
                        continue
                elif keyword == "has":
                    if param1 in user_input:
                        obg_tracker[i] = 'True'
                    else:
                        continue
                else:
                    continue
            elif location == "artifact" or location == " artifact":
                print("At artifact")
                match_keyword(i,keyword,res_tag,obg_tracker)
            elif location == "apd" or location == " apd":
                print("At apd")
            else:
                continue

    for k in policy_ids:
        policy = PolicyBigTable.objects.filter(id = k)[0]
        conditions = policy.condition.split(';')
        conditions.pop()
        true_counter = 0
        false_counter = 0
        for condition in conditions:
            if condition in obg_tracker:
                if(obg_tracker[f'{condition}'] == 'True'):
                    true_counter += 1
                elif(obg_tracker[f'{condition}'] == 'False'):
                    false_counter += 1
                            
        if true_counter == len(conditions):
            policy_evaluation[f'{policy.id}'] = policy.modality
        elif true_counter + false_counter == len(conditions):
            policy_evaluation[f'{policy.id}'] = f'{negation(policy.modality)}'
        else:
            policy_evaluation.pop(f'{policy.id}')

    # print(obg_tracker)
    return policy_evaluation

def consent_dashboard(request,apd_name):
    # Displaying the resources and their consent artifacts only for the admin
    resources = Resource.objects.filter(resource_apd=apd_name)
    return render(request, 'consent.html', {'apd_name':apd_name, 'resources':resources})

def policy_dashboard(request,apd_name):
    # Using the view_all_policies and modify_policy api functions to view and edit apd policies only for admin
    policies = PolicyBigTable.objects.filter(apd_name=apd_name)
    if request.method == "POST":
        if 'modality' not in request.POST and 'policy-id' in request.POST:
            policy_id = request.POST['policy-id']
            policy = PolicyBigTable.objects.get(id=policy_id)
            return render(request, 'policy.html', {'apd_name':apd_name, 'policies':policies, 'policy_id':policy_id, 'selected_policy':policy})
        else:
            policy_id = request.POST['id']
            condition = request.POST['condition']
            action = request.POST['action']
            # artifact = request.POST['artifact']
            event_type = request.POST['event_type']
            modality = request.POST['modality']
            policy = PolicyBigTable.objects.get(id=policy_id)
            policy.condition = condition
            policy.action = action
            policy.event_type = event_type
            policy.modality = modality
            policy.save()
            return render(request, 'policy.html', {'apd_name':apd_name, 'policies':policies})
        
    return render(request, 'policy.html', {'apd_name':apd_name, 'policies':policies})


def role_dashboard(request,apd_name):
    # Using the view_Users , Assign_role and DeAssign_role api functions to view and edit user roles only for admin
    users_id = []
    users_names = []
    apd_users_roles = []

    all_users = User.objects.all()
    for user in all_users:
        users_names.append(user.username)
        users_id.append(user.id)
    
    for user_id in users_id:
        if user_role_info.objects.filter(user_id=user_id).exists():
            user_role = user_role_info.objects.filter(user_id=user_id)[0].role
            if isinstance(user_role,str):
                user_role = eval(user_role)
            if f'{apd_name}' in user_role:
                apd_users_roles.append(user_role[f'{apd_name}'])
            else:
                apd_users_roles.append('No roles Assigned in this APD')
        else:
            apd_users_roles.append("No roles assigned yet")

    user_list = zip(users_id,users_names,apd_users_roles)
    apd_roles = APD.objects.filter(apd_name=apd_name)[0].template_roles
    if isinstance(apd_roles,str):
        apd_roles = eval(apd_roles)

    if request.method =="POST":
        user_id = int(request.POST['user_id'])
        func = request.POST['form_type']
        role = request.POST['role']
        if func == 'DeAssign':
            role_dict = user_role_info.objects.filter(user_id=user_id)[0].role
            if isinstance(role_dict, str):
                role_dict = eval(role_dict)
            if role in role_dict[f'{apd_name}']:
                role_dict[f'{apd_name}'].remove(f'{role}')
                updater = user_role_info.objects.filter(user_id=user_id).update(role=role_dict)
                message = 'Role successfully deassigned'
            else:
                message = 'User does not have the role'
        elif func == 'Assign':
            if user_role_info.objects.filter(user_id=user_id).exists():
                user_role = user_role_info.objects.filter(user_id=user_id)[0].role
                if isinstance(user_role, str):
                    user_role = eval(user_role)
                if(f'{apd_name}' not in user_role):
                    user_role[f'{apd_name}'] = [f'{role}']
                    updater = user_role_info.objects.filter(user_id=user_id).update(role=user_role)
                    message = 'Role successfully assigned'
                else:
                    user_roles = []
                    for i in user_role[f'{apd_name}']:
                        user_roles.append(i)
                    if(f'{role}' not in user_roles):
                        user_roles.append(f'{role}')
                        user_role[f'{apd_name}'] = user_roles
                        updater = user_role_info.objects.filter(user_id=user_id).update(role=user_role)
                        message = 'Role successfully assigned'
                    else:
                        message = "Role is already assigned to the user"
            else:
                role_list = []
                role_list.append(f'{role}')
                new_role = user_role_info.objects.create(user_id=user_id,role={f'{apd_name}':role_list})
                new_role.save()
                message = 'Role successfully assigned'
        
        username = request.session['username']
        current_user_id = User.objects.get(username=username).id
        if current_user_id == user_id:
            return redirect('/')
        else:
            return redirect(f'/apd/{apd_name}/role_dashboard')

    return render(request, 'role.html', {'apd_name':apd_name,'user_list':user_list,'apd_roles':apd_roles})

def jurisdiction_dashboard(request,apd_name):
    # Using view_regulations and inherit_jurisdiction api functions to view and edit regulations only for admin
    jurisdictions = []
    apd_jurisdictions = {}
    all_regulations = Jurisdiction.objects.all()
    for reg in all_regulations:
        if reg.Source not in jurisdictions:
            jurisdictions.append(reg.Source)
            
    for j in jurisdictions:
        jurisdiction_policies = PolicyBigTable.objects.filter(apd_name=apd_name,Source=j)
        if jurisdiction_policies.exists():
            apd_jurisdictions[f'{j}'] = True
        else:
            apd_jurisdictions[f'{j}'] = False

    if request.method == 'POST':
        response = request.POST['jurisdiction']
        jur_name = response.split(':')[0]
        jur_action = response.split(':')[1]
        if jur_action == 'add':
            apd_jurisdictions[f'{jur_name}'] = True
            jur_regulations = Jurisdiction.objects.filter(Source=jur_name)
            for reg in jur_regulations:
                p = PolicyBigTable(apd_name=apd_name, modality=reg.modality, artifact='*',event=reg.event,event_type=reg.event_type,
                               condition=reg.condition, action = reg.action, Source=reg.Source)
                p.save()
        elif jur_action == 'remove':
            apd_jurisdictions[f'{jur_name}'] = False
            jur_policies = PolicyBigTable.objects.filter(apd_name=apd_name,Source=jur_name)
            for j in jur_policies:
                j.delete()
        
        return render(request, 'jurisdiction.html', {'apd_name':apd_name,'apd_jurisdictions':apd_jurisdictions})
        
    return render(request, 'jurisdiction.html', {'apd_name':apd_name,'apd_jurisdictions':apd_jurisdictions})