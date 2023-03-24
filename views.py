# Django
from django.db.models import F
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth import authenticate
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.utils.encoding import smart_str
from django.db.models import Q

# standard library
import os
import requests
import math
import json
import string
import secrets
from datetime import datetime, timedelta
from django.db.models import Avg

# local Django
from users.authentication import token_expire_handler, expires_in
from users.models import Account,Vendor,Contact,CustomerReview, MySearch, MailTemplate, Services, Content, Notification, Legal, AbusiveWords, PilotState, Help, NotificationList, Policies,MailSubscription,LoginLogs
from .serializers import UserSerializer, AdminSerializer, CustomerReferralSerializer, VendorSerializer, ContactSerializer, CustomerReviewSerializer, ContentSerializer, NotificationSerializer, LegalSerializer, UserRoleSerializer, HelpSerializer, PoliciesSerializer
from .inputSerializer import CustomerAPIInputSerializer, UpdateProfileInputSerializer, CustomerInputSerializer, UserRegistrationSerializer, AdminSigninSerializer, UpdatePasswordInputSerializer, MemberAPIInputSerializer, UpdateMemberInputSerializer, DeleteMemberInputSerializer, InputTokenSerializer, ReplyReviewInputSerializer, AddContentInputSerializer, CreateNotificationInputSerializer, UpdateNotificationInputSerializer, CustomerListMailAPIInputSerializer, LegalInputSerializer, UpdateUserProfileInputSerializer, UpdateAdminEmailInputSerializer, ReportInputSerializer, AddHelpInputSerializer, UpdateHelpInputSerializer, PoliciesInputSerializer, MemberListMailAPIInputSerializer, AdminForgotPasswordSerializer

# Django Rest Framework
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.authtoken.models import Token
from django_rest_passwordreset.signals import reset_password_token_created
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
)

#forgot password
@api_view(["POST"])
@permission_classes([AllowAny,])
def forgot_password(request):
    signin_serializer = AdminForgotPasswordSerializer(data = request.data)
    if not signin_serializer.is_valid():
        errors = get_error_message(signin_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    email =  signin_serializer.data['email']
    try:
        check_superuser = Account.objects.get(email= email)
    except Account.DoesNotExist:
        return Response({'response': 'Email address not registered.'}, status=HTTP_400_BAD_REQUEST) 

    if check_superuser.is_superuser:
        API_ENDPOINT = settings.DJANGO_ENDPOINT+"/api/v1/password_reset/"
        data = {"email": email}
        response = requests.post(url = API_ENDPOINT, data = data)
        pastebin_url = response.text
        if response.status_code == 200:
            return Response({'response': "OK"}, status=response.status_code) 
        else:
            return Response({'response': pastebin_url}, status=response.status_code) 
    else:
        return Response({'response': 'You entered an email address that was not associated with an admin role.'}, status=HTTP_400_BAD_REQUEST) 
    
    
from rest_framework.views import APIView
from rest_framework import status
import requests

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny,]

    def post(self, request):
        signin_serializer = AdminForgotPasswordSerializer(data=request.data)
        if not signin_serializer.is_valid():
            errors = get_error_message(signin_serializer)
            return Response({'response':errors}, status=status.HTTP_400_BAD_REQUEST) 
        email =  signin_serializer.data['email']
        try:
            check_superuser = Account.objects.get(email= email)
        except Account.DoesNotExist:
            return Response({'response': 'Email address not registered.'}, status=status.HTTP_400_BAD_REQUEST) 

        if check_superuser.is_superuser:
            API_ENDPOINT = settings.DJANGO_ENDPOINT+"/api/v1/password_reset/"
            data = {"email": email}
            response = requests.post(url=API_ENDPOINT, data=data)
            pastebin_url = response.text
            if response.status_code == 200:
                return Response({'response': "OK"}, status=response.status_code) 
            else:
                return Response({'response': pastebin_url}, status=response.status_code) 
        else:
            return Response({'response': 'You entered an email address that was not associated with an admin role.'}, status=status.HTTP_400_BAD_REQUEST)


# Admin: Login API
@api_view(["POST"])
@permission_classes((AllowAny,))  # here we specify permission by default we set IsAuthenticated
def login_view1(request):
    signin_serializer = AdminSigninSerializer(data = request.data)
    if not signin_serializer.is_valid():
        errors = get_error_message(signin_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    email =  signin_serializer.data['email']
    try:
        check_superuser = Account.objects.get(email= email)
    except Account.DoesNotExist:
        return Response({'response': 'Invalid Email'}, status=HTTP_400_BAD_REQUEST) 

    if check_superuser.is_superuser:
        user = authenticate(
                username = email,
                password = signin_serializer.data['password'] 
            )
        if not user:
            return Response({'response': 'Invalid Credentials or activate account'}, status=HTTP_400_BAD_REQUEST)
        else:
            if user.email_verified:       
                # Token.objects.filter(user=user).delete()
                token, _ = Token.objects.get_or_create(user = user)
                #token_expire_handler will check, if the token is expired it will generate new one
                is_expired, token = token_expire_handler(token)     # The implementation will be described further
                user_serialized = AdminSerializer(user)
                context = {
                        'user': user_serialized.data, 
                        'expires_in': expires_in(token).total_seconds(),
                        'auth_token': token.key
                        }    
                return Response(context, status=HTTP_200_OK)
            else:
                return Response({'response': 'Verify your account'}, status=HTTP_400_BAD_REQUEST)
    else:
        return Response({'response': 'You entered an email address that was not associated with an admin role.'}, status=HTTP_400_BAD_REQUEST) 



# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.authtoken.models import Token
# from rest_framework.permissions import AllowAny
# from django.contrib.auth import authenticate
# from .serializers import AdminSigninSerializer, AdminSerializer
# from users.models import Account




class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        signin_serializer = AdminSigninSerializer(data=request.data)
        if not signin_serializer.is_valid():
            errors = get_error_message(signin_serializer)
            return Response({'response': errors}, status=HTTP_400_BAD_REQUEST)
        email = signin_serializer.data['email']
        try:
            check_superuser = Account.objects.get(email=email)
        except Account.DoesNotExist:
            return Response({'response': 'Invalid Email'}, status=HTTP_400_BAD_REQUEST)

        if check_superuser.is_superuser:
            user = authenticate(
                username=email,
                password=signin_serializer.data['password']
            )
            if not user:
                return Response({'response': 'Invalid Credentials or activate account'}, status=HTTP_400_BAD_REQUEST)
            else:
                if user.email_verified:
                    # Token.objects.filter(user=user).delete()
                    token, _ = Token.objects.get_or_create(user=user)
                    # token_expire_handler will check, if the token is expired it will generate new one
                    is_expired, token = token_expire_handler(token)  # The implementation will be described further
                    user_serialized = AdminSerializer(user)
                    context = {
                        'user': user_serialized.data,
                        'expires_in': expires_in(token).total_seconds(),
                        'auth_token': token.key
                    }
                    return Response(context, status=HTTP_200_OK)
                else:
                    return Response({'response': 'Verify your account'}, status=HTTP_400_BAD_REQUEST)
        else:
            return Response({'response': 'You entered an email address that was not associated with an admin role.'}, status=HTTP_400_BAD_REQUEST)
        
        
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from rest_framework.permissions import AllowAny, IsAuthenticated
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.models import User
# from .serializers import UserSerializer

# class RegistrationAPIView(APIView):
#     permission_classes = (AllowAny,)

#     def post(self, request):
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LoginAPIView(APIView):
#     permission_classes = (AllowAny,)

#     def post(self, request):
#         username = request.data.get('username')
#         password = request.data.get('password')
#         user = authenticate(username=username, password=password)
#         if user:
#             login(request, user)
#             return Response({'message': 'success'}, status=status.HTTP_200_OK)
#         else:
#             return Response({'message': 'invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# class LogoutAPIView(APIView):
#     permission_classes = (IsAuthenticated,)

#     def post(self, request):
#         logout(request)
#         return Response({'message': 'success'}, status=status.HTTP_200_OK)

# from rest_framework import serializers
# from django.contrib.auth.models import User

# class UserSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(write_only=True)

#     def create(self, validated_data):
#         user = User.objects.create(
#             username=validated_data['username']
#         )
#         user.set_password(validated_data['password'])
#         user.save()
#         return user

#     class Meta:
#         model = User
#         fields = ('id', 'username', 'password')



# UserProfile: User logout
@api_view(['GET'])
def logout(request):
    request.user.auth_token.delete()
    return Response({"response": "Logged out successfully"})

# UserProfile: Update password
@api_view(['POST'])
@permission_classes((AllowAny,))  # here we specify permission by default we set IsAuthenticated
def update_password(request):
    update_password_input_serializer = UpdatePasswordInputSerializer(data = request.data)
    if not update_password_input_serializer.is_valid():
        errors = get_error_message(update_password_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    token = update_password_input_serializer.data["user_token"]
    try:
        user = Account.objects.get(token=token)
    except Account.DoesNotExist:
        user = None    
    if user is not None:
        password = update_password_input_serializer.data["password"]
        user.set_password(password) 
        user.save()  
        return Response({"response":"Password changed successfully"})
    else:
        return Response({'response': 'Check your account details'}, status=HTTP_400_BAD_REQUEST) 



#get customer list of all customer
@api_view(['GET'])
# @permission_classes((AllowAny,))      
def get_customer_list(request):
    customer_input_serializer=CustomerAPIInputSerializer(data = request.query_params)
    if not customer_input_serializer.is_valid():
        errors = get_error_message(customer_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    page = customer_input_serializer.data["page"]
    order_by = '-id'#customer_input_serializer.data["filter"]
    count = Account.objects.count()
    customer_details = Account.objects.all().order_by(order_by)[((page-1)*10):(page * 10)]
    serializer = UserSerializer(customer_details, many=True, context={'page': page})
    return Response({"customer_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})


# #update single customer detail
@api_view(['POST'])
def update_customer_detail(request):
    update_profile_input_serializer=UpdateProfileInputSerializer(data = request.data)
    if not update_profile_input_serializer.is_valid():
        errors = get_error_message(update_profile_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    token = update_profile_input_serializer.data['user_token']
    try:
        user = Account.objects.get(token= token)
    except Account.DoesNotExist:
        response = {"response":"No such user is found"}
        return Response(response)
    if user is not None:
        try:
            check_email = Account.objects.filter(email=update_profile_input_serializer.data['email']).exclude(token=user.token)
        except Account.DoesNotExist:
            check_email = None
        if check_email.exists():
            return Response({"response": "Email already exists"}, status=400)
        else:
            user_response = update_customer_data(request, update_profile_input_serializer, user)
        response = {"response": user_response}
        return Response(response)

##delete a particular customer     
@api_view(['GET'])
def delete_customer_detail(request):
    customer_input_serializer = CustomerInputSerializer(data = request.query_params)
    if not customer_input_serializer.is_valid():
        errors = get_error_message(customer_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    user_token = customer_input_serializer.data['user_token']
    try:
        user = Account.objects.get(token = user_token)
    except Account.DoesNotExist:
        user = None
    if user is not None:
        user.is_active = False
        user.save()
        response = {"response":'User blocked successfully.'}
        return Response(response)
    else:
        response = {"response":'No such user is found'}
        return Response(response)

# customer_list_send_mail  
# @api_view(['POST'])
# def customer_send_mail(request):
#     customer_list_mail_input_serializer=CustomerListMailAPIInputSerializer(data = request.data)
#     if not customer_list_mail_input_serializer.is_valid():
#         errors = get_error_message(customer_list_mail_input_serializer)
#         return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
#     title = customer_list_mail_input_serializer.data["title"]
#     message = customer_list_mail_input_serializer.data["message"]
#     # image=request.FILES["image"]
#     recipient_list = customer_list_mail_input_serializer.data["recipient_list"]
#     for item in recipient_list:
#         try:
#             account = Account.objects.get(token = item)
#         except Account.DoesNotExist:
#             account = None
#         if account is not None:    
#             email_from = settings.DEFAULT_FROM_EMAIL
#             reply_to = settings.DEFAULT_REPLY_TO_EMAIL
#             ip = settings.REACT_INPUT_ENDPOINT
#             plain_message = render_to_string('users/mail-template.html', { 'ip': ip,'content':message,'title': title})
            
            
#             msg = EmailMultiAlternatives(
#                 "Invitation {title}".format(title="BNI Global"),
#                 message,
#                 email_from,
#                 [account.email],
#                 reply_to=[reply_to]
#             )
#             msg.attach_alternative(plain_message, "text/html")
#             if 'image' in request.FILES:
#                 image=request.FILES["image"]
#                 msg.attach(image.name, image.read(), image.content_type)
#             # msg.attach(image.name, image.read(), image.content_type)
#             msg.send()
#     return Response({"response":"Mail sent successfully"})


@api_view(['POST'])
@permission_classes((AllowAny,)) 
def customer_send_mail(request):
    customer_list_mail_input_serializer=CustomerListMailAPIInputSerializer(data = request.data)
    if not customer_list_mail_input_serializer.is_valid():
        errors = get_error_message(customer_list_mail_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    title = customer_list_mail_input_serializer.data["title"]
    message = customer_list_mail_input_serializer.data["message"]
    # image=request.FILES["image"]
    recipient_list = customer_list_mail_input_serializer.data["recipient_list"]
    for item in recipient_list:
        try:
            account = Account.objects.get(token = item)
        except Account.DoesNotExist:
            account = None
        if account is not None:    
            email_from = settings.DEFAULT_FROM_EMAIL
            reply_to = settings.DEFAULT_REPLY_TO_EMAIL
            ip = settings.REACT_INPUT_ENDPOINT
            plain_message = render_to_string('users/mail-template.html', { 'ip': ip,'content':message,'title': title})
            
            # check email subscription
            mail_sub = subscribe_mail(account.email)
            if mail_sub.subscribed:
                msg = EmailMultiAlternatives(
                    "Invitation {title}".format(title="BNI Global"),
                    message,
                    email_from,
                    [account.email],
                    reply_to=[reply_to]
                )
                msg.attach_alternative(plain_message, "text/html")
                if 'image' in request.FILES:
                    image=request.FILES["image"]
                    msg.attach(image.name, image.read(), image.content_type)
                # msg.attach(image.name, image.read(), image.content_type)
                msg.send()
    return Response({"response":"Mail sent successfully"})


# adding customer list via admin 
@api_view(['POST'])
@permission_classes((AllowAny,)) 
def add_customer(request):
    customer_input_serializer =UserRegistrationSerializer(data = request.data)
    if not customer_input_serializer.is_valid():
        errors = get_error_message(customer_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    name = customer_input_serializer.data["name"]
    email = customer_input_serializer.data["email"]
    location = customer_input_serializer.data["location"]
    lat = customer_input_serializer.data["lat"]
    lan = customer_input_serializer.data["lon"]
    phone = customer_input_serializer.data["phone"]
    password = password_generate(8)
    try:
        user = Account.objects.get(email=email)
    except Account.DoesNotExist:
            user = None
    if user is None:
        try:
            user = Account.objects.create(email = email, password = password, name = name, location = location, phone = phone, lat = lat, lon = lan, create_password = True)
            user.set_password(password) 
            if  'picture' in request.FILES:
                user.picture = request.FILES["picture"]
            user.save()  
            if user is not None:
                invite_mail(user.email, user.token)
                return Response({"response":"Customer Added Successfully!"}, HTTP_200_OK)
            else:
                return Response({"response":"Email or password not correct"}, HTTP_400_BAD_REQUEST)
        except Account.DoesNotExist:
            return Response({"response":"User already exists"}, HTTP_400_BAD_REQUEST)
    else:
        return Response({"response":"User already exists"}, HTTP_400_BAD_REQUEST) 

##get customer list of all member
@api_view(['GET'])
def get_memeber_list(request):
    member_input_serializer=MemberAPIInputSerializer(data = request.query_params)
    if not member_input_serializer.is_valid():
        errors = get_error_message(member_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    page = member_input_serializer.data["page"]
    count = Vendor.objects.all().order_by('id').count()
    member_details = Vendor.objects.all().order_by('id')[((page-1)*10):(page * 10)]
    serializer = VendorSerializer(member_details, many=True, context={'page': page})
    return Response({"vendor_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})

# member_send_mail  
@api_view(['POST'])
def member_send_mail(request):
    customer_list_mail_input_serializer=MemberListMailAPIInputSerializer(data = request.data)
    if not customer_list_mail_input_serializer.is_valid():
        errors = get_error_message(customer_list_mail_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    title = customer_list_mail_input_serializer.data["title"]
    message = customer_list_mail_input_serializer.data["message"]
    recipient_list = customer_list_mail_input_serializer.data["recipient_list"]
    for item in recipient_list:
        try:
            account = Vendor.objects.get(token = item)
        except Vendor.DoesNotExist:
            account = None
        if account is not None:    
            email_from = settings.DEFAULT_FROM_EMAIL
            reply_to = settings.DEFAULT_REPLY_TO_EMAIL
            ip = settings.REACT_INPUT_ENDPOINT
            
            plain_message = render_to_string('users/mail-template.html', { 'ip': ip,'content':message,'title': title})
            msg = EmailMultiAlternatives(
                "Invitation {title}".format(title="BNI Global"),
                message,
                email_from,
                [account.email],
                reply_to=[reply_to]
            )
            msg.attach_alternative(plain_message, "text/html")
            if 'image' in request.FILES:
                image=request.FILES['image']
                msg.attach(image.name, image.read(), image.content_type)
            if msg.send():
                return Response({"response":"Mail sent successfully"})
            else:
                return Response({"response":"Mail not sent"})
    return Response({"response":"Mail not sent"})


    

##update the member detail
@api_view(['POST'])
def update_member_detail(request):
    update_member_input_serializer=UpdateMemberInputSerializer(data = request.data)
    if not update_member_input_serializer.is_valid():
        errors = get_error_message(update_member_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    
    token = update_member_input_serializer.data['vendor_token']
    try:
        member = Vendor.objects.get(token= token)
    except Vendor.DoesNotExist:
        member = None
    if member is not None:
        if  'first_name' in request.data:
            member.first_name = update_member_input_serializer.data['first_name']
        if  'last_name' in request.data:
            member.last_name = update_member_input_serializer.data['last_name']
        if  'email' in request.data:
            member.email = update_member_input_serializer.data['email']
        if  'address_state' in request.data:
            member.address_state = update_member_input_serializer.data['address_state']
        if  'is_active' in request.data:
            member.id_status = update_member_input_serializer.data['is_active']
        member.save()
        response = {"response":'Member Profile Updated successfully'}
        return Response(response)
    else:
        response = {"response":'No such member is found'}
        return Response(response)


#delete a particular member
@api_view(['POST'])
def delete_member(request):
    delete_member_input_serializer=DeleteMemberInputSerializer(data = request.data)
    if not delete_member_input_serializer.is_valid():
        errors = get_error_message(delete_member_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)  
    vendor_token = delete_member_input_serializer.data['vendor_token']
    is_active = False
    if  'is_active' in request.data:
        is_active = delete_member_input_serializer.data['is_active']
    try:
        member = Vendor.objects.get(token= vendor_token)
    except Vendor.DoesNotExist:
        member = None
    if member is not None:
        member.id_status = is_active
        member.save()
        response = {"response":'Member Profile deleted successfully'}
        return Response(response)
    else:
        response = {"response":'No such member is found'}
        return Response(response)

#rating and review
#==================

##review_list
@api_view(['GET'])
def review_list(request):
    review_list_input_serializer = CustomerAPIInputSerializer(data = request.query_params)
    if not review_list_input_serializer.is_valid():
        errors = get_error_message(review_list_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    page = review_list_input_serializer.data["page"]
    count = CustomerReview.objects.count()
    member_request = CustomerReview.objects.all().order_by('-date')[((page-1)*10):(page * 10)]
    serializer = CustomerReviewSerializer(member_request, many=True, context={'page': page})
    return Response({"Review_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})
 
 ##review_list
@api_view(['GET'])
def flagged_review_list(request):
    review_list_input_serializer = CustomerAPIInputSerializer(data = request.query_params)
    if not review_list_input_serializer.is_valid():
        errors = get_error_message(review_list_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    page = review_list_input_serializer.data["page"]
    filter = review_list_input_serializer.data["filter"]
    if filter == 'flag_by_system':
        criterion1 = Q(is_auto_flagged=True) 
    elif filter == 'flag_by_member':
        criterion1 = Q(is_abusive = True)
    else:
        criterion1 = Q(is_auto_flagged=True) | Q(is_abusive = True)

    # count = CustomerReview.objects.count()
    criterion2 = Q(is_approved = False)
    count = CustomerReview.objects.filter(criterion1 & criterion2).count()
    member_request = CustomerReview.objects.filter(criterion1 & criterion2).order_by('-date')[((page-1)*10):(page * 10)]
    serializer = CustomerReviewSerializer(member_request, many=True, context={'page': page})
    return Response({"Review_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})


@api_view(['POST'])
def reply_review(request):
    review_input_serializer = ReplyReviewInputSerializer(data = request.data)
    if not review_input_serializer.is_valid():
        errors = get_error_message(review_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    review_token = review_input_serializer.data["token"]
    try:
        review = CustomerReview.objects.filter(token = review_token).first()
    except CustomerReview.DoesNotExist:
        review = None
    if request.user.is_authenticated:
        email = request.user.email
        try:
            vendor = Vendor.objects.get(email=email)
        except Vendor.DoesNotExist:
            vendor = None
        if vendor is not None:
            if review is not None:
                resp_data = update_review_data(request, review_input_serializer, review)
               
                #CustomerReview.objects.filter(token = review_token).update(reply=reply,comment=comment,is_flagged=is_flagged,is_abusive=is_abusive)
                context = {'response': resp_data}
                return Response(context)
            else:
                return Response({'response': "Review is not updated"}, status = HTTP_400_BAD_REQUEST)
        else:
            return Response({'response': 'Vendor token is wrong'}, status = HTTP_400_BAD_REQUEST)
    else:
        return Response({'response': 'Invalid token.'}, status = HTTP_400_BAD_REQUEST)

# #delete member_request
@api_view(['GET'])
def delete_review(request):
    review_customer_serializer=InputTokenSerializer(data = request.query_params)
    if not review_customer_serializer.is_valid():
        errors = get_error_message(review_customer_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    token = review_customer_serializer.data["token"]
    try:
        contact_request = CustomerReview.objects.get(token = token)
    except CustomerReview.DoesNotExist: 
        contact_request = None
    if contact_request is not None:
        contact_request.delete()
        response = {"response":'Review deleted successfully'}
        return Response(response)
    else:
        response = {"response":'No such Request is found'}
        return Response(response)  

##member Request
@api_view(['GET'])
def contact_request(request):
    contact_request_serializer = CustomerAPIInputSerializer(data = request.query_params)
    if not contact_request_serializer.is_valid():
        errors = get_error_message(contact_request_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    page = contact_request_serializer.data["page"]
    count = Contact.objects.count()
    member_request = Contact.objects.all().order_by('-date')[((page-1)*10):(page * 10)]
    serializer = ContactSerializer(member_request, many=True, context={'page': page})
    return Response({"customer_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})
    
    
    
# #delete member_request1
@api_view(['GET'])
def delete_contact_request(request):
    contact_request_serializer=InputTokenSerializer(data = request.query_params)
    if not contact_request_serializer.is_valid():
        errors = get_error_message(contact_request_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    token = contact_request_serializer.data["token"]
    try:
        member_request = Contact.objects.get(token = token)
    except Contact.DoesNotExist: 
        member_request = None
    if member_request is not None:
        member_request.delete()
        response = {"response":'Member request deleted successfully'}
        return Response(response)
    else:
        response = {"response":'No such Request is found'}
        return Response(response)  

##review_list
@api_view(['GET'])
def content_list(request):
    review_list_input_serializer = CustomerAPIInputSerializer(data = request.query_params)
    if not review_list_input_serializer.is_valid():
        errors = get_error_message(review_list_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    page = review_list_input_serializer.data["page"]
    count = Content.objects.count()
    content_request = Content.objects.all().order_by('-created_on')[((page-1)*10):(page * 10)]
    serializer = ContentSerializer(content_request, many=True, context={'page': page})
    return Response({"content_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})

# Add Content
@api_view(['POST'])
def add_content(request):
    add_content_input_serializer = AddContentInputSerializer(data = request.data)
    if not add_content_input_serializer.is_valid():
        errors = get_error_message(add_content_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    title = add_content_input_serializer.data['title']
    description = add_content_input_serializer.data['description']
    if  'image' in request.FILES:
        image = request.FILES["image"]
        Content.objects.create(title = title, description = description, attachment = image)
    else:
        Content.objects.create(title = title, description = description)
    response = {"response":'Content Added successfully'}
    return Response(response)


# Add Content
@api_view(['GET'])
def delete_content(request):
    delete_content_input_serializer = InputTokenSerializer(data = request.query_params)
    if not delete_content_input_serializer.is_valid():
        errors = get_error_message(delete_content_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    token  = delete_content_input_serializer.data['token']
    try:
        content = Content.objects.get(token = token)
    except Content.DoesNotExist: 
        content = None
    if content is not None:
        content.delete()
        response = {"response":'Content deleted successfully'}
        return Response(response)
    else:
        response = {"response":'No such Request is found'}
        return Response(response) 

# Notification Management
@api_view(['GET'])
def notification_list(request):
    notification_serializer = CustomerAPIInputSerializer(data=request.query_params)
    if not notification_serializer.is_valid():
        errors = get_error_message(notification_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    page = notification_serializer.data["page"]
    count = Notification.objects.count()
    content_details = Notification.objects.all().order_by('-id')[((page-1)*10):(page * 10)]
    serializer = NotificationSerializer(content_details, many=True, context={'page': page})
    return Response({"notification_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})

#Legal
#Terms and Conditions
@api_view(['GET'])
def terms_and_condition(request):
    terms = Policies.objects.filter(id = 1)
    serializer = PoliciesSerializer(terms, many=True)
    return Response({"terms": serializer.data})


#Privacy Policy
@api_view(['GET'])
def privacy_policy(request):
    terms = Policies.objects.filter(id = 2)
    serializer = PoliciesSerializer(terms, many=True)
    return Response({"policy": serializer.data})

#Terms and Conditions
@api_view(['POST'])
def add_terms_and_condition(request):
    legal_input_serializer = PoliciesInputSerializer(data=request.data)
    if not legal_input_serializer.is_valid():
        errors = get_error_message(legal_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    try:
        policy = Policies.objects.get(id = 1)
    except Policies.DoesNotExist:
        policy = None
    if policy is not None:
        policy.modified_on = datetime.now()
        policy.content = legal_input_serializer.data['content']
    if  'content_type' in request.data:
        policy.content_type = legal_input_serializer.data['content_type']
        if  'attachment' in request.FILES:
            policy.attachment = request.FILES["attachment"]
        policy.save()
    return Response({"response": "Data saved successfully!"})

#Add Privacy Policy
@api_view(['POST'])
def add_privacy_policy(request):
    legal_input_serializer = PoliciesInputSerializer(data=request.data)
    if not legal_input_serializer.is_valid():
        errors = get_error_message(legal_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    try:
        policy = Policies.objects.get(id = 2)
    except Policies.DoesNotExist:
        policy = None
    if policy is not None:
        policy.modified_on = datetime.now()
        policy.content = legal_input_serializer.data['content']
        if  'content_type' in request.data:
            policy.content_type = legal_input_serializer.data['content_type']
        if  'attachment' in request.FILES:
            policy.attachment = request.FILES["attachment"]
        policy.save()
    
    return Response({"response": "Data saved successfully!"})

#Cookies Policy
@api_view(['GET'])
def cookies_policy(request):
    terms = Policies.objects.filter(id = 4)
    serializer = PoliciesSerializer(terms, many=True)
    return Response({"cookies_policy": serializer.data})

#Add Cookies Policy
@api_view(['POST'])
def add_cookies_policy(request):
    legal_input_serializer = PoliciesInputSerializer(data=request.data)
    if not legal_input_serializer.is_valid():
        errors = get_error_message(legal_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    try:
        policy = Policies.objects.get(id = 4)
    except Policies.DoesNotExist:
        policy = None
    if policy is not None:
        policy.modified_on = datetime.now()
        policy.content = legal_input_serializer.data['content']
        if  'content_type' in request.data:
            policy.content_type = legal_input_serializer.data['content_type']
        if  'attachment' in request.FILES:
            policy.attachment = request.FILES["attachment"]
        policy.save()
    return Response({"response": "Data saved successfully!"})

# Notification Management
#Add Notification
@api_view(['POST'])
@permission_classes((AllowAny,)) 
def create_notification(request):
    create_notification_input_serializer = CreateNotificationInputSerializer(data=request.data)
    if not create_notification_input_serializer.is_valid():
        errors = get_error_message(create_notification_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    notification_title = create_notification_input_serializer.data["title"]
    description = create_notification_input_serializer.data["description"]
    send_notification = create_notification_input_serializer.data["send_notification"]
    if  'attachment' in request.FILES:
        attachment = request.FILES["attachment"]
        notification = Notification.objects.create(title=notification_title,description=description,attachment=attachment,notification_to=send_notification)
    else:
        notification = Notification.objects.create(title=notification_title,description=description,notification_to=send_notification)
    customers = Account.objects.filter(is_active = True, notification_enabled=True)
    members = Vendor.objects.filter(id_status = True)
    customer = list(customers)
    member = list(members)
    name = ''
    if send_notification == "customer": 
        for item in customer:
            if item.email not in [m.email for m in member]: # check if email is not present in member group
                email = item.email
                name = item.name
                item.notification_alert = True
                item.save()
                
                mail_sub = subscribe_mail(email)
                if mail_sub.subscribed:
                    email_from = settings.DEFAULT_FROM_EMAIL
                    reply_to = settings.DEFAULT_REPLY_TO_EMAIL
                    ip = settings.REACT_INPUT_ENDPOINT
                    plain_message = render_to_string('users/notification-sent.html', { 'ip': ip, 'notification_title': notification_title, 'description': description,'name':name,'email':email})
                    
                    msg = EmailMultiAlternatives(
                    "{title}".format(title=notification_title),
                    notification_title,
                    email_from,
                    [email],
                    reply_to=[reply_to]
                    ) 
                    msg.attach_alternative(plain_message, "text/html")
                    valid = validateEmail(email)
                    if valid:
                        if  'attachment' in request.FILES:
                            attachment = request.FILES["attachment"]
                            msg.attach(attachment.name, attachment.read(), attachment.content_type)
                        msg.send()
                    NotificationList.objects.create(notification = notification, user = item)
        context = {'response': "Notification sent successfully"}
        return Response(context)
    elif send_notification =="both":
        for item in customer:
            email = item.email
            name = item.name
            item.notification_alert = True
            item.save()
            mail_sub = subscribe_mail(email)
            if mail_sub.subscribed:
                email_from = settings.DEFAULT_FROM_EMAIL
                reply_to = settings.DEFAULT_REPLY_TO_EMAIL
                ip = settings.REACT_INPUT_ENDPOINT
                plain_message = render_to_string('users/notification-sent.html', { 'ip': ip, 'notification_title': notification_title, 'description': description,'name':name,'email':email})
            
                msg = EmailMultiAlternatives(
                "{title}".format(title=notification_title),
                notification_title,
                email_from,
                [email],
                reply_to=[reply_to]
                ) 
                msg.attach_alternative(plain_message, "text/html")
                valid = validateEmail(email)
                if valid:
                    if  'attachment' in request.FILES:
                        attachment = request.FILES["attachment"]
                        msg.attach(attachment.name, attachment.read(), attachment.content_type)
                    # msg.send()
                NotificationList.objects.create(notification = notification, user = item)
        context = {'response': "Notification sent successfully"}
        return Response(context)
    else:
        for item in member:
            email = item.email
            name = item.first_name + item.last_name
            # item.notification_alert = True
            # NotificationList.objects.create(notification = notification, user = item)

            item.save()
            mail_sub = subscribe_mail(email)
            if mail_sub.subscribed:
                email_from = settings.DEFAULT_FROM_EMAIL
                ip = settings.REACT_INPUT_ENDPOINT
                plain_message = render_to_string('users/notification-sent.html', { 'ip': ip, 'notification_title': notification_title, 'description': description,'name':name,'email':email})
                reply_to = settings.DEFAULT_REPLY_TO_EMAIL
                msg = EmailMultiAlternatives(
                "{title}".format(title=notification_title),
                notification_title,
                email_from,
                [email],    
                reply_to=[reply_to]
                ) 
                msg.attach_alternative(plain_message, "text/html")
                # msg.send()
            
            context = {'response': "Notification sent successfully"}
            return Response(context)
            
#update Notification
@api_view(['POST'])
def update_notification(request):
    update_notification_serializer=UpdateNotificationInputSerializer(data = request.data)
    if not update_notification_serializer.is_valid():
        errors = get_error_message(update_notification_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    
    token = update_notification_serializer.data['token']
    try:
        notification = Notification.objects.get(token = token)
    except Notification.DoesNotExist:
        notification = None
    if notification is not None:
        notification.title = update_notification_serializer.data['title']
        notification.description = update_notification_serializer.data['description']
        notification.notification_to = update_notification_serializer.data['send_notification']
        if  'attachment' in request.FILES:
            notification.attachment = request.FILES["attachment"]
        notification.save()
        response = {"response":'Notification is updated successfully.'}
        return Response(response)
    else:
        response = {"response":'No such notification is found'}
        return Response(response)

#Delete Notification
@api_view(['GET'])
def delete_notification(request):
    delete_notification_serializer=InputTokenSerializer(data = request.query_params)
    if not delete_notification_serializer.is_valid():
        errors = get_error_message(delete_notification_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    
    token = delete_notification_serializer.data['token']
    try:
        notification = Notification.objects.get(token = token)
    except Notification.DoesNotExist:
        notification = None
    if notification is not None:
        notification.delete()
        response = {"response":'Notification is Deleted'}
        return Response(response)
    else:
        response = {"response":'No such notification is found'}
        return Response(response)

#User Role
@api_view(['GET'])
def user_role(request):
    member_input_serializer=MemberAPIInputSerializer(data = request.query_params)
    if not member_input_serializer.is_valid():
        errors = get_error_message(member_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)    
    page = member_input_serializer.data["page"]
    if page <= 0:
        page = 0
        offset = str((0)*10)
    else:
        offset = str((page-1)*10)
    count = Account.objects.count()
    account = Account.objects.raw('select CASE WHEN m.id IS NULL THEN false ELSE true END AS member,u.id,u.name AS user_name, u.email AS user_email, u.picture , u.last_login, u.phone, u.is_active, u.date_joined, u.token, u.location, m.first_name, m.last_name, m.profile_image, m.email, m.token as member_token, m.address_city, m.address_line1, m.address_line2, m.address_state, m.address_postcode, m.address_country,m.chapter_id, m.secondary_category_id, m.id_status from users_account u left outer join member m on u.email=m.email LIMIT 10 OFFSET '+offset+'')
    user_list = list(account)
    users = []
    if page == 0:
        sl_no = ((page)*10)+1
    else:
        sl_no = ((page-1)*10)+1
    for item in user_list:
        picture = ''
        if item.picture:
            picture = item.picture.url
        users.append({
                's_no': sl_no,
                'is_member':item.member,
                'user_name':item.user_name,
                'user_email':item.user_email,
                'picture': picture,
                'phone': item.phone,
                'is_active' : item.is_active,
                'date_joined': item.date_joined,
                'user_token':item.token,
                'location':item.location,
                'member_first_name': item.first_name,
                'member_last_name': item.last_name,
                'member_profile_image':item.profile_image, 
                'member_email': item.email,
                'member_token':item.member_token, 
                'address_city' : item.address_city,
                'address_line1' : item.address_line1,
                'address_line2': item.address_line2,
                'address_state':item.address_state,
                "address_postcode": item.address_postcode,
                "address_country": item.address_country,
                "status": item.id_status
            })
        sl_no += 1
    return Response({'total_count':count,"total_pages":(int(math.ceil(count/10))),"users": users})

# Update user detail
# #update single customer detail
@api_view(['POST'])
def update_user_detail(request):
    update_profile_input_serializer=UpdateUserProfileInputSerializer(data = request.data)
    if not update_profile_input_serializer.is_valid():
        errors = get_error_message(update_profile_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)     
    token = update_profile_input_serializer.data['user_token']
    try:
        user = Account.objects.get(token= token)
    except Account.DoesNotExist:
        user = None
    if user is not None:
        if  'name' in request.data:
            user.name = update_profile_input_serializer.data['name']
        if  'email' in request.data:
            user.email = update_profile_input_serializer.data['email']
        user.save()
        response = {"response":'User Profile Updated'}
        return Response(response)
    else:
        response = {"response":'No such user is found'}
        return Response(response)

# #update Admin email
@api_view(['POST'])
def update_admin_email(request):
    update_profile_input_serializer=UpdateAdminEmailInputSerializer(data = request.data)
    if not update_profile_input_serializer.is_valid():
        errors = get_error_message(update_profile_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)      
    token = update_profile_input_serializer.data['token']
    try:
        user = Account.objects.get(token= token)
    except Account.DoesNotExist:
        user = None
    if user is not None:
        if  'email' in request.data:
            email = update_profile_input_serializer.data['email']
            try:
                check_user = Account.objects.get(email= email)
            except Account.DoesNotExist:
                check_user = None
            if check_user is None:
                user.email = email
                user.save()
                response = {"response":'Email Updated Successfully'}
                return Response(response)
            else:
               return Response({"response":'Email Already Exist in another account'},status = HTTP_400_BAD_REQUEST) 
    else:
        response = {"response":'no such user is found'}
        return Response(response, status = HTTP_400_BAD_REQUEST)


# #update single customer detail
@api_view(['POST'])
@permission_classes((AllowAny,)) 
def update_admin_password(request):
        update_password_input_serializer = UpdatePasswordInputSerializer(data = request.data)
        if not update_password_input_serializer.is_valid():
            errors = get_error_message(update_password_input_serializer)
            return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)    
        token = update_password_input_serializer.data["user_token"]
        try:
            check_user = Account.objects.get(token= token)
        except Account.DoesNotExist:
            check_user = None
        user = Account.objects.get(token=token)
        if check_user is not None:
            password = update_password_input_serializer.data["password"]
            user.set_password(password) 
            user.save()  
            return Response({"response":"Admin Password changed successfully"})
        else:
            return Response({"response":'Check the User'},status = HTTP_400_BAD_REQUEST) 


# Reports
# Total Customer report
@api_view(['POST'])
def customer_report(request):
    total_customer_input_serializer=ReportInputSerializer(data = request.data)
    if not total_customer_input_serializer.is_valid():
        errors = get_error_message(total_customer_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)    
    from_date = total_customer_input_serializer.data['from_date']
    to_date = total_customer_input_serializer.data['to_date']
    page = total_customer_input_serializer.data['page']

    if from_date != "" and to_date != "":
        count = Account.objects.all().filter(date_joined__gte=from_date,date_joined__lte=to_date, is_active=True).count()
        customer_details = Account.objects.filter(date_joined__gte=from_date,date_joined__lte=to_date, is_active=True).order_by('-date_joined')[((page-1)*10):(page * 10)]
        serializer = UserSerializer(customer_details, many=True, context={'page': page})
        return Response({"customer_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})
    else:
        count = Account.objects.count()
        customer_details = Account.objects.all().order_by('-date_joined')[((page-1)*10):(page * 10)]
        serializer = UserSerializer(customer_details, many=True, context={'page': page})
        return Response({"customer_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})

# Total Customer report
@api_view(['POST'])
def member_report(request):
    total_customer_input_serializer=ReportInputSerializer(data = request.data)
    if not total_customer_input_serializer.is_valid():
        errors = get_error_message(total_customer_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST) 
    from_date = total_customer_input_serializer.data['from_date']
    to_date = total_customer_input_serializer.data['to_date']
    page = total_customer_input_serializer.data['page']

    if from_date != "" and to_date != "":
        count = Vendor.objects.all().filter(induction_date__gte=from_date,induction_date__lte=to_date,  id_status =True).count()
        customer_details = Vendor.objects.filter(induction_date__gte=from_date,induction_date__lte=to_date,  id_status =True).order_by('-induction_date')[((page-1)*10):(page * 10)]
        serializer = VendorSerializer(customer_details, many=True, context={'page': page})
        return Response({"member_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})
    else:
        count = Vendor.objects.count()
        customer_details = Vendor.objects.all().order_by('-induction_date')[((page-1)*10):(page * 10)]
        serializer = VendorSerializer(customer_details, many=True, context={'page': page})
        return Response({"member_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})


@api_view(['POST'])
def search_report(request):
    total_searches_input_serializer=ReportInputSerializer(data = request.data)
    if not total_searches_input_serializer.is_valid():
        errors = get_error_message(total_searches_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    
    from_date = total_searches_input_serializer.data['from_date']
    to_date = total_searches_input_serializer.data['to_date']
    page = total_searches_input_serializer.data["page"]

    if from_date != "" and to_date != "":
        search_list = MySearch.objects.filter(date__gte=from_date,date__lte=to_date).values_list('category_name').distinct()[((page-1)*10):(page * 10)]
        count = MySearch.objects.filter(date__gte=from_date,date__lte=to_date).count()
        search_array =[]
        sl_no = 1
        for item in search_list:
            for name in item:
                total_search = MySearch.objects.filter(date__gte=from_date,date__lte=to_date, category_name = name).count()
                context = {"type":name, "count": total_search, "s_no": sl_no}
                search_array.append(context)
                
        return Response({"total_count":count,"total_search":search_array,"total_pages": (int(math.ceil(len(search_array)/10)))})
    else:
        search_list = MySearch.objects.all().values_list('category_name').distinct()[((page-1)*10):(page * 10)]
        count = MySearch.objects.count()
        search_array =[]
        sl_no = 1
        for item in search_list:
            for name in item:
                total_search = MySearch.objects.filter(category_name = name).count()
                context = {"type":name, "count": total_search, "s_no": sl_no}
                search_array.append(context)
                sl_no += 1
        return Response({"total_count":count,"total_search":search_array,"total_pages":(int(math.ceil(len(search_array)/10)))}) 

@api_view(['POST'])
def geographical_search_report(request):
    total_searches_input_serializer=ReportInputSerializer(data = request.data)
    if not total_searches_input_serializer.is_valid():
        errors = get_error_message(total_searches_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)

    
    from_date = total_searches_input_serializer.data['from_date']
    to_date = total_searches_input_serializer.data['to_date']
    page = total_searches_input_serializer.data["page"]

    if from_date != "" and to_date != "":
        search_list = MySearch.objects.filter(date__gte=from_date,date__lte=to_date).values_list('location').distinct()[((page-1)*10):(page * 10)]
        count = MySearch.objects.filter(date__gte=from_date,date__lte=to_date).count()
        search_array =[]
        sl_no = 1
        for item in search_list:
            for name in item:
                total_search = MySearch.objects.filter(date__gte=from_date,date__lte=to_date, location = name).count()
                context = {"type":name, "count": total_search, "s_no": sl_no}
                search_array.append(context)
                sl_no += 1
        return Response({"total_count":count,"total_search":search_array,"total_pages":(int(math.ceil(len(search_array)/10)))})
    else:
        search_list = MySearch.objects.all().values_list('location').distinct()[((page-1)*10):(page * 10)]
        count = MySearch.objects.count()
        search_array =[]
        sl_no = 1
        for item in search_list:
            for name in item:
                total_search = MySearch.objects.filter(location = name).count()
                context = {"type":name, "count": total_search, "s_no": sl_no}
                search_array.append(context)
                sl_no += 1
        return Response({"total_count":count,"total_search":search_array,"total_pages":(int(len(search_array)/10)+1)}) 

@api_view(['POST'])
def contact_report(request):
    total_contact_sent_serializer=ReportInputSerializer(data = request.data)
    if not total_contact_sent_serializer.is_valid():
        errors = get_error_message(total_contact_sent_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    
    from_date = total_contact_sent_serializer.data['from_date']
    to_date = total_contact_sent_serializer.data['to_date']
    page = total_contact_sent_serializer.data["page"]

    if from_date != "" and to_date != "":
        contact_list = Contact.objects.all().values_list('vendor_id').distinct()[((page-1)*10):(page * 10)]
        count = Contact.objects.filter(date__gte=from_date,date__lte=to_date).values_list('vendor_id').count()
        contact_array =[]
        sl_no = 1
        for item in contact_list:
            for name in item:
                total_search = Contact.objects.filter(date__gte=from_date,date__lte=to_date, vendor_id = name).count()
                vendor = Vendor.objects.get(id=name)
                name = f'{vendor.first_name} {vendor.last_name}'
                context = {"type":name, "count": total_search, "s_no": sl_no}
                contact_array.append(context)
                sl_no += 1
        return Response({"total_count":count,"contacts":contact_array,"total_pages":(int(math.ceil(len(contact_array)/10)))})
    else:
        contact_list = Contact.objects.all().values_list('vendor_id').distinct()[((page-1)*10):(page * 10)]
        count = Contact.objects.count()
        contact_array =[]
        sl_no = 1
        for item in contact_list:
            for name in item:
                total_search = Contact.objects.filter( vendor_id = name).count()
                vendor = Vendor.objects.get(id=name)
                name = f'{vendor.first_name} {vendor.last_name}'
                context = {"type":name, "count": total_search, "s_no": sl_no}
                contact_array.append(context)
                sl_no += 1
        return Response({"total_count":count,"contacts":contact_array,"total_pages":(int(math.ceil(len(contact_array)/10)))})



#list help data
@api_view(['GET'])
def help_list(request):
    review_list_input_serializer = CustomerAPIInputSerializer(data = request.query_params)
    if not review_list_input_serializer.is_valid():
        errors = get_error_message(review_list_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    page = review_list_input_serializer.data["page"]
    count = Help.objects.filter(is_active = True).count()
    content_request = Help.objects.filter(is_active = True).order_by('-created_on')[((page-1)*10):(page * 10)]
    serializer = HelpSerializer(content_request, many=True, context={'page': page})
    return Response({"help_list": serializer.data,"total_count":count,"total_pages":(int(math.ceil(count/10)))})

#add help data
@api_view(['POST'])
def add_help_data(request):
    add_help_input_serializer = AddHelpInputSerializer(data=request.data)
    if not add_help_input_serializer.is_valid():
        errors = get_error_message(add_help_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    title = add_help_input_serializer.data['title']
    description = add_help_input_serializer.data['description']
    content_type = add_help_input_serializer.data['content_type']

    if  'attachment' in request.FILES:
        attachment = request.FILES["attachment"]
    else:
        attachment = ""
    Help.objects.create(title=title,description=description,attachment=attachment,created_on =datetime.now(),content_type=content_type)
    response ={"response":"Helping data created suceesfully"} 
    return Response(response)

#update help data
@api_view(['POST'])
def update_help_data(request):
    update_help_input_serializer = UpdateHelpInputSerializer(data=request.data)
    if not update_help_input_serializer.is_valid():
        errors = get_error_message(update_help_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    token = update_help_input_serializer.data['token']
    try:
        data = Help.objects.get(token= token)
    except Help.DoesNotExist:
        response = {"response":'no such help data is found'}
        return Response(response)

    if 'title' in request.data:
        data.title = update_help_input_serializer.data['title']
    if 'description' in request.data:
        data.description = update_help_input_serializer.data['description']
    if 'content_type' in request.data:
        data.content_type = update_help_input_serializer.data['content_type']
    if 'attachment' in request.FILES:
        if data.attachment is not None and data.attachment != "" and os.path.exists(data.attachment.path):
            os.remove(data.attachment.path)
        data.attachment = request.FILES["attachment"]
    data.modified_on =datetime.now()
    data.save()
    response ={"response":"help data is updated"}
    return Response(response)
    

@api_view(['GET'])
def delete_help_data(request):
    delete_help_input_serializer = InputTokenSerializer(data=request.query_params)
    if not delete_help_input_serializer.is_valid():
        errors = get_error_message(delete_help_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    token = delete_help_input_serializer.data['token']
    try:
        data = Help.objects.get(token= token)
    except Help.DoesNotExist:
        data = None
    if data is not None:
        data.is_active = False
        data.save()
        response = {"response":'help data is Deleted'}
        return Response(response)
    else:
        response = {"response":'No such data is found'}
        return Response(response)

#Service Provider
@api_view(['GET'])
def service_provider(request):
    terms = Policies.objects.filter(id = 3)
    serializer = PoliciesSerializer(terms, many=True)
    return Response({"service_provider": serializer.data})

#Update Service Provider
@api_view(['POST'])
def update_service_provider(request):
    service_provider_input_serializer = LegalInputSerializer(data=request.data)
    if not service_provider_input_serializer.is_valid():
        errors = get_error_message(service_provider_input_serializer)
        return Response({'response':errors}, status = HTTP_400_BAD_REQUEST)
    try:
        policy = Policies.objects.get(id = 3)
    except Policies.DoesNotExist:
        policy = None
    if policy is not None:
        policy.modified_on = datetime.now()
        policy.content = service_provider_input_serializer.data['content']
        policy.save()
    return Response({"response": "Data updated successfully!"})

def get_error_message(serializer):
    errors = ""
    for error in serializer.errors:
        er = serializer.errors[error][0]
        errors += error 
        errors += "  "
        errors += er
    return errors

# Add Abusive words
@api_view(['POST'])
@permission_classes((AllowAny,))
def add_bad_words(request):
    req_body = request.body # json.loads(request.body.decode('utf-8'))
    words = json.loads(smart_str(req_body.decode('utf-8')))
    bad_words = list(words)
    # print(bad_words)
    for item in bad_words:
        word = item['word']
        try:
            secondary_category = AbusiveWords.objects.get(words=word)
        except AbusiveWords.DoesNotExist:
            secondary_category = None
        if secondary_category is None:
            words = AbusiveWords.objects.create(words=word)

    response = {"response":'Data Added Successfully'}
    return Response(response)

#delete a particular member
@api_view(['GET'])
@permission_classes((AllowAny,))
def add_services(request):
    connection_list = Vendor.objects.raw('SELECT `chapter_id`, `id`, `secondary_category_id` FROM `member` GROUP by chapter_id')
    for item in connection_list:
        Vendor.objects.filter(id=item.id)
        Services.objects.create(vendor_id = item.id, category_id=item.secondary_category_id, user_id=213)
    response = {"response":'No such member is found'}
    return Response(response)

# Add state
@api_view(['POST'])
@permission_classes((AllowAny,))
def add_state(request):
    req_body = request.body 
    words = json.loads(smart_str(req_body.decode('utf-8')))
    bad_words = list(words)
   
    for item in bad_words:
        code = item['code']
        name = item['name']
        PilotState.objects.create(code=code, name=name)

    response = {"response":'Data Added Successfully'}
    return Response(response)

def replace_all(text, dic):
    for i, j in dic.items():
        text = text.replace(i, j)
    return text

def update_review_data(request, review_input_serializer, review):
    reply = review_input_serializer.data["reply"]
    comment = review_input_serializer.data["comment"]
    is_flagged = review_input_serializer.data['is_flagged']
    is_abusive = review_input_serializer.data['is_abusive']
    if  'reply' in request.data:
        review.reply = reply
    if  'comment' in request.data:
        review.comment = comment
    if  'is_flagged' in request.data:
        review.is_flagged = is_flagged
    if  'is_abusive' in request.data:
        review.is_abusive = is_abusive 
    if  'is_approved' in request.data:
        review.is_approved = review_input_serializer.data['is_approved']
    if  'approved_by' in request.data:
        review.approved_by = review_input_serializer.data['approved_by']
    if  'is_auto_flagged' in request.data:
        review.is_auto_flagged = review_input_serializer.data['is_auto_flagged']
    review.save()
    return "Review Update Successfully."

def update_customer_data(request, update_profile_input_serializer, user):
    if  'name' in request.data:
        user.name = update_profile_input_serializer.data['name']
    if  'email' in request.data:
            user.email = update_profile_input_serializer.data['email']
    if  'phone' in request.data:
        user.phone = update_profile_input_serializer.data['phone']
    if  'location' in request.data:
        user.location = update_profile_input_serializer.data['location']
    if  'lat' in request.data:
        user.lat = update_profile_input_serializer.data['lat']
    if  'lon' in request.data:
        user.lon = update_profile_input_serializer.data['lon']
    if  'picture' in request.FILES:
        user.picture = request.FILES["picture"]
    if  'is_active' in request.data:
        user.is_active = update_profile_input_serializer.data['is_active']
    user.save()
    return 'Customer detail updated successfully.'

def password_generate(count):
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation
    alphabet = letters + digits + special_chars
    pwd = ''
    for _ in range(count):
        pwd += ''.join(secrets.choice(alphabet))
    return pwd

def invite_mail(email, token):
    mail_sub = subscribe_mail(email)
    if mail_sub.subscribed:
        email_from = settings.DEFAULT_FROM_EMAIL
        ip = settings.REACT_INPUT_ENDPOINT
        reply_to = settings.DEFAULT_REPLY_TO_EMAIL
        email_plaintext_message = ip+"/#/create_password/?token="+token 
        mail_temp = MailTemplate.objects.filter(id=11).first()

        if mail_temp is not None:
            content = f'''{mail_temp.mail_html_content}'''
            plain_txt_message = f'''{mail_temp.mail_txt_content}'''
            d = { '{ip}': ip, '{url}': email_plaintext_message, '{email}': email}
            content = replace_all(content, d)
            plain_message = replace_all(plain_txt_message, d)
            # subscribe_mail(email)
            msg = EmailMultiAlternatives(
                "Create New Password",
                plain_message,
                email_from,
                [email],
                reply_to=[reply_to]
            )
            msg.attach_alternative(content, "text/html")
            msg.send()

# def subscribe_mail(email):
#     try:
#         _ = MailSubscription.objects.filter(email = email)
#     except MailSubscription.DoesNotExist:
#         MailSubscription.objects.create(email=email)

def validateEmail( email ):
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError
    try:
        validate_email( email )
        return True
    except ValidationError:
        return False
    
    
def subscribe_mail(email):
    try:
        mail_sub = MailSubscription.objects.get(email = email)
    except MailSubscription.DoesNotExist:
       mail_sub = MailSubscription.objects.create(email=email)
    return mail_sub


from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db.models import Count
from users.models import Referral, Account, CustomerReview, Contact, MySearch,Translation


# import datetime

# # Get the current date
# today = datetime.date.today()

# # Calculate the date of the most recent Friday
# friday = today - datetime.timedelta(days=(today.weekday() + 2) % 7)

# # Calculate the date of the most recent Thursday
# thursday = friday + datetime.timedelta(days=6)

# # Set the start and end dates to the Friday and Thursday dates
# start_date = friday
# end_date = thursday

# # Use the start and end dates to query the database
# review_count = CustomerReview.objects.filter(date__gte=start_date, date__lte=end_date).count()
# search_count = MySearch.objects.filter(date__gte=start_date, date__lte=end_date).count()


from datetime import datetime, date,timedelta
from django.db.models import Count,Sum
import datetime
from django.db.models import Count, Sum
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from itertools import groupby
@api_view(['GET'])
@permission_classes([AllowAny])
def analytics(request):
  
    # Get the current date
    today = date.today()

    # Calculate the Friday and Thursday dates for the current week
    friday = today - timedelta(days=today.weekday()) + timedelta(days=4)
    last_friday = friday - timedelta(days=7)
   
    # Counts from last Friday to this Friday
    #account_count = Account.objects.exclude(email__in=Vendor.objects.values('email')).count()
    account_count = Account.objects.filter(is_active = True).count()
    invite_count = Referral.objects.filter(invitation_sent_date__gte=last_friday, invitation_sent_date__lte=friday).count()
    review_count = CustomerReview.objects.filter(date__gte=last_friday, date__lte=friday).count()
    search_count = MySearch.objects.filter(date__gte=last_friday, date__lte=friday).count()
    inquiry_count = CustomerReview.objects.filter(date__gte=last_friday, date__lte=friday).count()
    newaccount_count = Account.objects.filter(date_joined__gte=last_friday, date_joined__lte=friday).count()
    successful_login_count = LoginLogs.objects.filter(creation_date__gte=last_friday, creation_date__lte=friday, login_success=True).count()
    login_attempt_count = LoginLogs.objects.filter(creation_date__gte=last_friday, creation_date__lte=friday).count()
    unique_user_count = LoginLogs.objects.filter(login_success=True,creation_date__gte=last_friday, creation_date__lte=friday).values('email').distinct().count()
   

    #total rating and review for the vendor
    vendor_reviews = CustomerReview.objects.values('vendor__id', 'vendor__first_name','vendor__last_name' ,'vendor__secondary_category__name').annotate(avg_rating=Avg('rating'), total_reviews=Count('id'), total_rating=Sum('rating')).order_by('-total_rating')[:5]
  
   
    vendor_data = []
    for item in vendor_reviews:
        translation =  Translation.objects.filter(token=item['vendor__secondary_category__name']).values('translation').first()
        
        if translation: 
            translate = translation["translation"]
        vendor_dict = {
            'member_firstname': item['vendor__first_name'],
            'member_last_name': item['vendor__last_name'],
            'category_name': translate,
            'avg_rating': item['avg_rating'],
            'total_reviews': item['total_reviews'],
            'total_rating': item['total_rating']
        }
        vendor_data.append(vendor_dict)
        
    #top search categories count 
    top_categories = MySearch.objects.values('category_name').annotate(NoOfSearches=Count('category_name')).order_by('-NoOfSearches').all()[:5]
    
    #most searched categories based on location
 
    locations = MySearch.objects.values('location').annotate(
            category_count=Count('category_name')
        ).order_by('-category_count')[:10]
        
    search_data = []
    for location in locations:
        location_data = {'title': location['location'], 'value': []}
        categories = MySearch.objects.filter(location=location['location']).values('category_name').annotate(
            category_count=Count('category_name')
        ).order_by('-category_count')[:5]
        for category in categories:
            location_data['value'].append({
                'category_name': category['category_name'],
                'category_count': category['category_count']
            })
        search_data.append(location_data)

    
    # Get the total searches count by member
    member_search_count = MySearch.objects.filter(user__in=Account.objects.values('id').filter(email__in=Vendor.objects.values('email'))).count()

    # Get the total searches count by customer
    customer_search_count = MySearch.objects.filter(user__in=Account.objects.values('id').exclude(email__in=Vendor.objects.values('email'))).count()

    # Get the total searches count by general person (neither a member nor a customer)
    general_search_count = MySearch.objects.filter(user__isnull=True).count()

    # Get the total searches count
    total_search_count = member_search_count + customer_search_count + general_search_count

   
  
    
    data = {

        
        "search_data": search_data,
        "vendor_data": vendor_data,
        
        "top_categories":top_categories,
        
        "total_unique_user_count": unique_user_count,
        "total_account_count":account_count,
        "total_invite_count":invite_count,
        "total_review_count":review_count,
        "total_search_count":search_count,
        "total_inquiry_count":inquiry_count,
        "total_newaccount_count":newaccount_count,
        "total_successful_login_count":successful_login_count,
        "total_login_attempt":login_attempt_count,
        
        # "total_search_count":total_search_count,
        "member_search_count":member_search_count,
        "customer_search_count":customer_search_count,
        "general_search_count":general_search_count,
      
         
    }

    return Response(data)



# @api_view(['GET'])
# @permission_classes([AllowAny,])
# def analytics(request):
#     # Define the start and end dates for the one week period
#     start_date = datetime(2023, 3, 17)
#     end_date = datetime(2023, 3, 24)
    
#     #oneweek counts from 17-3-2023 to 24-3-2023
#     account_count = Account.objects.exclude(email__in=Vendor.objects.values('email')).count()
#     invite_count = Referral.objects.filter(invitation_sent_date__gte=start_date, invitation_sent_date__lte=end_date).count()
#     review_count = CustomerReview.objects.filter(date__gte=start_date, date__lte=end_date).count()
#     search_count = MySearch.objects.filter(date__gte=start_date, date__lte=end_date).count()
#     inquiry_count = CustomerReview.objects.filter(date__gte=start_date, date__lte=end_date).count()
#     newaccount_count = Account.objects.filter(date_joined__gte=start_date, date_joined__lte=end_date).count()
#     successful_login_count=LoginLogs.objects.filter(creation_date__gte=start_date,creation_date__lte =end_date, login_success=True).count()
#     login_attempt_count = LoginLogs.objects.filter(creation_date__gte=start_date,creation_date__lte =end_date).count()
#     unique_user_count = Account.objects.filter(last_login__gte=start_date, last_login__lte=end_date).count()
    
#     #total rating and review for the vendor
#     vendor_reviews = CustomerReview.objects.values('vendor__id', 'vendor__first_name', 'vendor__secondary_category__name').annotate(avg_rating=Avg('rating'), total_reviews=Count('id'), total_rating=Sum('rating'))[:5]
#     vendor_data = []
#     for item in vendor_reviews:
#         vendor_dict = {
#             'member_name': item['vendor__first_name'],
#             'category_name': item['vendor__secondary_category__name'],
#             'avg_rating': item['avg_rating'],
#             'total_reviews': item['total_reviews'],
#             'total_rating': item['total_rating']
#         }
#         vendor_data.append(vendor_dict)
        
#     #top search categories count 
#     top_categories = MySearch.objects.values('category_name').annotate(NoOfSearches=Count('category_name')).order_by('-NoOfSearches').all()[:5]
    
#     #most searched categories based on location
    
#     search_data = MySearch.objects.values('location', 'category_name').annotate(count=Count('id')).order_by('-count')[:50]
    
    
#     data = {}
    
#     # Loop through the search data to create the output dictionary
#     for result in search_data:
#         location_name = result['location']
#         category_name = result['category_name']
#         category_count = result['count']
        
#         # If the location hasn't been added to the dictionary yet, add it
#         if location_name not in data:
#             data[location_name] = []
        
#         # Add the category and count to the location's list
#         data[location_name].append({
#             'category_name': category_name,
#             'category_count': category_count
#         })
    
    
#     for location_name in data.keys():
#         # Sort the categories by count in descending order
#         categories = sorted(data[location_name], key=lambda x: x['category_count'], reverse=True)
      
#         categories = categories[:5]
       
#         data[location_name] = categories
    
  
#     searchcategories_location = []
#     for location_name, categories in data.items():
#         searchcategories_location.append({
#             'title': location_name,
#             'value': categories
#         })
    
#     # Get the total searches count by member
#     member_search_count = MySearch.objects.filter(user__in=Account.objects.values('id').filter(email__in=Vendor.objects.values('email'))).count()

#     # Get the total searches count by customer
#     customer_search_count = MySearch.objects.filter(user__in=Account.objects.values('id').exclude(email__in=Vendor.objects.values('email'))).count()

#     # Get the total searches count by general person (neither a member nor a customer)
#     general_search_count = MySearch.objects.filter(user__isnull=True).count()

#     # Get the total searches count
#     total_search_count = member_search_count + customer_search_count + general_search_count

   
  
    
#     data = {

        
#         "search_data": searchcategories_location,
#         "vendor_data": vendor_data,
        
#         "top_categories":top_categories,
        
#         "total_unique_user_count": unique_user_count,
#         "total_account_count":account_count,
#         "total_invite_count":invite_count,
#         "total_review_count":review_count,
#         "total_search_count":search_count,
#         "total_inquiry_count":inquiry_count,
#         "total_newaccount_count":newaccount_count,
#         "total_successful_login_count":successful_login_count,
#         "total_login_attempt":login_attempt_count,
        
#         "total_search_count":total_search_count,
#         "member_search_count":member_search_count,
#         "customer_search_count":customer_search_count,
#         "general_search_count":general_search_count,
      
        
        
        
#     }

#     return Response(data)

from django.db.models import Count

@api_view(['GET'])
@permission_classes([AllowAny,])
def top_categories(request):
    top_categories = MySearch.objects.values('category_name').annotate(NoOfSearches=Count('category_name')).order_by('-NoOfSearches').all()[:5]                               
    response_data = {'categories': list(top_categories)}
    return Response(response_data)





# @api_view(['GET'])
# @permission_classes([AllowAny,])
# def total_searches(request):
#     # Get the total searches count by member
#     member_search_count = MySearch.objects.filter(user__in =Account.objects.values('id').filter(email__in=Vendor.objects.values('email'))).count()

#     # Get the total searches count by cutomer
#     customer_search_count = MySearch.objects.filter(user__in =Account.objects.values('id').exclude(email__in=Vendor.objects.values('email'))).count()

#     # Return the search count as a JSON response
#     return Response({
       
#         'customer_search_count': customer_search_count,
#         'member_search_count':member_search_count
#     })

@api_view(['GET'])
@permission_classes([AllowAny,])
def total_searches(request):
    # Get the total searches count by member
    member_search_count = MySearch.objects.filter(user__in = Account.objects.values('id').filter(email__in = Vendor.objects.values('email'))).count()

    # Get the total searches count by customer
    customer_search_count = MySearch.objects.filter(user__in = Account.objects.values('id').exclude(email__in = Vendor.objects.values('email'))).count()

    # Get the total searches count by general person (neither a member nor a customer)
    general_search_count = MySearch.objects.filter(user__isnull = True).count()
    
    # Get the total searches count
    total_search_count = member_search_count + customer_search_count + general_search_count

    # Return the search count as a JSON response
    return Response({
        'customer_search_count': customer_search_count,
        'member_search_count': member_search_count,
        'general_search_count': general_search_count,
        'total_search_count': total_search_count,
    })






# @api_view(['GET'])
# @permission_classes([AllowAny,])
# def most_searched_categories_based_on_location(request):
   
#     search_data = MySearch.objects.values('location', 'category_name').annotate(count=Count('id')).order_by('-count')[:50]
    
#     # Initialize a dictionary to store the output
#     data = {}
    
   
#     for result in search_data:
#         location_name = result['location']
#         category_name = result['category_name']
#         category_count = result['count']
        
#         # If the location hasn't been added to the dictionary yet, add it
#         if location_name not in data:
#             data[location_name] = []
        
#         # Add the category and count to the location's list
#         data[location_name].append({
#             'category_name': category_name,
#             'category_count': category_count
#         })
        
       
#         # data[location_name] = sorted(data[location_name], key=lambda x: x['category_count'], reverse=True)[:5]
    
#     return Response(data)

@api_view(['GET'])
@permission_classes([AllowAny,])
def most_searched_categories_based_on_location(request):
    
    search_data = MySearch.objects.values('location', 'category_name').annotate(count=Count('id')).order_by('-count')[:50]
    
    
    data = {}
    
    # Loop through the search data to create the output dictionary
    for result in search_data:
        location_name = result['location']
        category_name = result['category_name']
        category_count = result['count']
        
        # If the location hasn't been added to the dictionary yet, add it
        if location_name not in data:
            data[location_name] = []
        
        # Add the category and count to the location's list
        data[location_name].append({
            'category_name': category_name,
            'category_count': category_count
        })
    
    
    for location_name in data.keys():
        # Sort the categories by count in descending order
        categories = sorted(data[location_name], key=lambda x: x['category_count'], reverse=True)
      
        categories = categories[:5]
       
        data[location_name] = categories
    
  
    output = []
    for location_name, categories in data.items():
        output.append({
            'title': location_name,
            'value': categories
        })
    
    return Response(output)








# #googler amnalytics

# """Hello Analytics Reporting API V4."""

# from apiclient.discovery import build
# from oauth2client.service_account import ServiceAccountCredentials


# SCOPES = ['https://www.googleapis.com/auth/analytics.readonly']
# KEY_FILE_LOCATION = '/Users/manikraja/Downloads/bni-analytics-375606-2623189d31c1.json'
# VIEW_ID = 283378601


# def initialize_analyticsreporting():
#   """Initializes an Analytics Reporting API V4 service object.

#   Returns:
#     An authorized Analytics Reporting API V4 service object.
#   """
#   credentials = ServiceAccountCredentials.from_json_keyfile_name(
#       KEY_FILE_LOCATION, SCOPES)

#   # Build the service object.
#   analytics = build('analyticsreporting', 'v4', credentials=credentials)

#   return analytics


# def get_report(analytics):
#   """Queries the Analytics Reporting API V4.

#   Args:
#     analytics: An authorized Analytics Reporting API V4 service object.
#   Returns:
#     The Analytics Reporting API V4 response.
#   """
#   return analytics.reports().batchGet(
#       body={
#         'reportRequests': [
#         {
#           'viewId': '283378601',
#           'dateRanges': [{'startDate': '7daysAgo', 'endDate': 'today'}],
#           'metrics': [{'expression': 'ga:sessions'}],
#           'dimensions': [{'name': 'ga:country'}]
#         }]

#       }
#   ).execute()


# def print_response(response):
#   """Parses and prints the Analytics Reporting API V4 response.

#   Args:
#     response: An Analytics Reporting API V4 response.
#   """
#   for report in response.get('reports', []):
#     columnHeader = report.get('columnHeader', {})
#     dimensionHeaders = columnHeader.get('dimensions', [])
#     metricHeaders = columnHeader.get('metricHeader', {}).get('metricHeaderEntries', [])

#     for row in report.get('data', {}).get('rows', []):
#       dimensions = row.get('dimensions', [])
#       dateRangeValues = row.get('metrics', [])

#       for header, dimension in zip(dimensionHeaders, dimensions):
#         print(header + ': ', dimension)

#       for i, values in enumerate(dateRangeValues):
#         print('Date range:', str(i))
#         for metricHeader, value in zip(metricHeaders, values.get('values')):
#           print(metricHeader.get('name') + ':', value)


# def main():
#   analytics = initialize_analyticsreporting()
#   response = get_report(analytics)
#   print_response(response)

# if __name__ == '__main__':
#   main()


#adding new functions
def login_sample(request):
    pass




    

