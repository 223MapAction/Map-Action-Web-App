import subprocess
from django.db.models import Q
from django.shortcuts import render, HttpResponse
from django.core.serializers import serialize
from rest_framework import status, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from .serializer import *
from django.middleware.csrf import get_token
from django.http import JsonResponse
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication, SessionAuthentication, BasicAuthentication
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import PasswordChangeView
from django.conf import settings
from django.db import IntegrityError
from rest_framework.permissions import IsAuthenticated
from backend.settings import *
import json
import datetime
import requests
from django.template.loader import get_template, render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives, send_mail
import random
import string

import httpx
from celery.result import AsyncResult
from .tasks import prediction_task, OverpassCall

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.settings import api_settings
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
import overpy
from rest_framework.exceptions import NotFound, ValidationError
import pyotp
import os
from twilio.rest import Client




class CustomPageNumberPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000


N = 7

def get_csrf_token(request):
    csrf_token = get_token(request)
    return JsonResponse({'csrf_token': csrf_token})
@extend_schema(
    description="Endpoint for retrieval token by email",
    request = UserSerializer,
    responses = {201: UserSerializer, 400:"Bad request"}
)
class GetTokenByMailView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def post(self, request, *args, **kwargs):
       
        try:
            item = User.objects.get(email=request.data['email'])
        except User.DoesNotExist:
            return Response(status=404)
        
        # Générer le token d'accès
        token = AccessToken.for_user(item)
        
        return Response({
            "status": "success",
            "message": "item successfully created",
            'token': str(token)
        }, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@extend_schema(
    description="Endpoint allowing user login. Authenticates user with provided email and password.",
    request=None,  
    responses={200: UserSerializer, 401: "Unauthorized"},
    parameters=[
        OpenApiParameter(name='email', description='User email', required=True, type=str),
        OpenApiParameter(name='password', description='User password', required=True, type=str),
    ]
)
def login_view(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(email=email, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            token = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            return Response({'user': UserSerializer(user).data, 'token': token}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        

@api_view(['GET', 'POST'])
@extend_schema(
    description="Endpoint allowing retrieval and creation of users. Retrieves all users from the database and register a new user",
    request=UserSerializer,
    responses={201: UserSerializer, 400: "Bad request"},
    parameters=[
        OpenApiParameter(name='first_name', description='First name of the user', required=True, type=str),
        OpenApiParameter(name='last_name', description='Last name of the user', required=True, type=str),
        OpenApiParameter(name='phone', description='Phone number of the user', required=False, type=str),
        OpenApiParameter(name='address', description='Address of the user', required=False, type=str),
        OpenApiParameter(name='email', description='Email of the user', required=True, type=str),
        OpenApiParameter(name='password', description='Password of the user', required=True, type=str),
    ],
    examples=[
        OpenApiExample(name='User', value={
            'first_name': 'Annoura',
            'last_name': 'Toure',
            'phone': '20303020',
            'address': 'Mali',
            'email': 'john@example.com',
            'password': 'secret_password'
        })
    ]
)
def UserRegisterView(request):
    if request.method == 'GET':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            token = {
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }
            return Response({'user': serializer.data, 'token': token}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of an user.",
    request=UserSerializer,
    responses={200: UserSerializer, 404: "user not found"},  
)
def user_api_view(request, id):
    if request.method == 'GET':
        try:
            item = User.objects.get(pk=id)
            serializer = UserSerializer(item)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        try:
            item = User.objects.get(pk=id)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        data = request.data.copy()
        if "password" in request.data:
            item.set_password(request.data['password'])
            data['password'] = item.password

        serializer = UserPutSerializer(item, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':
        try:
            item = User.objects.get(pk=id)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@extend_schema(
    description="Endpoint allowing retrieval and creation of users. Retrieves all users from the database, "
                "sorts them by primary identifier, paginates the results, and serializes them before returning "
                "the paginated response to the client. For creation, deserializes the request data and saves it "
                "to the database. Additionally, sends emails to users based on the type of account created.",
    request=UserSerializer,
    responses={201: UserSerializer, 400: "Bad request"}, 
)
class UserAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = User.objects.all()
    serializer_class = UserSerializer
    """
    récuperation de tous les utilisateurs de la base de données, on les trie par identifiant primaire, 
    les paginate et les sérialise pour ensuite renvoyer la réponse paginée au client.
    
    english:
    
    recovery of all users from the database, sorting them by primary identifier,
    paginates and serializes them and then returns the paginated response to the client.
    """
    
    def get(self, request, format=None):
        items = User.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = UserSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            """
                désérialisation des données de la requête et les enregistrer dans la base de données.

                deserialization of the query data and save it to the database.
            """
            if 'user_type' in request.data and request.data['user_type'] == "admin":
                subject, from_email, to = '[MAP ACTION] - Votre compte Admin', settings.EMAIL_HOST_USER, request.data[
                    "email"]
                html_content = render_to_string('mail_add_admin.html', {'email': request.data["email"],
                                                                        'password': request.data[
                                                                            "password"]})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
                """
                envoie des e-mails aux utilisateurs en fonction du type de compte  créé.
                
                send emails to users based on the type of account  created.
                """
            if 'user_type' in request.data and request.data['user_type'] == "elu":
                subject, from_email, to = '[MAP ACTION] - Votre compte ELU', settings.EMAIL_HOST_USER, request.data[
                    "email"]
                html_content = render_to_string('mail_add_account.html',
                                                {'email': request.data["email"], 'password': request.data["password"],
                                                 'usertype': 'ELU'})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            if 'user_type' in request.data and request.data['user_type'] == "visitor":
                subject, from_email, to = '[MAP ACTION] - Votre compte VISITEUR', settings.EMAIL_HOST_USER, \
                    request.data["email"]
                html_content = render_to_string('mail_add_account.html',
                                                {'email': request.data["email"], 'password': request.data["password"],
                                                 'usertype': 'VISITEUR'})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            if 'user_type' in request.data and request.data['user_type'] == "citizen":
                subject, from_email, to = '[MAP ACTION] - Votre compte CITOYEN', settings.EMAIL_HOST_USER, request.data[
                    "email"]
                html_content = render_to_string('mail_add_account.html',
                                                {'email': request.data["email"], 'password': request.data["password"],
                                                 'usertype': 'CITOYEN'})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            if 'user_type' in request.data and request.data['user_type'] == "reporter":
                subject, from_email, to = '[MAP ACTION] - Votre compte REPORTEUR', settings.EMAIL_HOST_USER, \
                    request.data["email"]
                html_content = render_to_string('mail_add_account.html',
                                                {'email': request.data["email"], 'password': request.data["password"],
                                                 'usertype': 'REPORTEUR'})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            if 'user_type' in request.data and request.data['user_type'] == "business":
                subject, from_email, to = '[MAP ACTION] - Votre compte BUSINESS', settings.EMAIL_HOST_USER, \
                    request.data["email"]
                html_content = render_to_string('mail_add_account.html',
                                                {'email': request.data["email"], 'password': request.data["password"],
                                                 'usertype': 'BUSINESS'})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
            return Response(serializer.data,
                            status=201)  # returns a response to the client with the data of the newly created user
            # and a code status of 201

        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrieval of incident by zone.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentByZoneAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer
    """
    :param permission class : permissions de qui peut acceder à cette vue. ici n'importe qui peut y accéder et 
     créer de nouveaux incidents
    :param queryset: utilise le queryset incident.objects.all() Cela signifie qu'elle renverra tous les incidents
     de la base de données.
    :param serializer_class: spécifie que cette vue API utilisera la classe IncidentSerializer pour sérialiser et 
     désérialiser les données d'incident.
     
    """

    def get(self, request, format=None, **kwargs):
        try:
            zone = kwargs['zone']
            item = Incident.objects.filter(zone=zone).order_by('-pk')  # filtrage du queryset Incident pour n'inclure
            # que les incidents avec la zone spécifiée. trier ensuite les résultats par clé primaire dans l'ordre
            # décroissant.
            serializer = IncidentGetSerializer(item, many=True)
            return Response(serializer.data)
        except Incident.DoesNotExist:
            return Response(status=404)

@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of an incident.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, id, format=None):
        try:
            item = Incident.objects.get(pk=id)
            serializer = IncidentSerializer(item)
            return Response(serializer.data)
        except Incident.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Incident.objects.get(pk=id)
        except Incident.DoesNotExist:
            return Response(status=404)
        serializer = IncidentSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            if request.data['etat'] and request.data['etat'] == 'resolved':
                 if serializer.data['user_id']:
                    user = User.objects.get(id=serializer.data['user_id'])
                    subject, from_email, to = '[MAP ACTION] - Changement de statut d’incident', settings.EMAIL_HOST_USER, user.email
                    html_content = render_to_string('mail_incident_resolu.html', {
                        'incident': serializer.data['title']})  # render with dynamic value#
                    text_content = strip_tags(
                        html_content)  # Strip the html tag. So people can see the pure text at least.
                    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                    msg.attach_alternative(html_content, "text/html")
                    msg.send()
            if request.data['etat'] and request.data['etat'] == 'in_progress':
                  if serializer.data['user_id']:
                    user = User.objects.get(id=serializer.data['user_id'])
                    subject, from_email, to = '[MAP ACTION] - Changement de statut d’incident', settings.EMAIL_HOST_USER, user.email
                    html_content = render_to_string('mail_incident_trait.html', {
                        'incident': serializer.data['title']})  # render with dynamic value#
                    text_content = strip_tags(
                        html_content)  # Strip the html tag. So people can see the pure text at least.
                    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                    msg.attach_alternative(html_content, "text/html")
                    msg.send()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Incident.objects.get(pk=id)
        except Incident.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

    """
        La classe IncidentAPIView est une vue API complète qui permet de gérer les incidents. 
        Elle permet de créer, récupérer, mettre à jour et supprimer des incidents, 
        ainsi que d'envoyer des emails aux utilisateurs concernés.
    """

@extend_schema(
    description="Endpoint for creating and retrieve a new incident."
        "Users can submit details of an incident by providing the required information via a POST request."
        "The submitted data will be validated and stored in the system."
        "Upon success, a status code 201 (Created) will be returned along with details of the newly created incident."
        "In case of validation errors or issues with creating the incident, a status code 400 (Bad Request) will be returned along with information about the encountered errors."
        "Users must ensure that the provided data adheres to the format and constraints defined for incidents in the system.",
    request=IncidentSerializer,  
    responses={201: IncidentSerializer, 400: "Bad Request"},  
)
class IncidentAPIListView(generics.CreateAPIView):
    permission_classes = ()
    
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer
    
    def get(self, request, format=None):
        items = Incident.objects.order_by('-pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = IncidentGetSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = IncidentSerializer(data=request.data)
        lat = ""
        lon = ""
        if "lattitude" in request.data:
            lat = request.data["lattitude"]
        if "longitude" in request.data:
            lon = request.data["longitude"]
        zone = Zone(name=request.data["zone"], lattitude=lat, longitude=lon)
        try:
            zone.save()
        except IntegrityError:
            pass

        if serializer.is_valid():
            serializer.save()

            image_name = serializer.data.get("photo")
            print("Image Name:", image_name)

            longitude = serializer.data.get("longitude")
            latitude = serializer.data.get("lattitude")
            print("Longitude:", longitude)
            incident_instance = Incident.objects.get(longitude=longitude)
            incident_id = incident_instance.id

            
            print(incident_id)
            result = prediction_task.delay(image_name, longitude, latitude, incident_id)
            
            #result_value = result.get()
            
            #if result_value:
            #    predictions, longitude, context, in_depth, piste_solution = result_value
            

            #try:
                
                #prediction_instance = Prediction(incident_id=incident_id, piste_solution=piste_solution, impact_potentiel=in_depth,
                #                                 context=context)
                #prediction_instance.save()
                
                #print("Incident updated successfully.")
            #except Incident.DoesNotExist:
                #print(f"No incident found with longitude={longitude}")

          

            if "user_id" in request.data:
                user = User.objects.get(id=request.data["user_id"])
                user.points += 1
                user.save()

            if "video" in request.data:
                subprocess.check_call(['python', f"{settings.BASE_DIR}" + '/convertvideo.py'])

            return Response(serializer.data, status=201)

        return Response(serializer.errors, status=400)
    """
    cette classe permet de créer et récuperer tous les incidents
    this class is used to create and retrieve all incidents
    """

@extend_schema(
    description="Endpoint allowing retrieval an incident resolved.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentResolvedAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None):
        items = Incident.objects.filter(etat="resolved").order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = IncidentGetSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

@extend_schema(
    description="Endpoint allowing retrieval an incident not resolved.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentNotResolvedAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None):
        items = Incident.objects.filter(etat="declared").order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = IncidentGetSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of an evenement.",
    request=EvenementSerializer,
    responses={200: EvenementSerializer, 404: "Incident not found"},  
)
class EvenementAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Evenement.objects.all()
    serializer_class = EvenementSerializer
    
    def get(self, request, id, format=None):
        try:
            item = Evenement.objects.get(pk=id)
            serializer = EvenementSerializer(item)
            return Response(serializer.data)
        except Evenement.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Evenement.objects.get(pk=id)
        except Evenement.DoesNotExist:
            return Response(status=404)
        serializer = EvenementSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Evenement.objects.get(pk=id)
        except Evenement.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrieval and creating of an evenement.",
    request=EvenementSerializer,
    responses={201: EvenementSerializer, 400: "Serializer error"},  
)
class EvenementAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Evenement.objects.all()
    serializer_class = EvenementSerializer

    
    def get(self, request, format=None):
        items = Evenement.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = EvenementSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = EvenementSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(id=request.data["user_id"])
            user.points += 2
            user.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of a contact.",
    request=ContactSerializer,
    responses={200: ContactSerializer, 404: "Not Found"},  
)
class ContactAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    
    def get(self, request, id, format=None):
        try:
            item = Contact.objects.get(pk=id)
            serializer = ContactSerializer(item)
            return Response(serializer.data)
        except Contact.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Contact.objects.get(pk=id)
        except Contact.DoesNotExist:
            return Response(status=404)
        serializer = ContactSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Contact.objects.get(pk=id)
        except Contact.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrieval and creating of a contact.",
    request=ContactSerializer,
    responses={201: ContactSerializer, 400: "Serializer error"},  
)
class ContactAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    
    def get(self, request, format=None):
        items = Contact.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = ContactSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = ContactSerializer(data=request.data)
        admins = User.objects.filter(user_type="admin").values_list('email', flat=True)
        if serializer.is_valid():
            serializer.save()

            subject, from_email = '[MAP ACTION] - Nouveau Message', settings.EMAIL_HOST_USER
            html_content = render_to_string('mail_new_message.html')  # render with dynamic value#
            text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
            msg = EmailMultiAlternatives(subject, text_content, from_email, list(admins))
            msg.attach_alternative(html_content, "text/html")
            msg.send()

            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of a community.",
    request=CommunauteSerializer,
    responses={200: CommunauteSerializer, 404: "Not Found"},  
)
class CommunauteAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Communaute.objects.all()
    serializer_class = CommunauteSerializer
    
    def get(self, request, id, format=None):
        try:
            item = Communaute.objects.get(pk=id)
            serializer = CommunauteSerializer(item)
            return Response(serializer.data)
        except Communaute.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Communaute.objects.get(pk=id)
        except Communaute.DoesNotExist:
            return Response(status=404)
        serializer = CommunauteSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Communaute.objects.get(pk=id)
        except Communaute.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrieval and creating of a community.",
    request=CommunauteSerializer,
    responses={201: CommunauteSerializer, 400: "Serializer error"},  
)
class CommunauteAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Communaute.objects.all()
    serializer_class = CommunauteSerializer
    
    def get(self, request, format=None):
        items = Communaute.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = CommunauteSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = CommunauteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of a rapport.",
    request=RapportSerializer,
    responses={200: RapportSerializer, 404: "rapport not found"},  
)
class RapportAPIView(generics.CreateAPIView):
    queryset = Rapport.objects.all()
    serializer_class = RapportSerializer
    
    def get(self, request, id, format=None):
        try:
            item = Rapport.objects.get(pk=id)
            serializer = RapportSerializer(item)
            return Response(serializer.data)
        except Rapport.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Rapport.objects.get(pk=id)
        except Rapport.DoesNotExist:
            return Response(status=404)
        serializer = RapportSerializer(item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            if 'disponible' in request.data and request.data['disponible'] == True:
                if serializer.data['user_id']:
                    user = User.objects.get(id=serializer.data['user_id'])
                    subject, from_email, to = 'Commande de rapport disponible', settings.EMAIL_HOST_USER, user.email
                    html_content = render_to_string('mail_commande_disp.html', {
                        'details': serializer.data['details']})  # render with dynamic value#
                    text_content = strip_tags(
                        html_content)  # Strip the html tag. So people can see the pure text at least.
                    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                    msg.attach_alternative(html_content, "text/html")
                    msg.send()
                return Response(serializer.data)
            if 'file' in request.data:
                if serializer.data['user_id']:
                    item.disponible = True
                    item.save()
                    user = User.objects.get(id=serializer.data['user_id'])
                    subject, from_email, to = 'Commande de rapport disponible', settings.EMAIL_HOST_USER, user.email
                    html_content = render_to_string('mail_commande_disp.html', {
                        'details': serializer.data['details']})  # render with dynamic value#
                    text_content = strip_tags(
                        html_content)  # Strip the html tag. So people can see the pure text at least.
                    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                    msg.attach_alternative(html_content, "text/html")
                    msg.send()
                serializer = RapportSerializer(item).data
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Rapport.objects.get(pk=id)
        except Rapport.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrieval and creating of a rapport.",
    request=RapportSerializer,
    responses={201: RapportSerializer, 400: "Error"},  
)
class RapportAPIListView(generics.CreateAPIView):
    queryset = Rapport.objects.all()
    serializer_class = RapportSerializer
    
    def get(self, request, format=None):
        items = Rapport.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = RapportGetSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = RapportSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            admins = User.objects.filter(user_type="admin").values_list('email', flat=True)
            # print("admins: ",list(admins))
            incident = Incident.objects.get(id=request.data['incident'])
            subject, from_email = '[MAP ACTION] - Nouvelle commande de rapport', settings.EMAIL_HOST_USER
            html_content = render_to_string('mail_rapport_admin.html',
                                            {'details': incident.title})  # render with dynamic value#
            text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
            msg = EmailMultiAlternatives(subject, text_content, from_email, list(admins))
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrieval a rapport by user.",
    request=RapportSerializer,
    responses={200: RapportSerializer, 404: "rapport not found"},  
)
class RapportByUserAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Rapport.objects.all()
    serializer_class = RapportSerializer
    
    def get(self, request, id, format=None, **kwargs):
        try:
            item = Rapport.objects.filter(user_id=id)
            serializer = RapportGetSerializer(item, many=True)
            return Response(serializer.data)
        except Rapport.DoesNotExist:
            return Response(status=404)

@extend_schema(
    description="Endpoint allowing retrieval and creating a rapport on zone.",
    request=RapportSerializer,
    responses={200: RapportSerializer, 404: "rapport not found"},  
)
class RapportOnZoneAPIView(generics.CreateAPIView):
    queryset = Rapport.objects.all()
    serializer_class = RapportSerializer
    
    def get(self, request, format=None):
        items = Rapport.objects.filter(type="zone").order_by('pk')
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = RapportGetSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        if request.data['type'] == 'zone' and 'zone' in request.data:
            serializer = RapportSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()

                rapport = Rapport.objects.get(id=serializer.data['id'])
                incidents = Incident.objects.filter(zone=request.data['zone'])
                for i in incidents:
                    rapport.incidents.add(i.id)
                # print(rapport.incidents)
                rapport.save()
                data = RapportSerializer(rapport).data

                admins = User.objects.filter(user_type="admin").values_list('email', flat=True)
                subject, from_email = '[MAP ACTION] - Nouveau Rapport', settings.EMAIL_HOST_USER
                html_content = render_to_string('mail_new_rapport.html')  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, list(admins))
                msg.attach_alternative(html_content, "text/html")
                msg.send()

                return Response({
                    "status": "success",
                    "message": "item successfully created",
                    "data": data
                }, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=400)
        else:
            return Response(status=404)


@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of participation.",
    request=ParticipateSerializer,
    responses={200: ParticipateSerializer, 404: "Participation not found"},  
)
class ParticipateAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Participate.objects.all()
    serializer_class = ParticipateSerializer

    def get(self, request, id, format=None):
        try:
            item = Participate.objects.get(pk=id)
            serializer = ParticipateSerializer(item)
            return Response(serializer.data)
        except Participate.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Participate.objects.get(pk=id)
        except Participate.DoesNotExist:
            return Response(status=404)
        serializer = ParticipateSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Participate.objects.get(pk=id)
        except Participate.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)


@extend_schema(
    description="Endpoint allowing retrieval and creating of participation.",
    request=ParticipateSerializer,
    responses={201: ParticipateSerializer, 400: "serializer error"},  
)
class ParticipateAPIListView(generics.ListCreateAPIView):
    permission_classes = ()
    queryset = Participate.objects.all()
    serializer_class = ParticipateSerializer
    pagination_class = PageNumberPagination

    def get(self, request, *args, **kwargs):
        self.pagination_class.page_size = 10  # Nombre d'éléments par page
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        serializer = ParticipateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(id=request.data["user_id"])
            user.points += 1
            user.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrieval and creating of an elu.",
    responses={201: UserEluSerializer, 400: "Serializer error"},  
)
class EluAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = User.objects.all()
    serializer_class = UserEluSerializer

    def get(self, request, format=None):
        items = User.objects.filter(user_type='elu').order_by('pk')
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = UserSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        self.data = request.data.copy()
        if "zones" in request.data:
            self.data.pop('zones')

        serializer = UserEluSerializer(data=self.data)

        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(id=serializer.data['id'])
            if "zones" in request.data:
                for id in request.data['zones']:
                    zone = Zone.objects.get(id=id)
                    if zone != None:
                        user.zones.add(zone)
            password = User.objects.make_random_password()
            user.set_password(password)
            user.save()

            subject, from_email, to = '[MAP ACTION] - Votre compte ÉLU', settings.EMAIL_HOST_USER, request.data["email"]
            html_content = render_to_string('mail_add_elu.html', {'email': request.data["email"],
                                                                  'password': password})  # render with dynamic value#
            text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
            msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            return Response(UserEluSerializer(user).data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing creating of an elu by zone.",
    request=UserEluSerializer,
    responses={201: UserEluSerializer, 400: "serializer error"},  
)
class EluToZoneAPIListView(generics.ListCreateAPIView):
    permission_classes = ()
    queryset = User.objects.all()
    serializer_class = EluToZoneSerializer

    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def post(self, request, format=None):
        try:
            elu = User.objects.get(id=request.data['elu'])
            zone = Zone.objects.get(id=request.data['zone'])
            if zone and elu:
                elu.zones.add(zone)
                return Response({
                    "status": "success",
                    "message": "elu attributed to zone"
                })
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema(
    description="Endpoint allowing retrivial of citizen.",
    responses={200: UserSerializer, 404: "Citizen not found"},  
)
class CitizenAPIListView(generics.ListAPIView):
    permission_classes = ()
    queryset = User.objects.filter(user_type='citizen').order_by('pk')
    serializer_class = UserSerializer
    pagination_class = PageNumberPagination

    def get(self, request, *args, **kwargs):
        self.pagination_class.page_size = 10  # Modifier ici pour définir la taille de la page
        return self.list(request, *args, **kwargs)

@extend_schema(
    description="Endpoint allowing retrival of user.",
    responses={200: UserSerializer, 404: "User not found"},  
)
class UserRetrieveView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (
        permissions.IsAuthenticated,
    )

    def get(self, request, *args, **kwargs):
        user = User.objects.get(email=request.user.email)

        if not user:
            return Response({
                "status": "failure",
                "message": "no such item",
            }, status=status.HTTP_400_BAD_REQUEST)

        data = UserSerializer(user).data

        return Response({
            "status": "success",
            "message": "item successfully created",
            "data": data
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint allowing retrival, updating and deletion of zone.",
    responses={200: ZoneSerializer, 404: "zone not found"},  
)
class ZoneAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Zone.objects.all()
    serializer_class = ZoneSerializer

    def get(self, request, id, format=None):
        try:
            item = Zone.objects.get(pk=id)
            serializer = ZoneSerializer(item)
            return Response(serializer.data)
        except Zone.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Zone.objects.get(pk=id)
        except Zone.DoesNotExist:
            return Response(status=404)
        serializer = ZoneSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Zone.objects.get(pk=id)
        except Zone.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrival and creating of zone.",
    request=ZoneSerializer,
    responses={201: ZoneSerializer, 400: "Bad request"},  
)
class ZoneAPIListView(generics.ListCreateAPIView):
    permission_classes = (
    )
    queryset = Zone.objects.all()
    serializer_class = ZoneSerializer
    pagination_class = PageNumberPagination

    def get(self, request, format=None, *args, **kwargs):
        try:
            return self.list(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, format=None, *args, **kwargs):
        serializer = ZoneSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrival, updating and deletion of Message.",
    responses={200: MessageSerializer, 404: "message not found"},  
)
class MessageAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def get(self, request, id, format=None):
        try:
            item = Message.objects.get(pk=id)
            serializer = MessageGetSerializer(item)
            return Response(serializer.data)
        except Message.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Message.objects.get(pk=id)
        except Message.DoesNotExist:
            return Response(status=404)
        serializer = MessageSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Message.objects.get(pk=id)
        except Message.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrieval and creating of message.",
    responses={201: MessageSerializer, 400: "serializer error"},  
)
class MessageAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Message.objects.all()
    serializer_class = MessageSerializer
    
    def get(self, request, format=None):
        items = Message.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = MessageGetSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            if 'user_id' in request.data and request.data['user_id']:
                elu = User.objects.get(pk=request.data['user_id'])
                subject, from_email, to = '[MAP ACTION] - Nouveau Message', settings.EMAIL_HOST_USER, elu.email
                html_content = render_to_string('mail_message_elu.html', {'prenom': elu.first_name,
                                                                          'nom': elu.last_name})  # render with dynamic value#
                text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()

            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing retrivial of message by community.",
    responses={200: MessageSerializer, 404: "message not found"},  
)
class MessageByComAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def get(self, request, id, format=None, **kwargs):
        try:
            item = Message.objects.filter(communaute=id)
            serializer = MessageSerializer(item, many=True)
            return Response(serializer.data)
        except Message.DoesNotExist:
            return Response(status=404)

@extend_schema(
    description="Endpoint allowing retrivial of message by zone.",
    responses={200: MessageSerializer, 404: "message not found"},  
)
class MessageByZoneAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def get(self, request, format=None, **kwargs):
        try:
            zone = kwargs['zone']
            item = Message.objects.filter(zone__name=zone)
            serializer = MessageByZoneSerializer(item, many=True)
            return Response(serializer.data)
        except Message.DoesNotExist:
            return Response(status=404)

@extend_schema(
    description="Endpoint allowing retrieval of incident by month.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentByMonthAPIListView(generics.ListAPIView):
    permission_classes = ()
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def list(self, request, *args, **kwargs):
        now = timezone.now()
        month_param = self.request.query_params.get('month', None)
        if month_param:
            try:
                month = int(month_param)
                items = Incident.objects.filter(created_at__year=now.year, created_at__month=month)
            except ValueError:
                return Response({"error": "Invalid month parameter"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            items = Incident.objects.filter(created_at__year=now.year)

        serializer = self.get_serializer(items, many=True)
        return Response({
            "status": "success",
            "message": "Incidents by month",
            "data": serializer.data
        }, status=status.HTTP_200_OK)


@extend_schema(
    description="Endpoint allowing retrieval of incident by month on zone.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentByMonthByZoneAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None, **kwargs):
        zone = kwargs['zone']
        now = timezone.now()
        items = Incident.objects.filter(zone=zone).filter(created_at__year=now.year)
        months = items.datetimes("created_at", kind="month")

        listData = []
        for month in months:
            # month_invs = items.filter(created_at__month=month.month).filter(created_at__year=now.year)
            month_invs = items.filter(created_at__month=month.month)
            month_total = month_invs.count()
            month_resolved = month_invs.filter(etat="resolved").count()
            month_unresolved = month_invs.filter(etat="declared").count()

            # print(f"Month: {month}, Total: {month_total}")
            dataMonth = {"month": month, "total": month_total, "resolved": month_resolved,
                         "unresolved": month_unresolved}
            listData.append(dataMonth)

        return Response({
            "status": "success",
            "message": "incidents by month ",
            "data": listData
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint allowing retrieval of incident on week.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentOnWeekAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None):
        some_day_last_week = timezone.now().date() - timedelta(days=7)
        monday_of_last_week = some_day_last_week - timedelta(days=(some_day_last_week.isocalendar()[2] - 1))
        monday_of_this_week = monday_of_last_week + timedelta(days=8)
        items = Incident.objects.filter(created_at__gte=monday_of_last_week,
                                        created_at__lt=monday_of_this_week).order_by('pk')
        days = items.datetimes("created_at", kind="day")

        listData = []
        for day in days:
            day_invs = items.filter(created_at__day=day.day)
            day_total = day_invs.count()
            day_resolved = day_invs.filter(etat="resolved").count()
            day_unresolved = day_invs.filter(etat="declared").count()
            # print(f"Month: {month}, Total: {month_total}")
            dataDay = {"day": day, "total": day_total, "resolved": day_resolved, "unresolved": day_unresolved}
            listData.append(dataDay)

        return Response({
            "status": "success",
            "message": "incidents by week ",
            "data": listData
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint allowing retrieval of incident on week by zone.",
    request=IncidentSerializer,
    responses={200: IncidentSerializer, 404: "Incident not found"},  
)
class IncidentByWeekByZoneAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None, **kwargs):
        zone = kwargs['zone']
        some_day_last_week = timezone.now().date() - timedelta(days=7)
        monday_of_last_week = some_day_last_week - timedelta(days=(some_day_last_week.isocalendar()[2] - 1))
        monday_of_this_week = monday_of_last_week + timedelta(days=8)
        items = Incident.objects.filter(zone=zone).filter(created_at__gte=monday_of_last_week,
                                                          created_at__lt=monday_of_this_week).order_by('pk')
        days = items.datetimes("created_at", kind="day")

        listData = []
        for day in days:
            day_invs = items.filter(created_at__day=day.day)
            day_total = day_invs.count()
            day_resolved = day_invs.filter(etat="resolved").count()
            day_unresolved = day_invs.filter(etat="declared").count()
            # print(f"Month: {month}, Total: {month_total}")
            dataDay = {"day": day, "total": day_total, "resolved": day_resolved, "unresolved": day_unresolved}
            listData.append(dataDay)

        return Response({
            "status": "success",
            "message": "incidents by month ",
            "data": listData
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint allowing retrieval, updating, and deletion of a category.",
    request=CategorySerializer,
    responses={200: CategorySerializer, 404: "category not found"},  
)
class CategoryAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def get(self, request, id, format=None):
        try:
            item = Category.objects.get(pk=id)
            serializer = CategorySerializer(item)
            return Response(serializer.data)
        except Category.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Category.objects.get(pk=id)
        except Category.DoesNotExist:
            return Response(status=404)
        serializer = CategorySerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Category.objects.get(pk=id)
        except Category.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrieval and creating of category.",
    request=CategorySerializer,
    responses={201: CategorySerializer, 400: "serializer error"},  
)
class CategoryAPIListView(generics.ListCreateAPIView):
    permission_classes = ()
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    pagination_class = PageNumberPagination

    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    description="Endpoint allowing retrival, updating, and deletion of an indicator",
    responses={200: IndicateurSerializer, 404: "indicator not found"}
)
class IndicateurAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Indicateur.objects.all()
    serializer_class = IndicateurSerializer

    def get(self, request, id, format=None):
        try:
            item = Indicateur.objects.get(pk=id)
            serializer = IndicateurSerializer(item)
            return Response(serializer.data)
        except Indicateur.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = Indicateur.objects.get(pk=id)
        except Indicateur.DoesNotExist:
            return Response(status=404)
        serializer = IndicateurSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = Indicateur.objects.get(pk=id)
        except Indicateur.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint allowing retrival and creating of indicator",
    responses={201: IndicateurSerializer, 400: "serializer error"}
)
class IndicateurAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Indicateur.objects.all()
    serializer_class = IndicateurSerializer

    def get(self, request, format=None):
        items = Indicateur.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = IndicateurSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = IndicateurSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint allowing changing password",
    responses={200: ChangePasswordSerializer, 400: "bad request"}
)
class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.password_reset_count = 1
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    description="Endpoint for updating points of users based on their activities.",
    responses={200: "Points updated successfully."},
)
class UpdatePointAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, format=None, **kwargs):
        users = User.objects.all()
        for user in users:
            incidents = Incident.objects.filter(user_id=user.id)
            evenements = Evenement.objects.filter(user_id=user.id)
            participate = Participate.objects.filter(user_id=user.id)
            user.points += (incidents.count()) + (evenements.count() * 2) + (participate.count())
            user.save()

        return Response({
            "status": "success",
            "message": "update success ",
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint for retrieving statistics on incidents based on indicators.",
    responses={200: "Statistics on incidents retrieved successfully."},
)
class IndicateurOnIncidentAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None):
        items = Indicateur.objects.all()
        total_incidents = Incident.objects.all().count()
        listData = []
        for item in items:
            # day_resolved = day_invs.filter(etat="resolved").count()
            incidents = Incident.objects.filter(indicateur_id=item.id)
            dataIndicateur = {"indicateur": item.name, "number": incidents.count(),
                              "pourcentage": (incidents.count() / total_incidents) * 100}
            listData.append(dataIndicateur)
        incidents_not_indic = Incident.objects.filter(indicateur_id__isnull=True)
        dataIndicateur = {"indicateur": "null", "number": incidents_not_indic.count(),
                          "pourcentage": (incidents_not_indic.count() / total_incidents) * 100}
        listData.append(dataIndicateur)
        return Response({
            "status": "success",
            "message": "indicateur % ",
            "data": listData
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint for retrieving statistics on incidents based on indicators by zone.",
    responses={200: "Statistics on incidents retrieved successfully."},
)
class IndicateurOnIncidentByZoneAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None, **kwargs):
        items = Indicateur.objects.all()
        zone = kwargs['zone']
        total_incidents = Incident.objects.filter(zone=zone).count()
        listData = []
        for item in items:
            # day_resolved = day_invs.filter(etat="resolved").count()
            incidents = Incident.objects.filter(indicateur_id=item.id, zone=zone)
            dataIndicateur = {"indicateur": item.name, "number": incidents.count(), "pourcentage": (
                                                                                                           incidents.count() / total_incidents) * 100 if incidents.count() > 0 else 0}
            listData.append(dataIndicateur)
        incidents_not_indic = Incident.objects.filter(indicateur_id__isnull=True, zone=zone)
        dataIndicateur = {"indicateur": "null", "number": incidents_not_indic.count(), "pourcentage": (
                                                                                                              incidents_not_indic.count() / total_incidents) * 100 if incidents_not_indic.count() > 0 else 0}
        listData.append(dataIndicateur)
        return Response({
            "status": "success",
            "message": "indicateur % ",
            "data": listData
        }, status=status.HTTP_200_OK)

@extend_schema(
    description="Endpoint for retrieving statistics on incidents based on indicators for a elu (organisation) user.",
    responses={200: "Statistics on incidents for the user retrieved successfully."},
)
class IndicateurOnIncidentByEluAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, id, format=None, **kwargs):
        items = Indicateur.objects.all()
        total_incidents = Incident.objects.filter(user_id=id).count()
        listData = []
        for item in items:
            # day_resolved = day_invs.filter(etat="resolved").count()
            incidents = Incident.objects.filter(indicateur_id=item.id, user_id=id)
            dataIndicateur = {"indicateur": item.name, "number": incidents.count(), "pourcentage": (
                                                                                                           incidents.count() / total_incidents) * 100 if incidents.count() > 0 else 0}
            listData.append(dataIndicateur)
        incidents_not_indic = Incident.objects.filter(indicateur_id__isnull=True, user_id=id)
        dataIndicateur = {"indicateur": "null", "number": incidents_not_indic.count(), "pourcentage": (
                                                                                                              incidents_not_indic.count() / total_incidents) * 100 if incidents_not_indic.count() > 0 else 0}
        listData.append(dataIndicateur)
        return Response({
            "status": "success",
            "message": "indicateur % ",
            "data": listData
        }, status=status.HTTP_200_OK)


class PasswordResetView(generics.CreateAPIView):
    """ use postman to test give 4 fields new_password  new_password_confirm email code post methode"""
    permission_classes = (

    )
    queryset = User.objects.all()
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):

        if 'code' not in request.data or request.data['code'] is None:
            return Response({
                "status": "failure",
                "message": "no code provided",
                "error": "not such item"
            }, status=status.HTTP_400_BAD_REQUEST)

        if 'email' not in request.data or request.data['email'] is None:
            return Response({
                "status": "failure",
                "message": "no email provided",
                "error": "not such item"
            }, status=status.HTTP_400_BAD_REQUEST)

        if 'new_password' not in request.data or 'new_password_confirm' not in request.data or request.data[
            'new_password'] is None or request.data['new_password'] != request.data['new_password_confirm']:
            return Response({
                "status": "failure",
                "message": "non matching passwords",
                "error": "not such item"
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            user_ = User.objects.get(email=request.data['email'])
            code_ = request.data['code']
            if user_ is None:
                return Response({
                    "status": "failure",
                    "message": "no such item",
                    "error": "not such item"
                }, status=status.HTTP_400_BAD_REQUEST)

            passReset = PasswordReset.objects.filter(
                user=user_, code=code_, used=False).order_by('-date_created').first()
            if passReset is None:
                return Response({
                    "status": "failure",
                    "message": "not such item",
                    "error": "not such item"
                }, status=status.HTTP_400_BAD_REQUEST)

            user_.set_password(request.data['new_password'])
            user_.save()
            passReset.used = True
            passReset.date_used = timezone.now()
            passReset.save()


        except User.DoesNotExist:
            return Response({
                "status": "failure",
                "message": "invalid data",
            }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "status": "success",
            "message": "item successfully saved",
        }, status=status.HTTP_201_CREATED)

@extend_schema(
    description="Endpoint for resetting user password.",
    request=ResetPasswordSerializer,
    responses={400: "Bad Request"},
)
class PasswordResetRequestView(generics.CreateAPIView):
    """ use postman to test give field email post methode"""
    permission_classes = (

    )
    queryset = User.objects.all()
    serializer_class = RequestPasswordSerializer

    def post(self, request, *args, **kwargs):
        if 'email' not in request.data or request.data['email'] is None:
            return Response({
                "status": "failure",
                "message": "no email provided",
                "error": "not such item"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_ = User.objects.get(email=request.data['email'])
            code_ = get_random()
            PasswordReset.objects.create(
                user=user_,
                code=code_
            )
            subject, from_email, to = '[MAP ACTION] - Votre code de reinitialisation', settings.EMAIL_HOST_USER, user_.email
            html_content = render_to_string('mail_pwd.html', {'code': code_})  # render with dynamic value#
            text_content = strip_tags(html_content)  # Strip the html tag. So people can see the pure text at least.
            msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
            msg.attach_alternative(html_content, "text/html")
            msg.send()

        except User.DoesNotExist:
            # print('sen error mail')
            return Response({
                "status": "failure",
                "message": "no such item",
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "status": "success",
            "message": "item successfully saved ",
        }, status=status.HTTP_201_CREATED)

@extend_schema(
    description="Endpoint for managing response messages.",
    request=ResponseMessageSerializer,
    responses={201: ResponseMessageSerializer, 400: "Bad Request"},
)
class ResponseMessageAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = ResponseMessage.objects.all()
    serializer_class = ResponseMessageSerializer

    def get(self, request, id, format=None):
        try:
            item = ResponseMessage.objects.get(pk=id)
            serializer = ResponseMessageSerializer(item)
            return Response(serializer.data)
        except ResponseMessage.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = ResponseMessage.objects.get(pk=id)
        except ResponseMessage.DoesNotExist:
            return Response(status=404)
        serializer = ResponseMessageSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = ResponseMessage.objects.get(pk=id)
        except ResponseMessage.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)

@extend_schema(
    description="Endpoint for managing response messages.",
    request=ResponseMessageSerializer,
    responses={201: ResponseMessageSerializer, 400: "Bad Request"},
)
class ResponseMessageAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = ResponseMessage.objects.all()
    serializer_class = ResponseMessageSerializer

    def get(self, request, format=None):
        items = ResponseMessage.objects.order_by('pk')
        paginator = CustomPageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = ResponseMessageSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = ResponseMessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@extend_schema(
    description="Endpoint for retrieving responses by message ID.",
    responses={200: ResponseMessageSerializer(many=True), 404: "Not Found"},
)
class ResponseByMessageAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = ResponseMessage.objects.all()
    serializer_class = ResponseMessageSerializer

    def get(self, request, id, format=None):
        try:
            item = ResponseMessage.objects.filter(message=id)
            serializer = ResponseMessageSerializer(item, many=True)
            return Response(serializer.data)
        except ResponseMessage.DoesNotExist:
            return Response(status=404)

@extend_schema(
    description="Endpoint for retrieving messages by user ID.",
    responses={200: MessageGetSerializer(many=True), 404: "Not Found"},
)
class MessageByUserAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def get(self, request, id, format=None):
        try:
            item = Message.objects.filter(user_id=id)
            serializer = MessageGetSerializer(item, many=True)
            return Response(serializer.data)
        except Message.DoesNotExist:
            return Response(status=404)


class ImageBackgroundAPIView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = ImageBackground.objects.all()
    serializer_class = ImageBackgroundSerializer

    def get(self, request, id, format=None):
        try:
            item = ImageBackground.objects.get(pk=id)
            serializer = ImageBackgroundSerializer(item)
            return Response(serializer.data)
        except ImageBackground.DoesNotExist:
            return Response(status=404)

    def put(self, request, id, format=None):
        try:
            item = ImageBackground.objects.get(pk=id)
        except ImageBackground.DoesNotExist:
            return Response(status=404)
        serializer = ImageBackgroundSerializer(item, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, id, format=None):
        try:
            item = ImageBackground.objects.get(pk=id)
        except ImageBackground.DoesNotExist:
            return Response(status=404)
        item.delete()
        return Response(status=204)


class ImageBackgroundAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = ImageBackground.objects.all()
    serializer_class = ImageBackgroundSerializer

    def get(self, request, format=None):
        items = ImageBackground.objects.last()
        serializer = ImageBackgroundSerializer(items)
        return Response(serializer.data, status=201)

    def post(self, request, format=None):
        serializer = ImageBackgroundSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    

class OverpassApiIntegration(generics.CreateAPIView):
    permission_classes = ()
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer
    @extend_schema(
        description="This endpoint retrieves the locality information of incidents based on their geographic coordinates."
        "It accepts latitude and longitude parameters to specify the location around which to search for incidents."
        " The endpoint queries amenities such as pharmacies, mosques, schools, restaurants, bars, prisons, rivers, and marigots"
        " within a 500-meter radius of the specified coordinates. It then returns a list of incidents found in the vicinity, "
        "including details such as the type of amenity and its name.",
        responses={200: IncidentSerializer(many=True), 404: "Not Found"},
    )
    def get(self, request, *args, **kwargs):
        lat = request.GET.get("latitude")
        lon = request.GET.get("longitude")
        query = f"""
        [out:json];
        (
            node["amenity"="pharmacy"](around:500, {lat}, {lon});
            node["amenity"="mosque"](around:500, {lat}, {lon});
            node["amenity"="school"](around:500, {lat}, {lon});
            node["amenity"="restaurant"](around:500, {lat}, {lon});
            node["amenity"="bar"](around:500, {lat}, {lon});
            node["amenity"="prison"](around:500, {lat}, {lon});
            node["amenity"="river"](around:500, {lat}, {lon});
            node["amenity"="marigot"](around:500, {lat}, {lon});
            node["amenity"="clinic"](around:500, {lat}, {lon});
        );
        out body;
        >;
        out skel qt;
        """
        api = overpy.Overpass()
        result = api.query(query)
        results_list = []
        for node in result.nodes:
            result_item = {
                "amenity": node.tags.get("amenity", ""),
                "name": node.tags.get("name", ""),
                
            }
            results_list.append(result_item)

        return HttpResponse(json.dumps(results_list))

class PhoneOTPView(generics.CreateAPIView):
    permission_classes = ()
    queryset = PhoneOTP.objects.all()
    serializer_class = PhoneOTPSerializer
    @extend_schema(
        description="Endpoint for generate otp code",
        responses={200: "generate", 400: "Bad request"},
    )
    def generate_otp(self, phone_number):
        secret_key = pyotp.random_base32()
        otp = pyotp.TOTP(secret_key)
        otp_code = otp.now()
        otp_code_str = str(otp_code)
        PhoneOTP.objects.create(phone_number=phone_number, otp_code=otp_code_str)
        return otp_code_str
    
    @extend_schema(
        description="Endpoint for retrivial a code otp",
        request=PhoneOTPSerializer,
        responses={200: PhoneOTPSerializer, 404: "Not Found"},
    )
    def get(self, request, *args, **kwargs):
        phone_number = request.query_params.get('phone_number')
        if not phone_number:
            raise ValidationError("Le numéro de téléphone est requis.")
        try:
            otp_instance = PhoneOTP.objects.get(phone_number=phone_number)
        except PhoneOTP.DoesNotExist:
            raise NotFound("Code OTP non trouvé pour ce numéro de téléphone.")
        return Response({'otp_code': otp_instance.otp_code}, status=status.HTTP_200_OK)
    
    @extend_schema(
        description="Endpoint for creating a code otp",
        request=PhoneOTPSerializer,
        responses={201: PhoneOTPSerializer, 400: "Bad request"},
    )
    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone_number')
        if not phone_number:
            raise ValidationError("Le numéro de téléphone est requis.")
        otp_code = self.generate_otp(phone_number)
        if send_sms(phone_number, otp_code):
            return Response({'otp_code': otp_code}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Erreur lors de l\'envoi du SMS'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def send_sms(phone_number, otp_code):
    account_sid = os.environ['TWILIO_ACCOUNT_SID']
    auth_token = os.environ['TWILIO_AUTH_TOKEN']
    twilio_phone = os.environ['TWILIO_PHONE_NUMBER']
    client = Client(account_sid, auth_token)
    message_body = f"Votre code de vérification OTP est : {otp_code}"
    message = client.messages.create(
        body=message_body,
        from_=twilio_phone,
        to=phone_number
    )
    if message.sid:
        return True
    else:
        return False
    

class CollaborationView(generics.CreateAPIView, generics.ListAPIView):
    permission_classes = ()
    queryset = Collaboration.objects.all()
    serializer_class = CollaborationSerializer
    @extend_schema(
        description="Endpoint for creating a collaboration",
        responses={200: "generate", 400: "Bad request"},
    )
    def post(self, request, *args, **kwargs):
        try:
            serializer = CollaborationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    @extend_schema(
        description="Endpoint for retrieving all collaborations",
        responses={200: CollaborationSerializer(many=True)},
    )
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class IncidentSearchView(generics.ListAPIView):
    def get(self, request):
        search_term = request.query_params.get('search_term')
        
        if search_term is None:
            return Response("Parameter 'search_term' is missing", status=status.HTTP_400_BAD_REQUEST)
        
        results = Incident.objects.filter(
            Q(title__icontains=search_term) | Q(description__icontains=search_term)
        )
        serializer = IncidentSerializer(results, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class PredictionView(generics.ListAPIView):
    permission_classes = ()
    queryset = Prediction.objects.all()
    serializer_class = PredictionSerializer

    
def history_list(request):
    histories = ChatHistory.objects.all()  # Retrieve all history records
    data = {"histories": list(histories.values("session_id", "question", "answer"))}
    return JsonResponse(data)

@csrf_exempt  # Disable CSRF token for this view for simplicity
def add_history(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            history = History(
                user_id=data['session_id'],
                question=data['question'],
                answer=data['answer']
            )
            history.save()
            return JsonResponse({"message": "History added successfully!"}, status=201)
        except (KeyError, TypeError) as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return HttpResponse(status=405)  # Method Not Allowed


class PredictionViewByID(generics.ListAPIView):
    permission_classes = ()
    serializer_class = PredictionSerializer

    def get_queryset(self):
        incident_id = self.kwargs['id']
        queryset = Prediction.objects.filter(incident_id=incident_id)
        return queryset


class NotificationViewSet(viewsets.ModelViewSet):
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Notification.objects.filter(user=user)

