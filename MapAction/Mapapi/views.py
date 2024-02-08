import subprocess

from django.shortcuts import render, HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from .serializer import *
from django.middleware.csrf import get_token
from django.http import JsonResponse
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
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
from django.template.loader import get_template, render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives, send_mail
import random
import string


class CustomPageNumberPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000


N = 7

def get_csrf_token(request):
    csrf_token = get_token(request)
    return JsonResponse({'csrf_token': csrf_token})

@api_view(('GET', 'POST'))
def login(request):
    if request.method == 'GET':
        return Response('i am a test', status=status.HTTP_200_OK)
    if request.method == 'POST':
        return Response("i am a test too", status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
def UserRegisterView(request):
    if request.method == 'GET':
        users = User.objects.all().values()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def UserAPIView(self, request, id):
    user = User.objects.all().values()

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
            return Response(status=404)
        self.data = request.data.copy()
        if "password" in request.data:
            item.set_password(request.data['password'])
            self.data['password'] = item.password

        serializer = UserPutSerializer(item, data=self.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    if request.method == 'DELETE':
        try:
            item = User.objects.get(pk=id)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


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
                # subject = "Etat de l'incident sur mapaction"
                # message = "L'incident du nom de: " +serializer.data['title'] +" que vous avez declaré dans map action a été résolu avec succès "
                if serializer.data['user_id']:
                    user = User.objects.get(id=serializer.data['user_id'])
                    # recepient = user.email
                    # send_mail(subject,
                    #     message, EMAIL_HOST_USER, [recepient], fail_silently = False)
                    subject, from_email, to = '[MAP ACTION] - Changement de statut d’incident', settings.EMAIL_HOST_USER, user.email
                    html_content = render_to_string('mail_incident_resolu.html', {
                        'incident': serializer.data['title']})  # render with dynamic value#
                    text_content = strip_tags(
                        html_content)  # Strip the html tag. So people can see the pure text at least.
                    msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                    msg.attach_alternative(html_content, "text/html")
                    msg.send()
            if request.data['etat'] and request.data['etat'] == 'in_progress':
                # subject = "Etat de l'incident sur mapaction"
                # message = "L'incident du nom de: " +serializer.data['title'] +" que vous avez declaré dans map action est en cours de traitement "
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


class IncidentAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
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
            
             # Assuming your image field is named 'image' in your Incident model
            image_name = serializer.data.get('photo')

            # Define the FastAPI endpoint URL
            fastapi_url = "http://192.168.1.7:8001/api1/image/predict"

            # Prepare the payload with the image name
            payload = {"image_name": image_name}

            try:
                # Make a POST request to the FastAPI endpoint
                response = requests.post(fastapi_url, json=payload)

                # Check if the request was successful (status code 200)
                if response.status_code == 200:
                    # Parse the response JSON
                    result = response.json()

                    # Extract relevant information from the result
                    prediction = result.get("prediction")
                    description = result.get("get_context")

                    # Do something with the prediction and description, e.g., save to Incident model
                    incident_instance = Incident.objects.get(id=serializer.data["id"])
                    incident_instance.prediction = prediction
                    incident_instance.description = description
                    incident_instance.save()
                    
                    
            if "user_id" in request.data:
                user = User.objects.get(id=request.data["user_id"])
                user.points += 1
                user.save()
            if "video" in request.data:
                subprocess.check_call(['python3', settings.BASE_DIR + '/convertvideo.py']) # convert video

            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    """
    cette classe permet de créer et récuperer tous les incidents
    this class is used to create and retrieve all incidents
    """


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


class ParticipateAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Participate.objects.all()
    serializer_class = ParticipateSerializer

    def get(self, request, format=None):
        items = Participate.objects.order_by('pk')
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = ParticipateSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = ParticipateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(id=request.data["user_id"])
            user.points += 1
            user.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


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


class EluToZoneAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = User.objects.all()
    serializer_class = EluToZoneSerializer

    def post(self, request, format=None):
        elu = User.objects.get(id=request.data['elu'])
        zone = Zone.objects.get(id=request.data['zone'])
        if zone != None and elu != None:
            elu.zones.add(zone)
            return Response({
                "status": "success",
                "message": "elu attribuated to zone"
            })
        return Response(serializer.errors, status=400)


class CitizenAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get(self, request, format=None):
        items = User.objects.filter(user_type='citizen').order_by('pk')
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = UserSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)


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


class ZoneAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Zone.objects.all()
    serializer_class = ZoneSerializer

    def get(self, request, format=None):
        items = Zone.objects.order_by('pk')
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = ZoneSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = ZoneSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


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


class IncidentByMonthAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

    def get(self, request, format=None):
        now = timezone.now()
        items = Incident.objects.filter(created_at__year=now.year)
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


class CategoryAPIListView(generics.CreateAPIView):
    permission_classes = (
    )
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def get(self, request, format=None):
        items = Category.objects.order_by('pk')
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(items, request)
        serializer = CategorySerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request, format=None):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


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
            # print(passReset)
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


class PasswordResetRequestView(generics.CreateAPIView):
    """ use postman to test give field email post methode"""
    permission_classes = (

    )
    queryset = User.objects.all()
    serializer_class = RequestPasswordSerializer

    def post(self, request, *args, **kwargs):

        # get user using email
        # if user

        if 'email' not in request.data or request.data['email'] is None:
            return Response({
                "status": "failure",
                "message": "no email provided",
                "error": "not such item"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_ = User.objects.get(email=request.data['email'])
            # generate random code
            code_ = get_random()
            # crete and save pr object
            PasswordReset.objects.create(
                user=user_,
                code=code_
            )

            # subject = 'Réinitialisation mot de passe' message = " Vous avez oublié votre mot de passe ? Pas de
            # panique!  Vous pouvez le réinitialiser en utilisant le code suivant  et en indiquant votre nouveau mot
            # de passe. "+code_ email_from = settings.EMAIL_HOST_USER recipient_list = [user_.email,] send_mail(
            # subject, message, email_from, recipient_list )
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
