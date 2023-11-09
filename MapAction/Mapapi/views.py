from django.shortcuts import render, HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view


@api_view(('GET', 'POST'))
def login(request):
    if request.method == 'GET':
        return Response('i am a test', status=status.HTTP_200_OK)
    if request.method == 'POST':
        return Response("i am a test too", status=status.HTTP_200_OK)