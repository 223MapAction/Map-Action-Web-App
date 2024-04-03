from celery import shared_task
from django_http_exceptions import HTTPExceptions
from .models import *
import json
import requests

@shared_task
def prediction_task(image_name, longitude):
    
    sensitive_structures = ""
    
    fastapi_url = "http://192.168.0.10:8001/api1/image/predict/"
    payload = {"image_name": image_name, "sensitive_structures": sensitive_structures}
    longitude = longitude
    
    response = requests.post(fastapi_url, json=payload)
    
    if response.status_code != 200:
        raise HTTPExceptions.INTERNAL_SERVER_ERROR
    
    result = response.json()
    prediction = result["prediction"]
    description = result["Context"]

             # Update the incident with the matching longitude
    
    
    return prediction, description, longitude
