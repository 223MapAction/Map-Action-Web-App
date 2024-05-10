from celery import shared_task
from django_http_exceptions import HTTPExceptions
from .models import *
import json
import requests
import overpy

@shared_task
def prediction_task(image_name, longitude, latitude, incident_id):
    
    sensitive_structures = OverpassCall(latitude, longitude)
    print(sensitive_structures)
    
    fastapi_url = "http://51.159.141.113:8001/api1/image/predict/"
    
    payload = {"image_name": image_name, "sensitive_structures": sensitive_structures, "incident_id": str(incident_id)}
    longitude = longitude
    
    response = requests.post(fastapi_url, json=payload)
    
    if response.status_code != 200:
        raise HTTPExceptions.INTERNAL_SERVER_ERROR
    
    result = response.json()
    prediction = result["prediction"]
    context = result["context"]
    in_depth = result["in_depht"]
    piste_solution = result["piste_solution"]

    
    
    return prediction, longitude, context, in_depth, piste_solution


@shared_task
def OverpassCall(lat, lon):
    
    query = f"""
        [out:json];
        (
            node["amenity"="school"](around:50, {lat}, {lon});
            node["amenity"="river"](around:50, {lat}, {lon});
            node["amenity"="marigot"](around:50, {lat}, {lon});
            node["amenity"="clinic"](around:50, {lat}, {lon});
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
            
    return results_list