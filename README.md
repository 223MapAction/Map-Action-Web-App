# Map-Action-Web-App

## Overview
Map-Action-Web-App is a comprehensive solution that combines a robust API. This project is designed to manage and visualize environment-related incidents efficiently and effectively.

## Technologies
- **Django**: Used to build the backend for Map Action mobile app and dashboard.
- **Postgres**: Used to store users data and incidents reported
- **Celery**: Used as an asynchronous task queue/job 
- **Redis**: Used as a message broker for Celery and for caching.

## Features
- **API**: Provides endpoints for managing and retrieving data on environment-related incidents.
- **Web Application**: Offers a user-friendly interface for interacting with and visualizing the incident data.
- **Asynchronous Task Processing**: Uses Celery and Redis to handle background tasks efficiently.
- **Database Management**: Utilizes Postgres for robust data storage and querying capabilities.

![image](https://github.com/223MapAction/Map-Action-Web-App/assets/64170643/08e7d056-c42a-4ae2-b95a-d70ae4bfe5c1)


### Setup
- Clone the repository
- setup the virtual env first 
it can be doing with the following command

**On Linux, MacOS:**
```bash
python3 -m venv env_name
# and activate it by
source env_name/bin/activate
```

**On windows**
```bash
py -m venv env_name
#activate it by
source env_name/script/activate.bat
```

##### Install requirements packages
```bash
pip install -r requirements.txt 
```
##### Apply migrations
```bash
python manage.py makemigrations
and
python manage.py migrate 
```

##### Run the server
```bash
python manage.py runserver 
```
it running on http:127.0.0.1:8000/

## Contibute to the project
Map Action is an open source project. Fell free to fork the source and contribute with your features. Please follow our [contribution guidelines](CONTRIBUTING.md).

## Authors
Our code squad : A7640S & Yugo19

## Licensing

This project was built under the [GNU General Public Licence](LICENSE).


##### Note
if your system is Linux or MacOS
you have to add 3 on python
example python3 manage.py runserver



