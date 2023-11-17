# Map-Action-Web-App
It is used for the api and the web application
# Requirement 
python^3
Django^4
# Setup
Clone the repository
setup the virtual env first, it can be doing with the following command:
on Linux, MacOS:
python3 -m venv env_name
and activate it by
source env_name/bin/activate

on windows
py -m venv env_name
activate it by
source env_name/script/activate.bat

install the requirements packages
pip install -r requirements.txt 

Apply migrations

python manage.py makemigrations
and
python manage.py migrate 

Run the server

python manage.py runserver 

it running on http:127.0.0.1:8000/

if your system is Linux or MacOS
you have to add 3 on python
example python3 manage.py runserver



