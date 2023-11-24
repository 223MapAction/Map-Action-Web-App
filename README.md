# Map-Action-Web-App
It is used for the api and the web application
## Requirement 
- python v3
- Django v4
### Setup
- Clone the repository
- setup the virtual env first 
it can be doing with the following command:
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
**Note:**
if your system is Linux or MacOS
you have to add 3 on python
example python3 manage.py runserver



