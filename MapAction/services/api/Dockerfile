# Use an official Python runtime as a parent image
FROM python:3.10.13-bookworm
WORKDIR /app
COPY /home/yugo19/map-action/Map-Action-Web-App/MapAction /app
ENV PYTHONDONTWRITEBYCODE 1
ENV PYTHONUNBUFFERED 1
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
CMD ["python", "manage.py", "test"]