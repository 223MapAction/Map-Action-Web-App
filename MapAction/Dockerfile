# Use an official Python runtime as a parent image
FROM python:3.12.0

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Run linting with flake8

RUN pip install flake8
RUN flake8 --ignore=E501,F401 ./Mapapi

# Set the working directory to /app/MapAction

# Install coverage and run tests
RUN pip install coverage
RUN coverage run manage.py test
RUN coverage report

# Run Django tests
CMD ["python", "manage.py", "test"]
