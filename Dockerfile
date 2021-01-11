# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD sociallogin /app
ADD requirements.txt /app
ADD config.py /app
ADD wsgi.py /app
ADD bin /app

# Install any needed packages specified in requirements.txt
RUN pip install -U pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Run wsgi.py when the container launches
CMD ["./bin/docker-server"]
