# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory to /app
WORKDIR /app
ARG DEBIAN_FRONTEND=noninteractive
RUN ln -s /usr/bin/dpkg-split /usr/sbin/dpkg-split
RUN ln -s /usr/bin/dpkg-deb /usr/sbin/dpkg-deb
RUN ln -s /bin/tar /usr/sbin/tar
RUN ln -s /bin/rm /usr/sbin/rm
RUN apt-get update \
    && apt-get install -y \
        apt-utils \
        gcc \
        g++ \
        build-essential libssl-dev libffi-dev python-dev python-pip python3-dev cargo  \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app
RUN python -m pip install -U pip

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt \
    && apt-get purge -y --auto-remove gcc g++ build-essential libssl-dev libffi-dev python-dev python-pip python3-dev cargo

# Copy the current directory contents into the container at /app
COPY . /app

# Make port 80 available to the world outside this container
EXPOSE 31337

# Define environment variable
#ENV NAME World

VOLUME /app/data

# Run app.py when the container launches
ENTRYPOINT ["python", "kitana.py"]