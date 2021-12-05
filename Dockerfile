# Use an official Python runtime as a parent image
FROM python:3.8-alpine

# Set the working directory to /app
WORKDIR /app

# Add Kitana files not filtered by .dockerignore to the image
COPY . .

# still meh. do we want to drop armv7?
ARG CRYPTOGRAPHY_DONT_BUILD_RUST=1

# We chain the following steps to create a single layer, reducing image size
# - Install packages needed to run and compile
# - Install and compile required Python packgages
# - Remove packages needed only for compiling
RUN apk add -U --repository=http://dl-cdn.alpinelinux.org/alpine/v3.13/main \
    gcc g++ musl-dev openssl-dev libffi-dev cargo build-base \
    libstdc++ \
    && pip install --trusted-host pypi.python.org -r requirements.txt \
    && apk del -r --purge \
    gcc g++ musl-dev openssl-dev libffi-dev cargo build-base \
    && rm /var/cache/apk/*

# Expose the port
EXPOSE 31337

# Store session tokens here
VOLUME /app/data

# Run kitana.py when the container launches
ENTRYPOINT ["python", "kitana.py"]