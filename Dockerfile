FROM python:3-alpine

# install build deps for pycryptodome and other c-based python modules
RUN apk add alpine-sdk autoconf automake libtool gcc

# add env var to let the relay know it's in a container
ENV DOCKER_RUNNING=true

# setup various container properties
VOLUME ["/data"]
CMD ["python", "-m", "relay"]
EXPOSE 8080/tcp
WORKDIR /opt/activityrelay

# install and update important python modules
RUN pip3 install -U setuptools wheel pip

# only copy necessary files
COPY relay ./relay
COPY LICENSE .
COPY README.md .
COPY requirements.txt .
COPY setup.cfg .
COPY setup.py .
COPY .git ./.git

# install relay deps
RUN pip3 install -r requirements.txt
