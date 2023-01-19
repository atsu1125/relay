FROM python:3-alpine
WORKDIR /workdir
RUN apk add alpine-sdk autoconf automake libtool gcc

ADD requirements.txt /workdir/
RUN pip3 install -r requirements.txt
ADD . /workdir/
CMD ["python", "-m", "relay"]
VOLUME ["/workdir/data"]
