FROM python:3-alpine

RUN apk update && apk add nmap nmcli -y

RUN rm -rf /var/cache/apk/*

COPY code/ /opt/nuvlabox/

WORKDIR /opt/nuvlabox/

ENTRYPOINT ["manager.sh"]
