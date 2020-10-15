FROM python:3-buster

COPY code/requirements.txt /opt/nuvlabox/

RUN apt update && apt install nmap network-manager -y

RUN pip install -r /opt/nuvlabox/requirements.txt

RUN rm -rf /var/cache/apt/*

COPY code/ /opt/nuvlabox/

WORKDIR /opt/nuvlabox/

ENTRYPOINT ["python", "manager.py"]
