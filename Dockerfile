FROM python:3-slim

COPY code/requirements.txt /opt/nuvlabox/

RUN apt update && apt install gcc -y && pip install -r /opt/nuvlabox/requirements.txt && rm -rf /var/cache/apt/*

COPY code/ /opt/nuvlabox/

WORKDIR /opt/nuvlabox/

ONBUILD RUN ./license.sh

ENTRYPOINT ["python", "manager.py"]
