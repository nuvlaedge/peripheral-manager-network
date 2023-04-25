ARG BASE_IMAGE=nuvladev/nuvlaedge-base:latest
FROM ${BASE_IMAGE} as builder

COPY code/requirements.txt /opt/nuvlaedge/

RUN apk update && apk add --no-cache gcc musl-dev linux-headers

RUN pip install -r /opt/nuvlaedge/requirements.txt

# ----
FROM ${BASE_IMAGE}

ARG GIT_BRANCH
ARG GIT_COMMIT_ID
ARG GIT_BUILD_TIME
ARG GITHUB_RUN_NUMBER
ARG GITHUB_RUN_ID
ARG PROJECT_URL

LABEL git.branch=${GIT_BRANCH}
LABEL git.commit.id=${GIT_COMMIT_ID}
LABEL git.build.time=${GIT_BUILD_TIME}
LABEL git.run.number=${GITHUB_RUN_NUMBER}
LABEL git.run.id=${GITHUB_RUN_ID}
LABEL org.opencontainers.image.authors="support@sixsq.com"
LABEL org.opencontainers.image.created=${GIT_BUILD_TIME}
LABEL org.opencontainers.image.url=${PROJECT_URL}
LABEL org.opencontainers.image.vendor="SixSq SA"
LABEL org.opencontainers.image.title="NuvlaEdge Peripheral Manager Network"
LABEL org.opencontainers.image.description="Finds and identifies network peripherals in the vicinity of the NuvlaEdge"

COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages

COPY code/ LICENSE /opt/nuvlaedge/

WORKDIR /opt/nuvlaedge/

ONBUILD RUN ./license.sh

ENTRYPOINT ["python", "network_manager.py"]
