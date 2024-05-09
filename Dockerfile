# latest hash as of 20 JULY 2020
FROM alpine@sha256:452e7292acee0ee16c332324d7de05fa2c99f9994ecc9f0779c602916a672ae4

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1
ENV SH_SCRIPTS_BUCKET=SH_SCRIPTS_BUCKET
ENV PluginNames=PluginNames

LABEL maintainer="https://montycloud.com/ElectricEye" \
    version="2.0" \
    license="GPL-3.0" \
    description="Continuously monitor your AWS services for configurations that can lead to degradation of confidentiality, integrity or availability. All results will be sent to Security Hub for further aggregation and analysis."

COPY requirements.txt /tmp/requirements.txt
# NOTE: This will copy all application files and auditors to the container
COPY ./sbauditor/ ./sbauditor/

RUN \
    apk add bash && \
    apk add --no-cache python3 && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install -r /tmp/requirements.txt

CMD \
    echo ${PluginNames} && \
    python3 sbauditor/controller.py -a ${PluginNames}

