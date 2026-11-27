# The Ansible image of the scenarios, which applies realm/ with the same play that the installations run
# from the tooling image of the set (Identity ADR 0009, Q11 of the plan). Every part is pinned: Python by
# the index digest of python:3.13-slim, ansible-core and every package it needs at exact versions in
# requirements.txt, and the collection middleware_automation.keycloak at 3.1.3 without the collections it
# names for its roles, which the play does not use: its modules import only the collection itself.
FROM python:3.13-slim@sha256:7249d5587b78209a006dc4a3b5340678f84ea729239193aa559962cd8c1fce50
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps -r /tmp/requirements.txt \
    && ansible-galaxy collection install --no-deps -p /usr/share/ansible/collections middleware_automation.keycloak:==3.1.3
USER 65532:65532
ENV HOME=/tmp ANSIBLE_LOCAL_TEMP=/tmp/.ansible ANSIBLE_HOME=/tmp/.ansible ANSIBLE_PYTHON_INTERPRETER=auto_silent
