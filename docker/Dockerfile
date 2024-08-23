FROM eclipse-temurin:19

ARG VERSION

RUN mkdir /opt/log-anonymiser

ADD https://github.com/spatineo/log-anonymiser/releases/download/log-anonymiser-${VERSION}/log-anonymiser-${VERSION}.jar /opt/log-anonymiser/log-anonymiser.jar

COPY ./scripts/process.sh /opt/log-anonymiser/

RUN chmod +xr -R /opt/log-anonymiser

USER root

ENTRYPOINT ["/bin/bash", "/opt/log-anonymiser/process.sh"]

