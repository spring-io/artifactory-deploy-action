FROM maniator/gh:v2.103 AS build
RUN gh release download v0.0.6 --repo spring-io/artifactory-deploy-action --pattern 'action.jar'

FROM ghcr.io/bell-sw/liberica-openjdk-debian:25
COPY --from=build gh/action.jar /opt/action/artifactory-deploy.jar
ENTRYPOINT ["java", "-jar", "/opt/action/artifactory-deploy.jar"]
