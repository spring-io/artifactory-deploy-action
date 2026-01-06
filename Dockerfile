FROM gradle:8.5.0-jdk21-alpine AS build
COPY src /app/src/
COPY config /app/config/
COPY build.gradle settings.gradle gradle.properties /app/
RUN cd /app && gradle -Dorg.gradle.welcome=never --no-daemon bootJar

FROM ghcr.io/bell-sw/liberica-openjdk-debian:21.0.2-14
COPY --from=build /app/build/libs/artifactory-deploy-action.jar /opt/action/artifactory-deploy.jar
ENTRYPOINT ["java", "-jar", "/opt/action/artifactory-deploy.jar"]
