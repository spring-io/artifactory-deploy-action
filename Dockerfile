FROM gradle:9-jdk17 AS build
COPY action /app/action/
COPY library /app/library/
COPY config /app/config/
COPY build.gradle settings.gradle gradle.properties /app/
RUN cd /app && gradle -Dorg.gradle.welcome=never --no-daemon bootJar

FROM ghcr.io/bell-sw/liberica-openjdk-debian:25
COPY --from=build /app/action/build/libs/action.jar /opt/action/artifactory-deploy.jar
ENTRYPOINT ["java", "-jar", "/opt/action/artifactory-deploy.jar"]
