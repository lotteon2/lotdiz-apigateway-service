FROM openjdk:11-slim-buster

WORKDIR /app

ARG ORIGINAL_JAR_FILE=./build/libs/apigateway-service-1.0.0.jar

COPY ${ORIGINAL_JAR_FILE} apigateway-service.jar

ENV DEFAULT_PORT 8000

EXPOSE ${DEFAULT_PORT}

CMD ["java", "-jar", "/app/apigateway-service.jar"]
