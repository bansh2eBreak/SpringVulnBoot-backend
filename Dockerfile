FROM maven:3.9-openjdk-11 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar

FROM openjdk:11-jre-slim
WORKDIR /app
COPY --from=builder /app/app.jar ./
EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]