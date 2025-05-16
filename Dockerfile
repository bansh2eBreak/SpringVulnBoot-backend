# 第一阶段：构建阶段
FROM maven:3.9.3-eclipse-temurin-11 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# 第二阶段：运行阶段
FROM eclipse-temurin:11-jre-jammy
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

# 设置时区为中国时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 暴露应用端口（默认8080，可以根据实际应用端口修改）
EXPOSE 8080

# 启动命令
ENTRYPOINT ["java", "-jar", "app.jar"]
