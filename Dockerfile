# --- 多阶段构建：第一阶段用于构建 Spring Boot JAR ---
FROM openjdk:11-jdk-slim as builder

WORKDIR /app
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

# 复制 Maven 项目文件，让 Maven 下载依赖，利用 Docker 层缓存
COPY pom.xml .
COPY src ./src
# 如果有父 pom 或其他模块依赖，也需要复制
# COPY ../pom.xml /app/../pom.xml

# 使用 Maven wrapper 或本地 Maven 打包
# 对于 Maven wrapper:
# COPY mvnw .
# COPY .mvn .mvn
# RUN ./mvnw package -DskipTests
# 对于本地 Maven (需要确保镜像中有 mvn):
RUN mvn package -DskipTests

# 找到生成的 JAR 文件 (通常在 target 目录下)
# 例如，如果你的 JAR 叫 app.jar，并且在 target 目录下
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} app.jar

# --- 第二阶段：使用 JRE 镜像运行 JAR ---
FROM openjdk:11-jre-slim

WORKDIR /app

# 从构建阶段复制 JAR 文件
COPY --from=builder /app/app.jar ./

# 暴露 Spring Boot 应用的端口 (通常是 8080)
EXPOSE 8080

# 设置容器启动时执行的命令，运行 Spring Boot JAR
ENTRYPOINT ["java","-jar","app.jar"]

# 可以在这里添加 HEALTHCHECK (健康检查) 如果需要
# HEALTHCHECK --interval=30s --timeout=10s --retries=5 CMD curl --fail http://localhost:8080/actuator/health || exit 1