# --- 多阶段构建：第一阶段用于构建 Spring Boot JAR ---
# 使用集成了 JDK 11 和 Maven 的镜像作为构建阶段的基础
FROM maven:3.9-openjdk-11 AS builder

WORKDIR /app

# 复制 Maven 项目文件，让 Maven 下载依赖，利用 Docker 层缓存
# 复制 pom.xml 和 src 目录
COPY pom.xml .
COPY src ./src
# 如果有父 pom 或其他模块依赖，也需要复制

# 直接使用预装的 mvn 命令执行打包
RUN mvn package -DskipTests # *** 直接运行 mvn 命令 ***


# 找到生成的 JAR 文件 (通常在 target 目录下)
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