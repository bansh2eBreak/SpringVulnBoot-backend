# 第一阶段：构建阶段
FROM maven:3.9.3-eclipse-temurin-11 AS build
WORKDIR /app

# 配置Maven使用阿里云镜像源
RUN mkdir -p /root/.m2 && \
    echo '<?xml version="1.0" encoding="UTF-8"?>' > /root/.m2/settings.xml && \
    echo '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"' >> /root/.m2/settings.xml && \
    echo '          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' >> /root/.m2/settings.xml && \
    echo '          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">' >> /root/.m2/settings.xml && \
    echo '    <mirrors>' >> /root/.m2/settings.xml && \
    echo '        <mirror>' >> /root/.m2/settings.xml && \
    echo '            <id>aliyunmaven</id>' >> /root/.m2/settings.xml && \
    echo '            <mirrorOf>*</mirrorOf>' >> /root/.m2/settings.xml && \
    echo '            <name>阿里云公共仓库</name>' >> /root/.m2/settings.xml && \
    echo '            <url>https://maven.aliyun.com/repository/public</url>' >> /root/.m2/settings.xml && \
    echo '        </mirror>' >> /root/.m2/settings.xml && \
    echo '    </mirrors>' >> /root/.m2/settings.xml && \
    echo '</settings>' >> /root/.m2/settings.xml

# 先复制pom文件，利用Docker缓存机制
COPY pom.xml .
# 下载依赖
RUN mvn dependency:go-offline -B

# 复制源代码
COPY src ./src
# 构建应用
RUN mvn clean package -DskipTests -B

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
