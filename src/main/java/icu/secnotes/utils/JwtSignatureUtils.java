package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.Map;

public class JwtSignatureUtils {

    private static String signKey = "K9mN8bV7cX6zA5qW4eR3tY2uI1oP0aS9dF8gH7jK6lZ5xC4vB3nM2qW1eR0tY9uI8oP7aS6dF5gH4jK3lZ2xC1vB0nM9qW8eR7tY6uI5oP4aS3dF2gH1jK0lZ9xC8vB7nM6qW5eR4tY3uI2oP1aS0dF9gH8jK7lZ6xC5vB4nM3qW2eR1tY0uI9oP8aS7dF6gH5jK4lZ3xC2vB1nM0qW9eR8tY7uI6oP5aS4dF3gH2jK1lZ0xC9vB8nM7qW6eR5tY4uI3oP2aS1dF0gH9jK8lZ7xC6vB5nM4qW3eR2tY1uI0oP9aS8dF7gH6jK5lZ4xC3vB2nM1qW0eR9tY8uI7oP6aS5dF4gH3jK2lZ1xC0vB9nM8qW7eR6tY5uI4oP3aS2dF1gH0jK9lZ8xC7vB6nM5qW4eR3tY2uI1oP0aS9dF8gH7jK6lZ5x";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法 - 正常生成
     * @param claims JWT第二部分载荷，payload中存储的内容
     * @return
     */
    public static String generateJwt(Map<String, Object> claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;
    }

    /**
     * JWT 令牌解析方法 - 漏洞实现（接受没有签名的令牌）
     * @param jwttoken
     * @return
     */
    public static Claims parseVulnJwt(String jwttoken) {
        // 漏洞：接受没有签名的令牌
        // 重点是使用 .parse() 方法而不是 .parseClaimsJws()
        Jwt jwt = Jwts.parser()
            .setSigningKey(signKey)
            .parse(jwttoken);

        return (Claims) jwt.getBody();

    }

    /**
     * JWT 令牌解析方法 - 安全实现（严格验证签名）
     * @param jwttoken
     * @return
     */
    public static Claims parseSecureJwt(String jwttoken) {
        // .parseClaimsJws() 方法严格验证签名，拒绝none算法
        Claims claims = Jwts.parser()
                .setSigningKey(signKey)
                .parseClaimsJws(jwttoken)
                .getBody();

        return claims;
    }
}
