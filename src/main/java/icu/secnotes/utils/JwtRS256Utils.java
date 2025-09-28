package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

/**
 * JWT RS256签名算法工具类
 * 演示RSA非对称加密的JWT签名和验证
 * 
 * RS256算法原理：
 * 1. 使用RSA密钥对（公钥+私钥）
 * 2. 签名：使用私钥对JWT进行签名
 * 3. 验证：使用公钥验证JWT签名
 * 4. 优势：公钥可以公开分发，私钥保密
 */
@Component
public class JwtRS256Utils {

    // RSA密钥对（用于RS256）
    private static KeyPair rsaKeyPair;
    private static Long expire = 3600000L; // 1小时

    static {
        try {
            // 生成RSA密钥对
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            rsaKeyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * 生成RS256签名的JWT
     * 使用私钥签名
     * @param claims JWT第二部分载荷，payload中存储的内容
     * @return
     */
    public static String generateRS256Jwt(Map<String, Object> claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.RS256, rsaKeyPair.getPrivate()) // 使用私钥签名
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;
    }

    /**
     * 解析RS256签名的JWT
     * 使用公钥验证
     * @param jwttoken
     * @return
     */
    public static Claims parseRS256Jwt(String jwttoken) {
        // 使用公钥验证签名
        Claims claims = Jwts.parser()
                .setSigningKey(rsaKeyPair.getPublic()) // 使用公钥验证
                .parseClaimsJws(jwttoken)
                .getBody();

        return claims;
    }

    /**
     * 易受算法混淆攻击的JWT验证方法
     * 完全按照Burp Suite官方文档的伪代码实现
     * 
     * 漏洞原理：
     * 1. 根据JWT header中的alg字段动态选择验证算法
     * 2. 如果alg="RS256"，使用公钥作为RSA公钥验证
     * 3. 如果alg="HS256"，使用公钥作为HMAC密钥验证
     * 4. 攻击者可以获取公钥，用公钥作为HMAC密钥签名HS256 JWT
     */
    public static Claims verifyVulnerable(String token, PublicKey publicKey) {
        try {
            // 解析JWT获取header
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid JWT format");
            }
            
            // 获取header中的算法类型
            String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
            String algorithm = extractAlgorithm(headerJson);
            
            // 根据算法类型选择验证方式（易受攻击的逻辑）
            if ("RS256".equals(algorithm)) {
                // 使用公钥作为RSA公钥验证
                return Jwts.parser()
                        .setSigningKey(publicKey)
                        .parseClaimsJws(token)
                        .getBody();
            } else if ("HS256".equals(algorithm)) {
                // 危险：使用公钥作为HMAC密钥验证
                // 这就是算法混淆漏洞的核心！
                return Jwts.parser()
                        .setSigningKey(publicKey.getEncoded()) // 将公钥字节作为HMAC密钥
                        .parseClaimsJws(token)
                        .getBody();
            } else {
                throw new RuntimeException("Unsupported algorithm: " + algorithm);
            }
        } catch (Exception e) {
            throw new RuntimeException("JWT verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * 从JWT header中提取算法类型
     */
    private static String extractAlgorithm(String headerJson) {
        try {
            // 简单的JSON解析，提取alg字段
            if (headerJson.contains("\"alg\":\"RS256\"")) {
                return "RS256";
            } else if (headerJson.contains("\"alg\":\"HS256\"")) {
                return "HS256";
            } else if (headerJson.contains("\"alg\":\"none\"")) {
                return "none";
            }
            return "unknown";
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract algorithm from header", e);
        }
    }

    /**
     * 获取RSA公钥对象（用于验证）
     */
    public static PublicKey getRsaPublicKeyObject() {
        return rsaKeyPair.getPublic();
    }

    /**
     * 获取用于算法混淆攻击的公钥（Base64格式）
     * 攻击者可以使用此公钥作为HMAC密钥来签名HS256 JWT
     */
    public static String getPublicKeyForAlgorithmConfusion() {
        PublicKey publicKey = rsaKeyPair.getPublic();
        return java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * 安全的JWT验证方法 - 修复算法混淆漏洞
     * 强制校验JWT必须是RS256算法，不允许其他算法
     */
    public static Claims verifySecure(String token) {
        try {
            // 解析JWT获取header
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid JWT format");
            }
            
            // 获取header中的算法类型
            String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
            String algorithm = extractAlgorithm(headerJson);
            
            // 强制校验算法必须是RS256
            if (!"RS256".equals(algorithm)) {
                throw new RuntimeException("Only RS256 algorithm is allowed, but found: " + algorithm);
            }
            
            // 使用公钥验证RS256签名
            return Jwts.parser()
                    .setSigningKey(rsaKeyPair.getPublic())
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new RuntimeException("Secure JWT verification failed: " + e.getMessage(), e);
        }
    }

}
