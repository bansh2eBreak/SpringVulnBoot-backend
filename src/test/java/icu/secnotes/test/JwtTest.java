package icu.secnotes.test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Date;
import java.util.Map;

public class JwtTest {

    private static String weakSignKey = "Aa123123";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法
     * @param claims JWT第二部分载荷，payload中存储的内容
     * @return
     */
    public static String generateJwt(Map<String, Object> claims) {
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, weakSignKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;
    }

    /**
     * JWT 令牌解析方法 - 使用弱密码
     * @param jwttoken
     * @return
     */
    public static Claims parseJwt(String jwttoken) {
        Claims claims = Jwts.parser()
                .setSigningKey(weakSignKey)
                .parseClaimsJws(jwttoken)
                .getBody();

        return claims;
    }

    /**
     * 解析JWT并分别展示header和payload
     * @param jwttoken JWT令牌
     */
    public static void parseAndDisplayJwt(String jwttoken) {
        try {
            // 分割JWT的三个部分
            String[] parts = jwttoken.split("\\.");
            if (parts.length != 3) {
                System.out.println("无效的JWT格式");
                return;
            }

            // 解析header
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            System.out.println("=== JWT Header ===");
            System.out.println(headerJson);
            System.out.println();

            // 解析payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            System.out.println("=== JWT Payload ===");
            System.out.println(payloadJson);
            System.out.println();

            // 使用Claims对象解析（带签名验证）
            Claims claims = parseJwt(jwttoken);
            System.out.println("=== 解析后的Claims对象 ===");
            System.out.println("用户ID: " + claims.get("id"));
            System.out.println("用户名: " + claims.get("username"));
            System.out.println("姓名: " + claims.get("name"));
            System.out.println("过期时间: " + claims.getExpiration());
            System.out.println();

        } catch (Exception e) {
            System.out.println("解析JWT时发生错误: " + e.getMessage());
        }
    }

    public static String generateAndDisplayJwt() {
        // 登录成功，生成JWT
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("id", 1);
        claims.put("username", "zhangsan");
        claims.put("name", "张三");
        
        return generateJwt(claims);
 
    }

    // 测试方法
    public static void main(String[] args) {

        // 1. 生成JWT并分开展示
        String jwt = generateAndDisplayJwt();
        System.out.println("生成的JWT令牌: " + jwt);

        // 2. 解析JWT并分开展示
        parseAndDisplayJwt(jwt);

    }
    
}
