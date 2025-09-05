package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.Map;

public class JwtSecureArbitraryUtils {

    private static String signKey = "password";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法 - 安全实现
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
     * JWT 令牌解析方法 - 安全实现（严格验证签名）
     * @param jwttoken
     * @return
     */
    public static Claims parseJwt(String jwttoken) {
        // 安全：严格验证签名，不允许任意签名
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(signKey)
                    .parseClaimsJws(jwttoken)
                    .getBody();
            
            // 验证过期时间
            if (claims.getExpiration().before(new Date())) {
                throw new RuntimeException("Token已过期");
            }
            
            return claims;
        } catch (Exception e) {
            // 安全：验证失败时抛出异常，不尝试其他方式
            throw new RuntimeException("JWT验证失败: " + e.getMessage());
        }
    }
}
