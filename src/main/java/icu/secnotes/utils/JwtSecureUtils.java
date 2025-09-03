package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;

public class JwtSecureUtils {

    private static String signKey = "password";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法 - 安全版本，不存储敏感信息
     * @param claims JWT第二部分载荷，payload中存储的内容
     * @return
     */
    public static String generateJwt(Map<String, Object> claims) {
        // 只存储必要的非敏感信息
        Map<String, Object> secureClaims = new HashMap<>();
        secureClaims.put("id", claims.get("id"));
        secureClaims.put("username", claims.get("username"));
        secureClaims.put("name", claims.get("name"));
        secureClaims.put("iat", new Date());
        
        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(secureClaims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;
    }

    /**
     * JWT 令牌解析方法 - 安全版本
     * @param jwttoken
     * @return
     */
    public static Claims parseJwt(String jwttoken) {
        Claims claims = Jwts.parser()
                .setSigningKey(signKey)
                .parseClaimsJws(jwttoken)
                .getBody();

        return claims;
    }
}
