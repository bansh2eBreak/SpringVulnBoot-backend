package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.Map;

public class JwtStrongUtils {

    // 使用强密码作为签名密钥（至少32位，包含大小写字母、数字、特殊字符）
    private static String signKey = "A9b8C7d6E5f4G3h2I1j0K9l8M7n6O5p4Q3r2";
    private static Long expire = 3600000L; // 1小时

    /**
     * JWT 令牌生成方法 - 使用强密码
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
     * JWT 令牌解析方法 - 使用强密码
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
