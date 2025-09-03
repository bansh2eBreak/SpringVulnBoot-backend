package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;

import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class JwtArbitraryUtils {

    private static String signKey = "password";
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
     * JWT 令牌解析方法 - 接受任意签名（漏洞实现）
     * @param jwttoken
     * @return
     */
    public static Claims parseJwt(String jwttoken) {
        // 漏洞：不验证签名或接受任意签名
        try {
            // 尝试使用原始密钥解析
            Claims claims = Jwts.parser()
                    .setSigningKey(signKey)
                    .parseClaimsJws(jwttoken)
                    .getBody();
            return claims;
        } catch (Exception e) {
            // 漏洞：如果原始密钥解析失败，尝试使用空密钥或默认密钥
            try {
                Claims claims = Jwts.parser()
                        .setSigningKey("") // 使用空密钥
                        .parseClaimsJws(jwttoken)
                        .getBody();
                return claims;
            } catch (Exception e2) {
                // 漏洞：如果还是失败，尝试不验证签名
                String[] parts = jwttoken.split("\\.");
                if (parts.length == 3) {
                    try {
                        // 直接解码payload部分，不验证签名
                        String payload = new String(Base64.getDecoder().decode(parts[1]));
                        // 这里应该解析JSON，但为了简化，直接返回一个包含payload的Claims对象
                        return new DefaultClaims() {{
                            put("payload", payload);
                        }};
                    } catch (Exception e3) {
                        // 如果解码失败，返回null
                        return null;
                    }
                }
            }
        }
        return null;
    }
}
