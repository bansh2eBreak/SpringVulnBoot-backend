package icu.secnotes.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.Map;

public class JwtUtils {

    private static String signKey = "password";
    private static Long expire = 4320000000L; //表示有效期1200h：1200 * 3600 * 1000 = 43200000

    /**
     * JWT 令牌生成方法
     * @param claims JWT第二部分载荷，paylaod中存储的内容
     * @return
     */
    public static String generateJwt(Map<String, Object> claims){

        String jwttoken = Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, signKey)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expire))
                .compact();

        return jwttoken;

    }

    /**
     * JWT 令牌解析方法
     * @param jwttoken
     * @return
     */
    public static Claims parseJwt(String jwttoken){
        Claims claims = Jwts.parser()
                .setSigningKey(signKey)
                .parseClaimsJws(jwttoken)
                .getBody();

        return claims;
    }

}