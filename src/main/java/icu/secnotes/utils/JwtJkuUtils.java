package icu.secnotes.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * jku 远程公钥演示用的两把钥匙。
 * 登录中心私钥只在内存里，用来给员工签发令牌。
 * 攻击者公钥由页面发布后暂存，重启后需要重新发布。
 * 验签只按 jku 的路径选择这两把本地公钥，不会按地址去发 HTTP 请求。
 */
public class JwtJkuUtils {

    public static final String LOGIN_CENTER_PATH = "/jwt/jku/login-center/jwks.json";
    public static final String ATTACKER_PATH = "/jwt/jku/attacker/jwks.json";

    private static final KeyPair LOGIN_CENTER_KEY;
    private static volatile JSONObject attackerPublicJwk;

    static {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            LOGIN_CENTER_KEY = generator.generateKeyPair();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private JwtJkuUtils() {
    }

    public static String signAsLoginCenter(Map<String, Object> claims, String jku) {
        return Jwts.builder()
                .setHeaderParam("kid", "login-center")
                .setHeaderParam("jku", jku)
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 1000))
                .signWith(SignatureAlgorithm.RS256, LOGIN_CENTER_KEY.getPrivate())
                .compact();
    }

    public static Claims verify(String token, PublicKey publicKey) {
        return Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(token)
                .getBody();
    }

    public static PublicKey loginCenterPublicKey() {
        return LOGIN_CENTER_KEY.getPublic();
    }

    public static Map<String, Object> loginCenterJwks() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("keys", new Object[]{publicJwk((RSAPublicKey) LOGIN_CENTER_KEY.getPublic(), "login-center")});
        return body;
    }

    public static void publishAttackerJwk(Map<String, Object> body) {
        if (body == null) {
            throw new IllegalArgumentException("缺少公钥");
        }
        Object raw = body.get("jwk") != null ? body.get("jwk") : body;
        JSONObject jwk = JSON.parseObject(JSON.toJSONString(raw));
        if (!"RSA".equals(jwk.getString("kty")) || isBlank(jwk.getString("n")) || isBlank(jwk.getString("e"))) {
            throw new IllegalArgumentException("公钥格式不正确");
        }
        if (jwk.getString("n").length() > 2000 || jwk.getString("e").length() > 32) {
            throw new IllegalArgumentException("公钥格式不正确");
        }
        publicKeyFromJwk(jwk);
        JSONObject stored = new JSONObject();
        stored.put("kty", "RSA");
        stored.put("kid", "attacker");
        stored.put("use", "sig");
        stored.put("alg", "RS256");
        stored.put("n", jwk.getString("n"));
        stored.put("e", jwk.getString("e"));
        attackerPublicJwk = stored;
    }

    public static Map<String, Object> attackerJwks() {
        Map<String, Object> body = new LinkedHashMap<>();
        if (attackerPublicJwk == null) {
            body.put("keys", new Object[0]);
        } else {
            body.put("keys", new Object[]{attackerPublicJwk});
        }
        return body;
    }

    public static PublicKey publicKeyForJku(String jku, boolean loginCenterOnly) {
        String path = pathOf(jku);
        if (loginCenterOnly && !LOGIN_CENTER_PATH.equals(path)) {
            throw new IllegalArgumentException("jku 不是登录中心登记的地址，没有下载公钥，也没有返回工资");
        }
        if (LOGIN_CENTER_PATH.equals(path)) {
            return LOGIN_CENTER_KEY.getPublic();
        }
        if (!loginCenterOnly && ATTACKER_PATH.equals(path)) {
            if (attackerPublicJwk == null) {
                throw new IllegalArgumentException("攻击者公钥尚未发布");
            }
            return publicKeyFromJwk(attackerPublicJwk);
        }
        throw new IllegalArgumentException("不接受的 jku");
    }

    public static JSONObject readHeader(String token) {
        String[] parts = token == null ? new String[0] : token.split("\\.");
        if (parts.length != 3 || parts[0].isEmpty()) {
            throw new IllegalArgumentException("令牌格式不正确");
        }
        try {
            String json = new String(base64Url(parts[0]), StandardCharsets.UTF_8);
            JSONObject header = JSON.parseObject(json);
            if (header == null) {
                throw new IllegalArgumentException("令牌格式不正确");
            }
            return header;
        } catch (Exception e) {
            throw new IllegalArgumentException("令牌格式不正确");
        }
    }

    static String pathOf(String jku) {
        if (jku == null) {
            return "";
        }
        String raw = jku.trim();
        String path = raw;
        if (raw.contains("://")) {
            try {
                URI uri = URI.create(raw);
                if (uri.getUserInfo() != null) {
                    return "";
                }
                path = uri.getPath();
            } catch (IllegalArgumentException e) {
                return "";
            }
        }
        if (path == null) {
            return "";
        }
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }
        if (path.contains("..") || path.contains("\\")) {
            return "";
        }
        return path;
    }

    private static Map<String, String> publicJwk(RSAPublicKey publicKey, String kid) {
        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("n", base64Url(unsigned(publicKey.getModulus())));
        jwk.put("e", base64Url(unsigned(publicKey.getPublicExponent())));
        return jwk;
    }

    private static PublicKey publicKeyFromJwk(JSONObject jwk) {
        try {
            BigInteger modulus = new BigInteger(1, base64Url(jwk.getString("n")));
            BigInteger exponent = new BigInteger(1, base64Url(jwk.getString("e")));
            int bits = modulus.bitLength();
            if (bits < 2048 || bits > 4096) {
                throw new IllegalArgumentException("公钥长度不正确");
            }
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("公钥格式不正确");
        }
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static byte[] base64Url(String value) {
        String padded = value;
        int mod = padded.length() % 4;
        if (mod == 2) {
            padded += "==";
        } else if (mod == 3) {
            padded += "=";
        }
        return Base64.getUrlDecoder().decode(padded);
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
