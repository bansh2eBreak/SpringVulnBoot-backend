package icu.secnotes.utils;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

public class GoogleAuthenticatorUtil {

    private static final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    /**
     * 生成密钥
     * @return 生成的密钥信息
     */
    public static GoogleAuthenticatorKey createCredentials() {
        return gAuth.createCredentials();
    }

    /**
     * 生成二维码URL
     * @param username 用户名
     * @param issuer 发行者(一般是应用名称)
     * @param secret 密钥
     * @return 二维码URL
     */
    public static String getQRCodeUrl(String username, String issuer, String secret) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(issuer, username, new GoogleAuthenticatorKey.Builder(secret).build());
    }

    /**
     * 验证动态口令
     * @param secret 密钥
     * @param code 待验证的口令
     * @return 是否验证通过
     */
    public static boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
}
