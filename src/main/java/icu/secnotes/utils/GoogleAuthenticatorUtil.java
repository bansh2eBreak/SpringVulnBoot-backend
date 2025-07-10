package icu.secnotes.utils;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import java.util.concurrent.TimeUnit;

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
        // 设置只允许当前窗口
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30)) // 30秒窗口
                .setWindowSize(1) // 表示只验证当前时间窗口（即当前 30 秒内）的验证码，不验证前一个或后一个窗口的代码
                .build();
        GoogleAuthenticator gAuth = new GoogleAuthenticator(config);
        return gAuth.authorize(secret, code);
    }
}
