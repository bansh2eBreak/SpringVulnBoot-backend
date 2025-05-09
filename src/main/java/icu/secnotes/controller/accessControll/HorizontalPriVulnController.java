package icu.secnotes.controller.accessControll;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import icu.secnotes.pojo.MfaSecret;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.MfaSecretService;
import icu.secnotes.utils.GoogleAuthenticatorUtil;
import icu.secnotes.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/accessControl/HorizontalPri")
public class HorizontalPriVulnController {

    @Autowired
    private MfaSecretService mfaSecretService;

    /**
     * 用户绑定MFA密钥
     * @param mfaSecret
     * @return
     */
    @PostMapping("/bindMfa")
    public Result bindMfaSecret(@RequestBody MfaSecret mfaSecret, HttpServletRequest request) {
        // 获取JWT Token
        String jwttoken = request.getHeader("Authorization");
        try {
            // 解析获取JWT中用户ID
            String tokenUserId = JwtUtils.parseJwt(jwttoken).get("id").toString();

            // 验证用户只能绑定自己的MFA密钥，否则退出
            if (!mfaSecret.getUserId().toString().equals(tokenUserId)) {
                log.warn("用户 {} 尝试越权绑定用户 {} 的MFA密钥", tokenUserId, mfaSecret.getUserId());
                return Result.error("无权绑定其他用户的MFA密钥");
            }

            // 检查用户是否已有MFA密钥，否则退出
            MfaSecret existingSecret = mfaSecretService.getSecretByUserId(mfaSecret.getUserId());
            if (existingSecret != null) {
                // 表示用户已绑定MFA
                return Result.error("用户已经绑定过MFA");
            }

            // 生成google mfa secreate
            GoogleAuthenticatorKey credentials = GoogleAuthenticatorUtil.createCredentials();
            String secret = credentials.getKey();
            log.info("生成的MFA密钥: {}", secret);

            String qrCodeUrl = GoogleAuthenticatorUtil.getQRCodeUrl("admin", "SpringVulnBoot", secret);
            log.info(qrCodeUrl);

            // 设置GoogleAuthenticatorKey
            mfaSecret.setSecret(secret);

            // 设置创建时间为当前，update_time为null
            mfaSecret.setCreateTime(LocalDateTime.now());

            // 为用户生成google authenticator的密钥
            Integer res = mfaSecretService.createMfaSecret(mfaSecret);

            // 进行判断
            if (res > 0) {
                // 表示用户mfa生成成功
//                return Result.success("用户MFA绑定成功");
                // 表示用户mfa生成成功
                Map<String, String> data = new HashMap<>();
                data.put("secret", secret);
                data.put("qrCodeUrl", qrCodeUrl);

                return Result.success(data);
            } else {
                // 表示用户mfa生成成功
                return Result.error("用户MFA绑定失败");
            }

        } catch (Exception e) {
            log.error("JWT验证失败", e);
            return Result.error("身份验证失败");
        }

    }

    /**
     * 删除用户的MFA密钥
     * @param mfaSecret
     * @return
     */
    @PostMapping("/resetMfa")
    public Result resetMfaSecret(@RequestBody MfaSecret mfaSecret, HttpServletRequest request) {
        // 获取JWT Token
        String jwttoken = request.getHeader("Authorization");
        try {
            // 解析获取JWT中用户ID
            String tokenUserId = JwtUtils.parseJwt(jwttoken).get("id").toString();

            // 验证用户只能重置自己的MFA密钥
            if (!mfaSecret.getUserId().toString().equals(tokenUserId)) {
                log.warn("用户 {} 尝试越权重置用户 {} 的MFA密钥", tokenUserId, mfaSecret.getUserId());
                return Result.error("无权重置其他用户的MFA密钥");
            }
            // 删除用户的MFA密钥
            Integer res = mfaSecretService.deleteMfaSecret(mfaSecret);
            if (res > 0) {
                return Result.success("用户MFA解绑成功");
            } else {
                return Result.error("用户MFA解绑失败");
            }

        } catch (Exception e) {
            log.error("JWT验证失败", e);
            return Result.error("身份验证失败");
        }

    }

    /**
     * 越权漏洞，可越权查询其他用户的MFA密钥
     * @param userId
     * @return
     */
    @GetMapping("/vuln1/{userId}")
    public Result getMfaSecret(@PathVariable Integer userId) {
        MfaSecret mfaSecret = mfaSecretService.getSecretByUserId(userId);
        if (mfaSecret != null) {
            return Result.success(mfaSecret.getSecret());
        } else {
            return Result.error("用户不存在或者用户未绑定MFA");
        }
    }

    /**
     * 安全获取MFA密钥接口
     * 使用JWT验证用户身份，防止越权访问
     * @param userId 用户ID
     * @param request HTTP请求对象，用于获取JWT token
     * @return MFA密钥信息
     */
    @GetMapping("/sec1/{userId}")
    public Result getSecureMfaSecret(@PathVariable Integer userId, HttpServletRequest request) {
        // 获取JWT token
        String jwttoken = request.getHeader("Authorization");

        try {
            // 解析获取JWT中用户ID
            String tokenUserId = JwtUtils.parseJwt(jwttoken).get("id").toString();
            
            // 验证用户只能访问自己的MFA密钥
            if (!userId.toString().equals(tokenUserId)) {
                log.warn("用户 {} 尝试越权访问用户 {} 的MFA密钥", tokenUserId, userId);
                return Result.error("无权访问其他用户的MFA密钥");
            }

            // 获取MFA密钥
            MfaSecret mfaSecret = mfaSecretService.getSecretByUserId(userId);
            if (mfaSecret != null) {
                return Result.success(mfaSecret.getSecret());
            } else {
                return Result.error("用户不存在或者用户未绑定MFA");
            }
        } catch (Exception e) {
            log.error("JWT验证失败", e);
            return Result.error("身份验证失败");
        }
    }

    /**
     * 未授权访问漏洞，不需要认证登录就可以获取其他人的MFA密钥
     * @param userId
     * @return
     */
    @GetMapping("/vuln2/{userId}")
    public Result getMfaSecretByUnAuth(@PathVariable Integer userId) {
        MfaSecret mfaSecret = mfaSecretService.getSecretByUserId(userId);
        if (mfaSecret != null) {
            return Result.success(mfaSecret.getSecret());
        } else {
            return Result.error("用户不存在或者用户未绑定MFA");
        }
    }

}
