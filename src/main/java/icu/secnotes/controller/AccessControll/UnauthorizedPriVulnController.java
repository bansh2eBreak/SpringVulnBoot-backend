package icu.secnotes.controller.AccessControll;

import icu.secnotes.pojo.MfaSecret;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.MfaSecretService;
import icu.secnotes.utils.JwtUtils;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;

@Tag(name = "未授权访问漏洞", description = "未授权访问漏洞演示")
@RestController
@Slf4j
@RequestMapping("/accessControl/UnauthorizedPri")
public class UnauthorizedPriVulnController {

    @Autowired
    private MfaSecretService mfaSecretService;

    /**
     * 未授权访问漏洞，不需要认证登录就可以获取其他人的MFA密钥
     * @param userId
     * @return
     */
    @GetMapping("/vuln1/{userId}")
    public Result getMfaSecretByUnAuth(@PathVariable Integer userId) {
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

}
