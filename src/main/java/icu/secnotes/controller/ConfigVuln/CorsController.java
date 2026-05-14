package icu.secnotes.controller.ConfigVuln;

import icu.secnotes.pojo.MfaSecret;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.MfaSecretService;
import icu.secnotes.utils.JwtUtils;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * CORS 配置漏洞演示 Controller
 *
 * 演示三种 CORS 配置场景：
 *
 * 漏洞1 - Origin 完全信任（/cors/vuln1/**）：
 *   addAllowedOriginPattern("*") + allowCredentials(true)
 *   后端反射任意 Origin，任意来源的恶意页面均可携带受害者凭证读取响应数据。
 *
 * 漏洞2 - Origin 校验可绕过（/cors/vuln2/**）：
 *   开发者本意只允许本机访问，使用 origin.contains("127.0.0.1") 做模糊匹配，
 *   但端口 80 与端口 81 是不同 Origin，两者均包含 "127.0.0.1"，攻击者页面（:81）照样绕过。
 *
 * 安全版 - 严格白名单（/cors/secure/**）：
 *   仅允许 http://trusted.secnotes.icu，其他 Origin 浏览器直接报 CORS 错误。
 *   靶场前端（127.0.0.1:80）不在白名单，访问该接口将被拦截，演示防御效果。
 */
@Tag(name = "CORS配置漏洞", description = "CORS配置错误漏洞演示")
@Slf4j
@RestController
@RequestMapping("/cors")
@RequiredArgsConstructor
public class CorsController {

    private final MfaSecretService mfaSecretService;

    /**
     * 从 JWT 解析当前登录用户身份，并从数据库查询其 MFA secret 作为敏感数据返回。
     * MFA secret 是高敏感字段，一旦泄露攻击者可伪造 OTP，直接接管账户。
     */
    private Map<String, Object> buildSensitiveData(HttpServletRequest request) {
        Map<String, Object> data = new HashMap<>();
        try {
            String token = request.getHeader("Authorization");
            if (token != null) {
                Map<?, ?> claims = JwtUtils.parseJwt(token);
                data.put("userId", claims.get("id"));
                data.put("username", claims.get("username"));

                Integer userId = Integer.valueOf(claims.get("id").toString());
                MfaSecret mfaSecret = mfaSecretService.getSecretByUserId(userId);
                if (mfaSecret != null) {
                    data.put("mfaSecret", mfaSecret.getSecret());
                } else {
                    data.put("mfaSecret", "（该用户未绑定 MFA，请先在 MFA 漏洞页面完成绑定）");
                }
            }
        } catch (Exception ignored) {}
        return data;
    }

    // ================================================================
    // 漏洞1：Origin 完全信任
    // CorsConfig 对 /cors/vuln1/** 配置了 addAllowedOriginPattern("*") + allowCredentials(true)
    // ================================================================

    @GetMapping("/vuln1/sensitiveData")
    public Result vuln1SensitiveData(HttpServletRequest request) {
        log.warn("⚠️ CORS漏洞1（Origin完全信任）：来源 Origin={}", request.getHeader("Origin"));
        return Result.success(buildSensitiveData(request));
    }

    // ================================================================
    // 漏洞2：Origin 校验可绕过
    // CorsConfig 对 /cors/vuln2/** 配置了 addAllowedOriginPattern("*127.0.0.1*")
    // 等价于 origin.contains("127.0.0.1")，:80（合法前端）和 :81（攻击者）均可通过
    // ================================================================

    @GetMapping("/vuln2/sensitiveData")
    public Result vuln2SensitiveData(HttpServletRequest request) {
        log.warn("⚠️ CORS漏洞2（Origin校验可绕过）：来源 Origin={}", request.getHeader("Origin"));
        return Result.success(buildSensitiveData(request));
    }

    // ================================================================
    // 安全版：严格白名单
    // CorsConfig 对 /cors/secure/** 仅允许 http://trusted.secnotes.icu
    // 靶场前端（127.0.0.1:80）不在白名单，浏览器将报 CORS 错误
    // ================================================================

    @GetMapping("/secure/sensitiveData")
    public Result secureSensitiveData(HttpServletRequest request) {
        log.info("✅ CORS安全版：来源 Origin={}", request.getHeader("Origin"));
        return Result.success(buildSensitiveData(request));
    }
}
