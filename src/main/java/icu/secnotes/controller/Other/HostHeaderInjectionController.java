package icu.secnotes.controller.Other;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.LoginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Host Header 注入漏洞演示控制器（密码重置投毒场景）
 *
 * 漏洞版：从 HTTP 请求头 Host 中拼接重置链接 baseUrl，攻击者可控制邮件里的链接域名/端口，
 *        诱导被害人点击钓鱼链接，泄露 reset token，进而接管账户。
 * 安全版：从 application.yml 的 app.base-url 配置读取 baseUrl，永远不信任 Host 头。
 *
 * 本靶场用 127.0.0.1:80（合法）与 127.0.0.1:81（攻击者站点）模拟"业务方"与"攻击者站点"，
 * 不依赖真实域名即可完整演示攻击闭环。
 */
@RestController
@RequestMapping("/hostHeaderInjection")
@Slf4j
@Tag(name = "HostHeader注入漏洞", description = "密码重置投毒（Password Reset Poisoning）漏洞演示")
public class HostHeaderInjectionController {

    @Autowired
    private LoginService loginService;

    /**
     * token → username 的内存映射（演示用，进程重启即清空）
     */
    private static final Map<String, String> RESET_TOKENS = new ConcurrentHashMap<>();

    /**
     * 安全版用的固定 baseUrl，来自配置，不受 Host 头影响
     */
    @Value("${app.base-url:http://127.0.0.1}")
    private String safeBaseUrl;

    /**
     * 漏洞版"忘记密码"接口：用 Host 头拼接重置链接
     */
    @PostMapping("/forgot-password/vuln")
    @Operation(summary = "忘记密码-漏洞版", description = "用 request.getHeader(\"Host\") 拼 baseUrl，攻击者可投毒")
    public Result forgotPasswordVuln(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String username = body == null ? null : body.get("username");
        if (username == null || username.trim().isEmpty()) {
            return Result.error("用户名不能为空");
        }

        String token = UUID.randomUUID().toString().substring(0, 8);
        RESET_TOKENS.put(token, username);

        // ❌ 漏洞点：Host 头完全由客户端控制，攻击者可注入任意值
        String scheme = request.getScheme();
        String host = request.getHeader("Host");
        String resetLink = scheme + "://" + host + "/host-header-injection-reset.html?token=" + token;

        log.warn("【HostHeader-VULN】username={}, Host={}, resetLink={}", username, host, resetLink);

        return Result.success(buildMailPreview(username, resetLink, host, "vuln"));
    }

    /**
     * 安全版"忘记密码"接口：从配置文件读 baseUrl，Host 头无效
     */
    @PostMapping("/forgot-password/sec")
    @Operation(summary = "忘记密码-安全版", description = "从 application.yml 的 app.base-url 读 baseUrl，Host 头无效")
    public Result forgotPasswordSec(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String username = body == null ? null : body.get("username");
        if (username == null || username.trim().isEmpty()) {
            return Result.error("用户名不能为空");
        }

        String token = UUID.randomUUID().toString().substring(0, 8);
        RESET_TOKENS.put(token, username);

        // ✅ baseUrl 来自配置，无论 Host 怎么传都不受影响
        String resetLink = safeBaseUrl + "/host-header-injection-reset.html?token=" + token;
        String injectedHost = request.getHeader("Host");

        log.info("【HostHeader-SEC】username={}, 收到 Host={}（被忽略）, resetLink={}", username, injectedHost, resetLink);

        return Result.success(buildMailPreview(username, resetLink, injectedHost, "sec"));
    }

    /**
     * 用 token 真改密码（模拟攻击者拿到 token 后接管账号）
     * 漏洞版/安全版都调用此接口
     */
    @PostMapping("/reset")
    @Operation(summary = "用 token 重置密码", description = "凭借 reset token 修改对应用户密码，模拟账号接管")
    public Result reset(@RequestBody Map<String, String> body) {
        if (body == null) {
            return Result.error("请求体不能为空");
        }
        String token = body.get("token");
        String newPassword = body.get("newPassword");

        if (token == null || token.trim().isEmpty()) {
            return Result.error("token 不能为空");
        }
        if (newPassword == null || newPassword.trim().isEmpty()) {
            return Result.error("新密码不能为空");
        }

        String username = RESET_TOKENS.remove(token);
        if (username == null) {
            return Result.error("token 无效或已使用");
        }

        int affected = loginService.changePassword(username, newPassword);
        if (affected <= 0) {
            return Result.error("密码重置失败，用户不存在：" + username);
        }

        log.warn("【HostHeader-RESET】用户 {} 密码已被 token {} 重置为：{}", username, token, newPassword);
        return Result.success("用户 " + username + " 密码已被重置为：" + newPassword);
    }

    /**
     * 构造"模拟邮件预览"返回结构（前端会渲染成邮件卡片）
     */
    private Map<String, Object> buildMailPreview(String username, String resetLink, String hostHeader, String scene) {
        Map<String, Object> mail = new HashMap<>();
        mail.put("to", username + "@secnotes.icu");
        mail.put("from", "support@secnotes.icu");
        mail.put("subject", "【SpringVulnBoot】密码重置请求");
        mail.put("body",
                "您好 " + username + "，\n\n" +
                "我们收到了您的密码重置请求，请点击以下链接重置您的密码（24 小时内有效）：\n" +
                resetLink + "\n\n" +
                "如非本人操作，请忽略本邮件。\n\n" +
                "SpringVulnBoot 安全团队");
        mail.put("resetLink", resetLink);
        mail.put("hostHeader", hostHeader);
        mail.put("scene", scene);
        return mail;
    }
}
