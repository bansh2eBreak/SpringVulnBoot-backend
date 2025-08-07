package icu.secnotes.controller.Components;

import icu.secnotes.pojo.Result;
import icu.secnotes.utils.Shiro550Util;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Shiro-550漏洞测试控制器
 * 提供payload生成和测试接口
 */
@RestController
@RequestMapping("/components/shiro")
@Slf4j
@Tag(name = "Shiro-550漏洞", description = "Shiro-550反序列化漏洞测试")
public class ShiroController {



    /**
     * 生成URLDNS链payload
     */
    @PostMapping("/generate/urldns")
    @Operation(summary = "生成URLDNS链payload", description = "生成URLDNS链的DNS探测payload")
    public Result generateURLDNSPayload(@RequestParam String dnsUrl) {
        try {
            String payload = Shiro550Util.generateURLDNSPayload(dnsUrl);
            return Result.success(payload);
        } catch (Exception e) {
            log.error("生成URLDNS payload失败", e);
            return Result.error("生成payload失败: " + e.getMessage());
        }
    }

    /**
     * Shiro登录接口
     */
    @PostMapping("/login")
    @Operation(summary = "Shiro登录", description = "Shiro框架的登录接口，用于测试Shiro-550漏洞")
    public Result shiroLogin(@RequestParam String username, 
                           @RequestParam String password,
                           @RequestParam(defaultValue = "false") boolean rememberMe) {
        try {
            // 使用Shiro进行认证
            org.apache.shiro.subject.Subject subject = org.apache.shiro.SecurityUtils.getSubject();
            org.apache.shiro.authc.UsernamePasswordToken token = 
                new org.apache.shiro.authc.UsernamePasswordToken(username, password, rememberMe);
            subject.login(token);
            
            // 获取用户信息
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("username", username);
            userInfo.put("isAuthenticated", subject.isAuthenticated());
            userInfo.put("roles", subject.hasRole("admin") ? 
                java.util.Arrays.asList("admin", "user") : java.util.Arrays.asList("user"));
            
            return Result.success(userInfo);
        } catch (Exception e) {
            log.error("Shiro登录失败", e);
            return Result.error("Shiro登录失败: " + e.getMessage());
        }
    }

    /**
     * Shiro登出
     */
    @GetMapping("/logout")
    @Operation(summary = "Shiro登出", description = "Shiro框架的登出接口")
    public Result shiroLogout() {
        try {
            org.apache.shiro.subject.Subject subject = org.apache.shiro.SecurityUtils.getSubject();
            subject.logout();
            return Result.success("Shiro登出成功");
        } catch (Exception e) {
            log.error("Shiro登出失败", e);
            return Result.error("Shiro登出失败: " + e.getMessage());
        }
    }

    /**
     * Shiro未授权页面
     */
    @GetMapping("/unauthorized")
    @Operation(summary = "Shiro未授权页面", description = "Shiro未授权页面")
    public Result shiroUnauthorized() {
        return Result.error("Shiro未授权访问");
    }

    /**
     * 测试权限
     */
    @GetMapping("/test/permission/{permission}")
    @Operation(summary = "测试权限", description = "测试用户是否具有指定权限")
    public Result testPermission(@PathVariable String permission) {
        try {
            org.apache.shiro.subject.Subject subject = org.apache.shiro.SecurityUtils.getSubject();
            if (subject.isPermitted(permission)) {
                return Result.success("用户具有 " + permission + " 权限");
            } else {
                return Result.error("用户不具有 " + permission + " 权限");
            }
        } catch (Exception e) {
            log.error("权限检查失败", e);
            return Result.error("权限检查失败: " + e.getMessage());
        }
    }

    /**
     * 测试角色
     */
    @GetMapping("/test/role/{role}")
    @Operation(summary = "测试角色", description = "测试用户是否具有指定角色")
    public Result testRole(@PathVariable String role) {
        try {
            org.apache.shiro.subject.Subject subject = org.apache.shiro.SecurityUtils.getSubject();
            if (subject.hasRole(role)) {
                return Result.success("用户具有 " + role + " 角色");
            } else {
                return Result.error("用户不具有 " + role + " 角色");
            }
        } catch (Exception e) {
            log.error("角色检查失败", e);
            return Result.error("角色检查失败: " + e.getMessage());
        }
    }

} 