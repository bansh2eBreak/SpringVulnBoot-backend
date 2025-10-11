package icu.secnotes.controller.CSRF;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.LoginService;
import icu.secnotes.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * CSRF漏洞演示Controller
 * 用于演示CSRF攻击和防护机制
 */
@Slf4j
@RestController
@RequestMapping("/csrf")
public class CsrfController {

    @Autowired
    private LoginService loginService;

    /**
     * 修改密码接口 - 存在CSRF漏洞（演示用）
     * 只验证新密码，不验证旧密码，容易被CSRF攻击
     */
    @PostMapping("/changePasswordVuln")
    public Result changePasswordVuln(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        String newPassword = request.get("newPassword");
        String token = httpRequest.getHeader("Authorization");
        
        // 验证JWT Token是否存在
        if (token == null || token.trim().isEmpty()) {
            return Result.error("未授权访问");
        }
        
        try {
            // 获取用户ID
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
            
            // 直接修改密码，不验证旧密码 - 存在CSRF漏洞
            boolean success = loginService.changePassword(userId, newPassword);
            
            if (success) {
                log.info("用户ID: {} 密码修改成功（CSRF漏洞演示接口）", userId);
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }
        } catch (Exception e) {
            log.error("JWT解析失败", e);
            return Result.error("未授权访问");
        }
    }

    /**
     * 修改密码接口 - CSRF防护（演示用）
     * 验证旧密码，防止CSRF攻击
     */
    @PostMapping("/changePasswordSecure")
    public Result changePasswordSecure(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        String oldPassword = request.get("oldPassword");
        String newPassword = request.get("newPassword");
        String token = httpRequest.getHeader("Authorization");
        
        // 验证JWT Token是否存在
        if (token == null || token.trim().isEmpty()) {
            return Result.error("未授权访问");
        }
        
        try {
            // 获取用户ID
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
            
            // 验证旧密码
            if (oldPassword == null || oldPassword.trim().isEmpty()) {
                return Result.error("旧密码不能为空");
            }
            
            if (!loginService.verifyOldPassword(userId, oldPassword)) {
                log.warn("用户ID: {} 尝试修改密码，但旧密码验证失败（CSRF防护演示）", userId);
                return Result.error("旧密码错误");
            }
            
            // 修改密码
            boolean success = loginService.changePasswordSecure(userId, oldPassword, newPassword);
            
            if (success) {
                log.info("用户ID: {} 密码修改成功（CSRF防护演示接口）", userId);
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }
        } catch (Exception e) {
            log.error("JWT解析失败", e);
            return Result.error("未授权访问");
        }
    }

    /**
     * 生成CSRF Token接口
     * 用于演示CSRF Token机制
     */
    @GetMapping("/generateToken")
    public Result generateCsrfToken(HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession();
        
        // 生成唯一的CSRF Token
        String csrfToken = UUID.randomUUID().toString();
        
        // 将Token存储在Session中
        session.setAttribute("CSRF_TOKEN", csrfToken);
        
        log.info("生成CSRF Token: {}", csrfToken);
        
        Map<String, String> data = new HashMap<>();
        data.put("csrfToken", csrfToken);
        
        return Result.success(data);
    }

    /**
     * 修改密码接口 - CSRF Token防护（演示用）
     * 使用CSRF Token机制防止CSRF攻击
     */
    @PostMapping("/changePasswordWithToken")
    public Result changePasswordWithToken(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        String newPassword = request.get("newPassword");
        String csrfToken = request.get("csrfToken");
        String token = httpRequest.getHeader("Authorization");
        
        // 验证JWT Token是否存在
        if (token == null || token.trim().isEmpty()) {
            return Result.error("未授权访问");
        }
        
        try {
            // 验证CSRF Token
            HttpSession session = httpRequest.getSession();
            String sessionToken = (String) session.getAttribute("CSRF_TOKEN");
            
            if (sessionToken == null || !sessionToken.equals(csrfToken)) {
                log.warn("CSRF Token验证失败！Session Token: {}, Request Token: {}", sessionToken, csrfToken);
                return Result.error("CSRF Token验证失败");
            }
            
            // 获取用户ID
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
            
            // 修改密码
            boolean success = loginService.changePassword(userId, newPassword);
            
            if (success) {
                log.info("用户ID: {} 密码修改成功（CSRF Token防护演示接口）", userId);
                
                // 使用后销毁Token（一次性Token）
                session.removeAttribute("CSRF_TOKEN");
                
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }
        } catch (Exception e) {
            log.error("JWT解析失败", e);
            return Result.error("未授权访问");
        }
    }
}

