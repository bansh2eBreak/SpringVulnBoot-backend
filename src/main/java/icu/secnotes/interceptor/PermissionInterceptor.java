package icu.secnotes.interceptor;

import icu.secnotes.config.PermissionConfig;
import icu.secnotes.pojo.Admin;
import icu.secnotes.service.LoginService;
import icu.secnotes.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.HandlerInterceptor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

/**
 * 权限拦截器
 * 统一验证所有请求的权限
 * 根据用户角色和请求路径自动判断是否有权限访问
 */
@Slf4j
@Component
public class PermissionInterceptor implements HandlerInterceptor {

    @Autowired
    private LoginService loginService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestPath = request.getRequestURI();
        log.debug("权限验证 - 请求路径: {}", requestPath);

        // 1. 公共路径直接放行
        if (PermissionConfig.isPublicPath(requestPath)) {
            log.debug("公共路径，直接放行: {}", requestPath);
            return true;
        }

        // 2. 获取用户 token
        String token = request.getHeader("Authorization");
        if (token == null || token.trim().isEmpty()) {
            log.warn("未授权访问: {} - 缺少 token", requestPath);
            sendErrorResponse(response, 401, "未授权访问，请先登录");
            return false;
        }

        // 3. 解析 token 获取用户信息
        try {
            String userId = JwtUtils.parseJwt(token).get("id").toString();
            Admin admin = loginService.getAdminById(userId);
            
            if (admin == null) {
                log.warn("无效的 token: {}", token);
                sendErrorResponse(response, 401, "无效的 token");
                return false;
            }

            String userRole = admin.getRole() != null ? admin.getRole() : "guest";
            log.debug("用户: {}, 角色: {}", admin.getUsername(), userRole);

            // 4. 检查是否为基础接口（只需登录即可，无需特定角色）
            if (PermissionConfig.isCommonAuthPath(requestPath)) {
                log.debug("基础接口，已登录用户可访问: {}", requestPath);
                return true;
            }

            // 5. 验证权限
            if (!hasPermission(requestPath, userRole)) {
                log.warn("权限不足: 用户 {} (角色: {}) 尝试访问 {}", 
                         admin.getUsername(), userRole, requestPath);
                sendErrorResponse(response, 403, "权限不足，无法访问此资源");
                return false;
            }

            log.debug("权限验证通过: 用户 {} 访问 {}", admin.getUsername(), requestPath);
            return true;

        } catch (Exception e) {
            log.error("权限验证失败: {}", e.getMessage());
            sendErrorResponse(response, 401, "Token 验证失败");
            return false;
        }
    }

    /**
     * 检查用户是否有权限访问指定路径
     */
    private boolean hasPermission(String requestPath, String userRole) {
        Map<String, Set<String>> pathRoleMapping = PermissionConfig.getPathRoleMapping();
        
        // admin 拥有所有权限
        if ("admin".equals(userRole)) {
            return true;
        }

        // 遍历所有权限规则，查找匹配的路径
        for (Map.Entry<String, Set<String>> entry : pathRoleMapping.entrySet()) {
            String pathPattern = entry.getKey();
            Set<String> allowedRoles = entry.getValue();
            
            // 使用 PermissionConfig 中的 pathMatcher（避免重复创建实例）
            if (PermissionConfig.matchPath(pathPattern, requestPath)) {
                log.debug("路径匹配: {} -> 需要角色: {}", pathPattern, allowedRoles);
                return allowedRoles.contains(userRole);
            }
        }

        // 如果没有匹配到任何规则，默认拒绝访问（安全起见）
        log.warn("未找到匹配的权限规则: {}", requestPath);
        return false;
    }

    /**
     * 发送 JSON 错误响应
     */
    private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        String json = String.format("{\"code\":%d,\"msg\":\"%s\"}", status, message);
        response.getWriter().write(json);
    }
}
