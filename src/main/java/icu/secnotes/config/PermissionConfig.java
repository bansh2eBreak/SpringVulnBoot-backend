package icu.secnotes.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.util.AntPathMatcher;
import java.util.*;

/**
 * 权限配置类
 * 集中管理前后端权限映射关系
 * 当前端路由权限变化时，只需修改此配置即可
 */
@Configuration
public class PermissionConfig {

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * 公共路径（无需登录即可访问）
     * 包含特殊的业务场景路径
     * 支持 Ant 风格路径模式（/** 表示任意子路径）
     */
    public static final List<String> PUBLIC_PATHS = Arrays.asList(
        "/login",                                       // 登录接口
        "/register",                                    // 用户注册接口（允许公开访问）
        "/error",                                       // 错误页面
        "/favicon.ico",                                 // 网站图标
        "/openUrl/**",                                  // 任意URL跳转漏洞演示
        "/authentication/passwordBased/captcha",        // 验证码接口
        "/accessControl/UnauthorizedPri/vuln1/**",      // 未授权访问漏洞演示
        "/swagger-ui/**",                               // Swagger文档
        "/swagger-ui.html",
        "/v3/api-docs/**",                              // Swagger API文档
        "/xml/xxe-ssrf/dtd",                            // XXE SSRF 漏洞演示（DTD解析）
        "/fileInclusion/**"                             // 文件包含漏洞演示（需要无认证访问）
    );

    /**
     * 基础接口路径（所有已登录用户都可以访问，无需特定角色）
     * 这些接口需要有效 token，但不限制角色
     */
    public static final List<String> COMMON_AUTH_PATHS = Arrays.asList(
        "/getAdminInfo",                                // 获取用户信息接口（需要 token）
        "/changePassword"                               // 修改密码接口（所有用户都可以修改自己的密码）
    );

    /**
     * guest 角色可访问的路径
     * 对应前端 constantRoutes 中的页面
     */
    public static final List<String> GUEST_PATHS = Arrays.asList(
        "/sqli/**",           // SQL注入
        "/xss/**",            // XSS跨站脚本
        "/rce/**",            // 任意命令执行（后端接口路径为 /rce）
        "/massAssignment/**"  // Mass Assignment 批量赋值漏洞
    );

    /**
     * admin 角色专属路径
     * 对应前端 asyncRoutes 中的页面
     */
    public static final List<String> ADMIN_ONLY_PATHS = Arrays.asList(
        "/csrf/**",           // CSRF漏洞
        "/ssrf/**",           // SSRF漏洞
        "/accessControl/**",  // 权限漏洞
        "/authentication/**", // 身份认证漏洞（除了验证码接口）
        "/jwt/**",            // JWT安全漏洞
        "/pathtraversal/**",  // 路径穿越漏洞
        "/fileUpload/**",     // 文件上传漏洞（注意大小写：后端是 /fileUpload）
        "/deserialize/**",    // 反序列化漏洞
        "/xml/**",            // XML安全漏洞
        "/components/**",     // 组件漏洞
        "/ipspoofing/**",     // IP伪造漏洞
        "/redos/**",          // ReDoS 正则拒绝服务
        "/spel/**"            // SpEL 表达式注入
    );

    /**
     * 路径角色映射缓存（避免每次请求都重新构建）
     */
    private static final Map<String, Set<String>> PATH_ROLE_MAPPING;
    
    static {
        Map<String, Set<String>> mapping = new HashMap<>();
        
        // guest 可访问的路径（guest 和 admin 都可以访问）
        for (String path : GUEST_PATHS) {
            mapping.put(path, new HashSet<>(Arrays.asList("guest", "admin")));
        }
        
        // admin 专属路径（只有 admin 可以访问）
        for (String path : ADMIN_ONLY_PATHS) {
            mapping.put(path, new HashSet<>(Collections.singletonList("admin")));
        }
        
        PATH_ROLE_MAPPING = Collections.unmodifiableMap(mapping);
    }

    /**
     * 获取所有需要权限验证的路径模式（使用缓存）
     */
    public static Map<String, Set<String>> getPathRoleMapping() {
        return PATH_ROLE_MAPPING;
    }

    /**
     * 检查路径是否为公共路径（无需权限）
     * 使用 Ant 路径匹配器，支持 /** 通配符
     */
    public static boolean isPublicPath(String requestPath) {
        for (String pattern : PUBLIC_PATHS) {
            if (pathMatcher.match(pattern, requestPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查路径是否为基础接口（只需登录即可，无需特定角色）
     */
    public static boolean isCommonAuthPath(String requestPath) {
        for (String pattern : COMMON_AUTH_PATHS) {
            if (pathMatcher.match(pattern, requestPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 公共路径匹配方法（供其他类使用，避免重复创建 AntPathMatcher 实例）
     */
    public static boolean matchPath(String pattern, String path) {
        return pathMatcher.match(pattern, path);
    }
}
