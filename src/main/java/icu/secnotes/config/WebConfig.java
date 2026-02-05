package icu.secnotes.config;

import icu.secnotes.interceptor.PermissionInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web配置类
 * 注册权限拦截器，统一管理前后端权限验证
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Autowired
    private PermissionInterceptor permissionInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 注册权限拦截器，拦截所有请求
        // 公共路径和权限路径的配置都在 PermissionConfig 中集中管理
        registry.addInterceptor(permissionInterceptor)
                .addPathPatterns("/**");
        
        // 注意：不再需要手动配置 excludePathPatterns
        // 所有公共路径都在 PermissionConfig.PUBLIC_PATHS 中配置
        // 所有权限路径都在 PermissionConfig.GUEST_PATHS 和 ADMIN_ONLY_PATHS 中配置
    }
}
