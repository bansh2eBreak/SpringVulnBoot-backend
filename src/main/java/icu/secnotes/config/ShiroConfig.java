package icu.secnotes.config;

import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shiro配置类
 * 配置Shiro 1.2.4框架，实现真实的Shiro-550漏洞
 */
@Configuration
public class ShiroConfig {

    /**
     * 创建ShiroFilterFactoryBean
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        
        // 设置安全管理器
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        
        // 设置登录页面 - 使用Shiro专用的登录页面
        shiroFilterFactoryBean.setLoginUrl("/components/shiro/login");
        // 设置登录成功页面 - 重定向到前端页面
        shiroFilterFactoryBean.setSuccessUrl("/");
        // 设置未授权页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/components/shiro/unauthorized");
        
        // 配置过滤器链 - 只控制Shiro相关路径，不影响原有靶场接口
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        
        // 允许匿名访问的接口
        filterChainDefinitionMap.put("/components/shiro/login", "anon"); // 登录接口（Shiro-550漏洞测试目标）
        filterChainDefinitionMap.put("/components/shiro/unauthorized", "anon"); // 未授权页面
        filterChainDefinitionMap.put("/components/shiro/generate/**", "anon"); // payload生成接口
        
        // 需要登录认证的接口
        filterChainDefinitionMap.put("/components/shiro/logout", "authc"); // 登出接口（需要登录）
        filterChainDefinitionMap.put("/components/shiro/test/permission/**", "authc"); // 权限测试接口（需要登录）
        filterChainDefinitionMap.put("/components/shiro/test/role/**", "authc"); // 角色测试接口（需要登录）
        
        // 其他所有路径不经过Shiro过滤器，保持原有的Interceptor控制
        // filterChainDefinitionMap.put("/**", "anon");
        
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    /**
     * 创建安全管理器
     */
    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(customShiroRealm());
        
        // 设置RememberMe管理器 - 启用Shiro-550漏洞测试
        securityManager.setRememberMeManager(rememberMeManager());
        
        return securityManager;
    }

    /**
     * 创建自定义Realm
     */
    @Bean
    public CustomShiroRealm customShiroRealm() {
        return new CustomShiroRealm();
    }

    /**
     * 创建RememberMe管理器
     * 注意：这里使用的是Shiro 1.2.4版本的硬编码密钥，用于漏洞测试
     */
    @Bean
    public CookieRememberMeManager rememberMeManager() {
        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
        
        // 设置RememberMe Cookie
        SimpleCookie rememberMeCookie = new SimpleCookie("rememberMe");
        rememberMeCookie.setHttpOnly(false); // 允许JavaScript访问，便于测试
        rememberMeCookie.setMaxAge(2592000); // 30天
        rememberMeCookie.setPath("/");
        rememberMeManager.setCookie(rememberMeCookie);
        
        // 注意：这里使用的是Shiro 1.2.4版本的硬编码密钥
        // 在生产环境中应该使用自定义密钥
        byte[] key = org.apache.shiro.codec.Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
        // 使用固定的自定义密钥（仅用于测试）
        // byte[] key = org.apache.shiro.codec.Base64.decode("MyCustomSecureKeyForShiro550Fix==");
        rememberMeManager.setCipherKey(key);
        
        return rememberMeManager;
    }
} 