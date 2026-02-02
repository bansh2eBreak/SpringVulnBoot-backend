package icu.secnotes.config;

import icu.secnotes.interceptor.LoginCheckInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Autowired
    private LoginCheckInterceptor loginCheckInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(loginCheckInterceptor).addPathPatterns("/**").excludePathPatterns("/login").excludePathPatterns("/openUrl/**")
                .excludePathPatterns("/authentication/passwordBased/captcha")
                .excludePathPatterns("/accessControl/UnauthorizedPri/vuln1/**")
                .excludePathPatterns("/swagger-ui/**")
                .excludePathPatterns("/swagger-ui.html")
                .excludePathPatterns("/v3/api-docs/**")
                // SSRF via XXE：解析器请求 DTD 时不带 Authorization，需放行否则返回“未登录”导致 DTD 解析报错
                .excludePathPatterns("/xml/xxe-ssrf/dtd");
    }

}
