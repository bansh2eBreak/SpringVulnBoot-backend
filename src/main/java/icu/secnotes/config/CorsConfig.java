package icu.secnotes.config;

import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Properties;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // ============================================================
        // CORS 漏洞演示 - 路径级 CORS 配置
        // ============================================================

        // 漏洞1：Origin 完全信任 —— addAllowedOriginPattern("*") + allowCredentials(true)
        // 浏览器会携带用户凭证向任意 Origin 反射 Access-Control-Allow-Origin，攻击者可读取响应
        CorsConfiguration vuln1Config = new CorsConfiguration();
        vuln1Config.setAllowCredentials(true);
        vuln1Config.addAllowedOriginPattern("*");
        vuln1Config.addAllowedMethod("*");
        vuln1Config.addAllowedHeader("*");
        source.registerCorsConfiguration("/cors/vuln1/**", vuln1Config);

        // 漏洞2：Origin 校验可绕过 —— 使用 contains("127.0.0.1") 做字符串匹配
        // 开发者本意：只允许本机（127.0.0.1）访问
        // 缺陷：端口 80 和端口 81 是不同 Origin，但都包含 "127.0.0.1"，攻击者页面（:81）照样绕过
        // addAllowedOriginPattern("*127.0.0.1*") 等价于代码中 origin.contains("127.0.0.1") 的模糊匹配
        CorsConfiguration vuln2Config = new CorsConfiguration();
        vuln2Config.setAllowCredentials(true);
        vuln2Config.addAllowedOriginPattern("*127.0.0.1*");
        vuln2Config.addAllowedMethod("*");
        vuln2Config.addAllowedHeader("*");
        source.registerCorsConfiguration("/cors/vuln2/**", vuln2Config);

        // 安全版：严格白名单 —— 仅允许指定 Origin，其他来源一律拒绝
        // 靶场前端（127.0.0.1:80）不在白名单内，访问该接口浏览器会报 CORS 错误，演示防御效果
        CorsConfiguration secureConfig = new CorsConfiguration();
        secureConfig.setAllowCredentials(true);
        secureConfig.addAllowedOrigin("http://trusted.secnotes.icu");
        secureConfig.addAllowedMethod("*");
        secureConfig.addAllowedHeader("*");
        source.registerCorsConfiguration("/cors/secure/**", secureConfig);

        // ============================================================
        // 全局配置 —— 靶场部署便利性，允许任意来源（非 /cors/** 路径使用）
        // ============================================================
        CorsConfiguration globalConfig = new CorsConfiguration();
        globalConfig.setAllowCredentials(true);
        // 注意：allowCredentials(true) 时不能用 addAllowedOrigin("*")，必须用 addAllowedOriginPattern("*")
        globalConfig.addAllowedOriginPattern("*");
        globalConfig.addAllowedMethod("*");
        globalConfig.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", globalConfig);

        return new CorsFilter(source);
    }

    @Bean
    public DefaultKaptcha defaultKaptcha() {
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        Properties properties = new Properties();
        properties.setProperty("kaptcha.border", "yes"); // 图片边框
        properties.setProperty("kaptcha.border.color", "105,179,90"); // 边框颜色
        properties.setProperty("kaptcha.textproducer.font.color", "blue"); // 字体颜色
        properties.setProperty("kaptcha.image.width", "110"); // 图片宽度
        properties.setProperty("kaptcha.image.height", "40"); // 图片高度
        properties.setProperty("kaptcha.textproducer.font.size", "30"); // 字体大小
        properties.setProperty("kaptcha.session.key", "code"); // Session Key
        properties.setProperty("kaptcha.textproducer.char.length", "4"); // 验证码长度
        properties.setProperty("kaptcha.textproducer.font.names", "Arial,Courier"); // 字体
        Config config = new Config(properties);
        defaultKaptcha.setConfig(config);
        return defaultKaptcha;
    }

}
