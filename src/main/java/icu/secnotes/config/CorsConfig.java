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

    /**
     * 这是因为浏览器的安全机制对跨域请求的 Cookie 处理有严格的限制。当你的前端应用（http://10.225.13.70:9528）向后端服务（http://10.225.13.70:8080）发起跨域请求，并且需要携带 Cookie（例如 JSESSIONID 用于 Session 验证）时，浏览器会执行以下安全检查：
     *
     * 检查 Access-Control-Allow-Origin： 浏览器会检查后端响应头中的 Access-Control-Allow-Origin 字段。如果这个字段的值是通配符 *，或者与发起请求的源（http://10.225.13.70:9528）不匹配，浏览器就会阻止请求，以防止跨站请求伪造（CSRF）攻击。
     *
     * 检查 Access-Control-Allow-Credentials： 如果 Access-Control-Allow-Origin 匹配，浏览器还会检查 Access-Control-Allow-Credentials 字段。如果这个字段的值不是 true，或者缺失，浏览器也会阻止请求，因为这表示服务器没有明确允许客户端携带凭据（包括 Cookie）。
     *
     * 为什么不能使用 *？
     *
     * 使用通配符 * 作为 Access-Control-Allow-Origin 的值，虽然在某些情况下可以简化配置，但是在需要携带凭据的跨域请求中，这是绝对禁止的。因为如果允许任何来源的网站都携带用户的 Cookie 发起跨域请求，那么恶意网站就可以轻易地伪造请求，窃取用户的敏感信息。
     *
     * 精确指定来源地址的重要性
     *
     * 通过将 Access-Control-Allow-Origin 设置为精确的来源地址（http://10.225.13.70:9528），你就明确告诉浏览器，只有来自这个特定来源的请求才被允许携带 Cookie。这样可以有效地防止其他网站利用你的用户的 Cookie 发起跨域请求，提高了安全性。
     *
     * 总结
     *
     * 为了确保跨域请求的安全性，并允许浏览器携带 Cookie，你必须：
     *
     * 将 Access-Control-Allow-Origin 设置为精确的来源地址，而不是通配符 *。
     * 将 Access-Control-Allow-Credentials 设置为 true。
     * 这两个设置是缺一不可的，只有同时满足这两个条件，浏览器才会允许跨域请求携带 Cookie。
     */

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);    //这是最关键的改动，必须设置 allowCredentials 为 true，才能允许跨域请求携带 Cookie。
        corsConfiguration.addAllowedOrigin("http://127.0.0.1:9528");
        corsConfiguration.addAllowedOrigin("http://127.0.0.1");
        corsConfiguration.addAllowedOrigin("http://localhost:9528");
        corsConfiguration.addAllowedOrigin("http://localhost");
        corsConfiguration.addAllowedMethod("*"); // 允许所有请求方法
        corsConfiguration.addAllowedHeader("*"); // 允许所有请求头部

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
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
