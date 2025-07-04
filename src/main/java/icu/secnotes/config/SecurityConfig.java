package icu.secnotes.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

// 禁用SecurityConfig，当需要启用，请取消注释，这样就可以开启Actuator授权
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        // 创建管理员用户，用于访问Actuator端点
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // 禁用CSRF，因为这是API服务
            .authorizeRequests(authz -> authz
                .antMatchers("/actuator/env").hasRole("ADMIN") // 只有env端点需要认证
                .antMatchers("/swagger-ui.html", "/swagger-ui/**",
                "/v3/api-docs", "/v3/api-docs/**").hasRole("ADMIN") // 需认证访问Swagger UI
                .anyRequest().permitAll() // 允许所有其他请求（包括其他Actuator端点）
            )
            .httpBasic(httpBasic -> httpBasic
                .realmName("Spring Security")
            );

        return http.build();
    }

} 