// package icu.secnotes.config;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.provisioning.InMemoryUserDetailsManager;
// import org.springframework.security.web.SecurityFilterChain;

// // 禁用SecurityConfig，当需要启用，请取消注释，这样就可以开启Actuator授权
// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

//     @Bean
//     public PasswordEncoder passwordEncoder() {
//         System.out.println("passwordEncoder111");
//         return new BCryptPasswordEncoder();
//     }

//     @Bean
//     public UserDetailsService userDetailsService() {
//         // 创建管理员用户，用于访问Actuator端点
//         UserDetails admin = User.builder()
//                 .username("admin")
//                 .password(passwordEncoder().encode("admin123"))
//                 .roles("ADMIN")
//                 .build();

//         return new InMemoryUserDetailsManager(admin);
//     }

//     @Bean
//     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//         http
//             .csrf(csrf -> csrf.disable()) // 禁用CSRF，因为这是API服务
//             .authorizeRequests(authz -> authz
//                 // 允许所有非Actuator端点的请求
//                 .antMatchers("/actuator/**").hasRole("ADMIN")
//                 .anyRequest().permitAll()
//             )
//             .httpBasic(httpBasic -> httpBasic
//                 .realmName("Spring Boot Actuator")
//             );

//         return http.build();
//     }
// } 