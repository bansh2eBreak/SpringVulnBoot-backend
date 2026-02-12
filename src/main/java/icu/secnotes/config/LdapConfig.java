package icu.secnotes.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

/**
 * LDAP 配置类
 * 用于配置 LDAP 连接和 LdapTemplate
 */
@Configuration
public class LdapConfig {
    
    @Value("${ldap.urls}")
    private String ldapUrls;
    
    @Value("${ldap.base}")
    private String ldapBase;
    
    @Value("${ldap.username}")
    private String ldapUsername;
    
    @Value("${ldap.password}")
    private String ldapPassword;
    
    /**
     * 配置 LDAP 上下文源
     */
    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrls);
        contextSource.setBase(ldapBase);
        contextSource.setUserDn(ldapUsername);
        contextSource.setPassword(ldapPassword);
        return contextSource;
    }
    
    /**
     * 配置 LDAP 模板
     */
    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }
}
