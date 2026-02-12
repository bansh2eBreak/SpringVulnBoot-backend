package icu.secnotes.pojo;

import lombok.Data;

/**
 * LDAP 登录请求参数
 */
@Data
public class LdapLoginRequest {
    /**
     * 用户名
     */
    private String username;
    
    /**
     * 密码
     */
    private String password;
}
