package icu.secnotes.controller.Other;

import icu.secnotes.pojo.LdapLoginRequest;
import icu.secnotes.pojo.Result;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.web.bind.annotation.*;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * LDAP 注入漏洞演示 Controller
 * 
 * 场景：登录认证绕过
 */
@Slf4j
@RestController
@RequestMapping("/api/ldap")
@Tag(name = "LDAP注入漏洞", description = "LDAP注入漏洞演示")
public class LdapInjectionController {
    
    @Autowired
    private LdapTemplate ldapTemplate;
    
    // ============================================
    // 场景1：登录认证绕过
    // ============================================
    
    /**
     * 存在 LDAP 注入漏洞的登录接口（不安全）
     * 
     * 攻击示例1（绕过认证）：
     *   username: admin)(uid=*))(&(uid=*
     *   password: anything
     *   
     * 攻击示例2（通配符）：
     *   username: *
     *   password: *
     *   
     * @param request 登录请求参数
     * @return 登录结果
     */
    @PostMapping("/vuln/login")
    public Result vulnerableLogin(@RequestBody LdapLoginRequest request) {
        try {
            String username = request.getUsername();
            String password = request.getPassword();
            
            // 直接拼接用户输入到 LDAP 过滤器（危险！）
            String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";

            log.warn("LDAP 过滤器: {}", filter);
            // 执行 LDAP 查询
            List<Map<String, String>> users = ldapTemplate.search(
                "ou=users", 
                filter, 
                (AttributesMapper<Map<String, String>>) attrs -> {
                    Map<String, String> user = new HashMap<>();
                    user.put("uid", getAttributeValue(attrs, "uid"));
                    user.put("cn", getAttributeValue(attrs, "cn"));
                    user.put("mail", getAttributeValue(attrs, "mail"));
                    return user;
                }
            );
            
            if (!users.isEmpty()) {
                // 构造返回结果
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("message", "登录成功！");
                responseData.put("user", users.get(0));
                responseData.put("filter", filter);
                responseData.put("matchedCount", users.size());
                
                return Result.success(responseData);
            } else {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", false);
                responseData.put("message", "用户名或密码错误");
                responseData.put("filter", filter);
                
                return Result.error(responseData);
            }
        } catch (Exception e) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("success", false);
            errorData.put("message", "LDAP 查询错误: " + e.getMessage());
            errorData.put("error", e.getClass().getSimpleName());
            
            return Result.error(errorData);
        }
    }
    
    /**
     * 安全的登录接口（使用参数化查询）
     * 
     * @param request 登录请求参数
     * @return 登录结果
     */
    @PostMapping("/safe/login")
    public Result safeLogin(@RequestBody LdapLoginRequest request) {
        try {
            String username = request.getUsername();
            String password = request.getPassword();
            
            // 使用 Spring LDAP 的参数化查询（安全）
            AndFilter filter = new AndFilter();
            filter.and(new EqualsFilter("uid", username));
            filter.and(new EqualsFilter("userPassword", password));
            
            // 执行 LDAP 查询
            List<Map<String, String>> users = ldapTemplate.search(
                "ou=users", 
                filter.encode(),  // 自动转义特殊字符
                (AttributesMapper<Map<String, String>>) attrs -> {
                    Map<String, String> user = new HashMap<>();
                    user.put("uid", getAttributeValue(attrs, "uid"));
                    user.put("cn", getAttributeValue(attrs, "cn"));
                    user.put("mail", getAttributeValue(attrs, "mail"));
                    return user;
                }
            );
            
            if (!users.isEmpty()) {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("message", "登录成功！");
                responseData.put("user", users.get(0));
                
                return Result.success(responseData);
            } else {
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", false);
                responseData.put("message", "用户名或密码错误");
                
                return Result.error(responseData);
            }
        } catch (Exception e) {
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("success", false);
            errorData.put("message", "LDAP 查询错误: " + e.getMessage());
            
            return Result.error(errorData);
        }
    }
    
    // ============================================
    // 工具方法
    // ============================================
    
    /**
     * 获取 LDAP 属性值
     */
    private String getAttributeValue(Attributes attrs, String name) {
        try {
            Attribute attr = attrs.get(name);
            return attr != null ? attr.get().toString() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
