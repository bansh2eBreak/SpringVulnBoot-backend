package icu.secnotes.pojo;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * GraphQL 用户实体
 * 用于演示 GraphQL 安全漏洞
 * 
 * 包含敏感字段用于演示：
 * 1. 字段建议泄露（Introspection 暴露敏感字段名）
 * 2. 越权查询（普通用户查询管理员字段）
 */
@Data
@NoArgsConstructor
public class GraphQLUser {
    
    /**
     * 用户ID
     */
    private Long id;
    
    /**
     * 用户名
     */
    private String username;
    
    /**
     * 邮箱
     */
    private String email;
    
    /**
     * 角色（guest/admin）
     */
    private String role;
    
    /**
     * 敏感字段：薪资
     * 用于演示字段建议泄露漏洞
     */
    private Double salary;
    
    /**
     * 敏感字段：社保号
     * 用于演示字段建议泄露漏洞
     */
    private String ssn;
    
    /**
     * 敏感字段：内部备注
     * 用于演示字段建议泄露漏洞
     */
    private String internalNotes;
}
