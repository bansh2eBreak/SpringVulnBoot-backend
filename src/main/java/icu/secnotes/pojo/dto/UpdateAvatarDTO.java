package icu.secnotes.pojo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 安全版本：用户头像更新 DTO
 * 
 * 防御 Mass Assignment 漏洞的核心思想：
 * 1. 不直接使用实体类（如 Admin）接收前端参数
 * 2. 创建专门的 DTO 类，只包含允许用户修改的字段
 * 3. 使用"字段白名单"策略，敏感字段不在 DTO 中
 * 
 * 这是 OWASP 推荐的防御方法
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateAvatarDTO {
    /**
     * 用户头像 URL（只允许修改这个字段）
     */
    private String avatar;
    
    // ⚠️ 注意：role 字段不在 DTO 中
    // 即使攻击者在请求中添加 role 参数，也不会被绑定到这个对象
    // 这就是 DTO 的作用：字段白名单
}
