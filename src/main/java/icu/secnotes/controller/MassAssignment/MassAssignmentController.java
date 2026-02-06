package icu.secnotes.controller.MassAssignment;

import icu.secnotes.pojo.Admin;
import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.dto.UpdateAvatarDTO;
import icu.secnotes.service.LoginService;
import icu.secnotes.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Mass Assignment（批量赋值）漏洞演示
 * 场景：用户修改头像功能
 * 
 * ⚠️ 漏洞成因（通用方法被滥用）：
 * 
 * 1. 最初设计：
 *    - Mapper 层的 updateAdmin() 方法是为"管理员后台修改用户信息"设计的通用方法
 *    - 使用动态 SQL，可以灵活更新用户的任意字段（name、avatar、role 等）
 *    - 这在管理员后台是合理的，因为管理员有权限修改任何信息
 * 
 * 2. 错误复用：
 *    - 开发者为了方便，将 updateAdmin() 通用方法复用到了"用户修改头像"功能
 *    - Controller 直接使用 Admin 实体类接收前端参数，没有做字段过滤
 *    - 结果：普通用户也能通过注入 role 参数来提权
 * 
 * 3. 根本问题：
 *    - 不同权限场景混用了同一个通用方法
 *    - 直接使用实体类接收参数，没有字段白名单控制
 * 
 * 教训：代码复用要注意安全边界，不同权限场景应该使用不同的方法或 DTO
 */
@Slf4j
@RestController
@RequestMapping("/massAssignment")
@CrossOrigin
public class MassAssignmentController {

    @Autowired
    private LoginService loginService;

    /**
     * 【漏洞版本】修改用户头像 - 存在 Mass Assignment 漏洞
     * 
     * 业务场景：
     * 用户自助修改头像（常见功能）
     * 
     * 漏洞成因：
     * 1. Mapper 层的 updateAdmin() 方法本来是为"管理员后台"设计的通用更新方法
     * 2. 开发者为了方便，将这个通用方法复用到了"用户修改头像"功能
     * 3. Controller 直接使用 Admin 实体类接收参数，没有字段白名单限制
     * 4. 结果：普通用户可以注入 role 参数来修改自己的角色
     * 
     * 根本问题：通用方法被滥用到了不同权限场景
     * 
     * @Poc: 
     * POST /massAssignment/updateProfileVuln
     * Body: {"avatar": "http://new-avatar.png", "role": "admin"}
     * 
     * 攻击效果：guest 用户可以通过注入 role=admin 参数提权为管理员
     */
    @PostMapping("/updateProfileVuln")
    public Result updateProfileVuln(@RequestBody Admin admin, HttpServletRequest request) {
        try {
            // 从 token 中获取用户 ID（确保只能修改自己的信息）
            String token = request.getHeader("Authorization");
            String userId = JwtUtils.parseJwt(token).get("id").toString();
            
            // ⚠️ 漏洞点：直接使用 Admin 对象接收前端参数
            // 攻击者可以在请求中添加 role 参数，修改自己的角色
            admin.setId(Integer.parseInt(userId)); // 强制设置为当前登录用户 ID
            
            boolean success = loginService.updateAdmin(admin);
            
            if (success) {
                log.warn("【漏洞】用户 {} 通过 Mass Assignment 修改了头像，可能包含 role 字段！", userId);
                
                // 查询更新后的用户信息，返回给前端
                Admin updatedUser = loginService.getAdminById(userId);
                
                // 构造返回数据（包含 role 字段，让攻击者看到）
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("id", updatedUser.getId());
                responseData.put("username", updatedUser.getUsername());
                responseData.put("name", updatedUser.getName());
                responseData.put("avatar", updatedUser.getAvatar());
                responseData.put("role", updatedUser.getRole());  // ⚠️ 关键：返回 role 字段
                
                return Result.success(responseData);
            } else {
                return Result.error("修改失败");
            }
        } catch (Exception e) {
            log.error("修改失败：{}", e.getMessage());
            return Result.error("修改失败：" + e.getMessage());
        }
    }

    /**
     * 【安全版本】修改用户头像 - 使用 DTO 防止 Mass Assignment 漏洞
     * 
     * 安全措施：
     * 1. 创建专门的 DTO 类（UpdateAvatarDTO），只包含 avatar 字段
     * 2. 使用 DTO 接收前端参数，而不是直接使用实体类
     * 3. 手动构造 Admin 对象，只更新白名单字段（avatar）
     * 4. 敏感字段（如 role）从数据库查询原值，不接收前端传入
     * 
     * 这是 OWASP 推荐的防御方法
     */
    @PostMapping("/updateProfileSec")
    public Result updateProfileSec(@RequestBody UpdateAvatarDTO dto, HttpServletRequest request) {
        try {
            // 从 token 中获取用户 ID
            String token = request.getHeader("Authorization");
            String userId = JwtUtils.parseJwt(token).get("id").toString();
            
            // ✅ 安全点：只设置需要修改的字段（avatar）
            // 由于 Mapper 使用动态 SQL，只有非空字段才会被更新
            // name、role 等字段为 null，不会被更新，保持数据库原值
            Admin admin = new Admin();
            admin.setId(Integer.parseInt(userId));
            admin.setAvatar(dto.getAvatar());  // 只接收 DTO 中的 avatar 字段
            
            boolean success = loginService.updateAdmin(admin);
            
            if (success) {
                log.info("【安全】用户 {} 成功修改头像，role 字段未被修改", userId);
                
                // 查询更新后的用户信息，返回给前端
                Admin updatedUser = loginService.getAdminById(userId);
                
                // 构造返回数据
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("id", updatedUser.getId());
                responseData.put("username", updatedUser.getUsername());
                responseData.put("name", updatedUser.getName());
                responseData.put("avatar", updatedUser.getAvatar());
                responseData.put("role", updatedUser.getRole());
                
                return Result.success(responseData);
            } else {
                return Result.error("修改失败");
            }
        } catch (Exception e) {
            log.error("修改失败：{}", e.getMessage());
            return Result.error("修改失败：" + e.getMessage());
        }
    }

    /**
     * 获取当前登录用户信息（用于前端显示）
     */
    @GetMapping("/getCurrentUser")
    public Result getCurrentUser(HttpServletRequest request) {
        try {
            String token = request.getHeader("Authorization");
            String userId = JwtUtils.parseJwt(token).get("id").toString();
            
            Admin admin = loginService.getAdminById(userId);
            if (admin != null) {
                // 不返回密码和 token
                admin.setPassword(null);
                admin.setToken(null);
                return Result.success(admin);
            } else {
                return Result.error("用户不存在");
            }
        } catch (Exception e) {
            log.error("获取用户信息失败：{}", e.getMessage());
            return Result.error("获取用户信息失败");
        }
    }
}
