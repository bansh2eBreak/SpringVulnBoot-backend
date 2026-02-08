package icu.secnotes.controller;

import icu.secnotes.pojo.Admin;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.LoginService;
import icu.secnotes.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
public class LoginController {

    @Autowired
    private LoginService loginService;

    /**
     * 管理员登录接口
     * @param admin
     * @return
     */
    @PostMapping("/login")
    public Result login(@RequestBody Admin admin) {
        Admin login = loginService.login(admin);
        if (login != null) {
            //表示账号密码校验成功，登录成功
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", login.getId());
            claims.put("username", login.getUsername());
            claims.put("name", login.getName());

            String jwttoken = JwtUtils.generateJwt(claims);

            log.info("管理员:{} 登录成功，分配的jwttoken是:{}", login.getUsername(), jwttoken);
//            return Result.success(login);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("登录失败，登录账号:{}， 密码: {}", admin.getUsername(), admin.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * 获取登录管理员账号的信息
     */
    @GetMapping("/getAdminInfo")
    public Result getAdminInfo(HttpServletRequest request, HttpServletResponse response) {

        //1.获取请求头的令牌
        String jwttoken = request.getHeader("Authorization");
        String id = JwtUtils.parseJwt(jwttoken).get("id").toString();

        Admin admin = loginService.getAdminById(id);

        if (admin != null) {
            // 查询到用户，构造返回数据（包含roles数组）
            Map<String, Object> userData = new HashMap<>();
            userData.put("id", admin.getId());
            userData.put("name", admin.getName());
            userData.put("username", admin.getUsername());
            userData.put("avatar", admin.getAvatar());
            
            // 将role转换为roles数组，如果role为null则默认为guest
            String role = admin.getRole() != null ? admin.getRole() : "guest";
            userData.put("roles", Arrays.asList(role));
            
            log.info("用户 {} 获取信息成功，角色: {}", admin.getUsername(), role);
            return Result.success(userData);
        } else {
            // 根据token未查到用户
            return Result.error("未查到相关token");
        }
    }

    /**
     * 修改密码接口 - 存在二次注入漏洞
     * ⚠️ 从 JWT 中提取 username（该 username 是从数据库读取的，可能包含恶意 SQL）
     */
    @PostMapping("/changePassword")
    public Result changePassword(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        String newPassword = request.get("newPassword");
        String token = httpRequest.getHeader("Authorization");
        
        // 验证JWT Token是否存在
        if (token == null || token.trim().isEmpty()) {
            return Result.error("未授权访问");
        }
        
        try {
            // 从 Token 获取 username（这个 username 是从数据库中读取的，可能包含恶意 SQL）
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String username = JwtUtils.parseJwt(cleanToken).get("username").toString();

            System.out.println("username: " + username);
            
            log.warn("【二次注入】当前用户: {}, 准备修改密码", username);
            
            // ⚠️ 危险：Service 调用 Mapper，Mapper 中使用 ${} 拼接 username，触发二次注入
            int affectedRows = loginService.changePassword(username, newPassword);
            
            log.warn("【二次注入】SQL执行完成，影响行数: {}", affectedRows);

            
            // 注意：这是漏洞演示代码，只要影响行数 > 0 就返回成功
            // 即使影响了多行或不是预期的用户，也不做额外检查
            // 在真实场景中，应该使用 #{} 而非 ${} 来防止注入
            if (affectedRows > 0) {
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }
        } catch (Exception e) {
            log.error("修改密码失败，错误信息: {}", e.getMessage(), e);
            return Result.error("未授权访问或修改失败: " + e.getMessage());
        }
    }

    /**
     * 用户注册接口
     * 默认注册为 guest 角色
     */
    @PostMapping("/register")
    public Result register(@RequestBody Admin admin) {
        log.info("注册请求：username={}", admin.getUsername());
        
        // 参数校验
        if (admin.getUsername() == null || admin.getUsername().trim().isEmpty()) {
            return Result.error("用户名不能为空");
        }
        if (admin.getPassword() == null || admin.getPassword().trim().isEmpty()) {
            return Result.error("密码不能为空");
        }
        
        try {
            // 检查用户名是否已存在
            if (loginService.checkUsernameExists(admin.getUsername())) {
                return Result.error("用户名已存在");
            }
            
            // 设置默认姓名（如果未提供）
            if (admin.getName() == null || admin.getName().trim().isEmpty()) {
                admin.setName(admin.getUsername());
            }
            
            // 注册用户（默认 role='guest'）
            boolean success = loginService.register(admin);
            
            if (success) {
                log.info("用户注册成功：username={}", admin.getUsername());
                return Result.success("注册成功");
            } else {
                return Result.error("注册失败");
            }
        } catch (Exception e) {
            log.error("注册失败：{}", e.getMessage(), e);
            return Result.error("注册失败：" + e.getMessage());
        }
    }
}
