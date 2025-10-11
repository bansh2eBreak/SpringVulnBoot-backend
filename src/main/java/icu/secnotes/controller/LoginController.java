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
            // 查询到用户
            return Result.success(admin);
        } else {
            // 根据token未查到用户
            return Result.error("未查到相关token");
        }
    }

    /**
     * 管理员修改密码接口
     * 用于管理员实际使用的修改密码功能
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
            // 获取用户ID
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = JwtUtils.parseJwt(cleanToken).get("id").toString();
            
            // 修改密码
            boolean success = loginService.changePassword(userId, newPassword);
            
            if (success) {
                log.info("管理员ID: {} 密码修改成功", userId);
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }
        } catch (Exception e) {
            log.error("JWT解析失败", e);
            return Result.error("未授权访问");
        }
    }
}
