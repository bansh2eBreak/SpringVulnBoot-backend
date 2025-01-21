package icu.secnotes.controller;

import icu.secnotes.pojo.Admin;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.LoginService;
import icu.secnotes.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

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
}
