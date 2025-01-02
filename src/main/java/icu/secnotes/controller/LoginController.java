package icu.secnotes.controller;

import icu.secnotes.pojo.Admin;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.LoginService;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
            log.info("用户 {} 登录成功...", login.getUsername());
            return Result.success(login);
        } else {
            // 登录失败
            log.info("登录失败，登录账号:{}， 密码: {}", admin.getUsername(), admin.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * 通过token获取用户信息
     */
    @GetMapping("/getUserByToken")
    public Result getUserByToken(@Param("token") String token) {
        Admin admin = loginService.getUserByToken(token);
        if (admin != null) {
            // 查询到用户
            log.info("token {} 查询到用户 {}", token, admin.getUsername());
            return Result.success(admin);
        }else {
            // 根据token未查到用户
            log.info("token {} 未查询到任何用户", token);
            return Result.error("未查到相关token");
        }
    }
}
