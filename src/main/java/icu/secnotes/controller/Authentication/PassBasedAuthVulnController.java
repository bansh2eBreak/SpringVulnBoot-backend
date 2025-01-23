package icu.secnotes.controller.Authentication;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserLoginLogService;
import icu.secnotes.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;

@RestController
@Slf4j
@RequestMapping("/authentication/passwordBased")
public class PassBasedAuthVulnController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserLoginLogService userLoginLogService;

    /**
     * 用户登录，存在暴力破解漏洞
     *
     * @param user
     * @return
     */
    @PostMapping("/vuln1")
    public Result passwordLoginVuln(@RequestBody User user) {
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功
            log.info("{} 登录成功！", u.getUsername());
            return Result.success("登录成功，账号：" + user.getUsername() + "，密码：" + user.getPassword());
        } else {
            // 登录失败
            log.error("登录失败，账号密码是：{},{}", user.getUsername(), user.getPassword());
            return Result.success("登录失败，账号：" + user.getUsername() + "，密码：" + user.getPassword());
        }
    }

    /**
     * 防止暴力破解的用户登录，可以伪造IP绕过
     */
    @PostMapping("/vuln2")
    public Result passwordLoginVuln2(@RequestBody User user, HttpServletRequest request) {
        //1. 获取用户登录ip
        String ip = (request.getHeader("X-Forwarded-For") != null) ? request.getHeader("X-Forwarded-For") : request.getRemoteAddr();

        //2. 判断最近5分钟内登录失败次数是否超过5次
        if (userLoginLogService.countUserLoginLogByIp(ip) >= 5) {
            log.error("登录失败次数过多，账号：{}", user.getUsername());
            return Result.success("登录失败次数过多，请稍后再试！");
        }

        //3. 登录
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功，清除登录失败记录
            userLoginLogService.deleteUserLoginLogByIp(ip);
            log.info("{} 登录成功！", u.getUsername());
            return Result.success("登录成功，账号：" + user.getUsername() + "，密码：" + user.getPassword());
        } else {
            // 登录失败，记录登录失败日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now());
            log.error("登录失败，账号密码是：{},{}", user.getUsername(), user.getPassword());
            return Result.success("登录失败，账号：" + user.getUsername() + "，密码：" + user.getPassword());
        }
    }

    /**
     * 防止暴力破解的用户登录
     */
    @PostMapping("/sec")
    public Result passwordLoginSec(@RequestBody User user, HttpServletRequest request) {
        //1. 获取用户登录ip
        String ip = request.getRemoteAddr();

        //2. 判断最近5分钟内登录失败次数是否超过5次
        if (userLoginLogService.countUserLoginLogByIp(ip) >= 5) {
            log.error("登录失败次数过多，账号：{}", user.getUsername());
            return Result.success("登录失败次数过多，请稍后再试！");
        }

        //3. 登录
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功，清除登录失败记录
            userLoginLogService.deleteUserLoginLogByIp(ip);
            log.info("{} 登录成功！", u.getUsername());
            return Result.success("登录成功，账号：" + user.getUsername() + "，密码：" + user.getPassword());
        } else {
            // 登录失败，记录登录失败日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now());
            log.error("登录失败，账号密码是：{},{}", user.getUsername(), user.getPassword());
            return Result.success("登录失败，账号：" + user.getUsername() + "，密码：" + user.getPassword());
        }
    }
}
