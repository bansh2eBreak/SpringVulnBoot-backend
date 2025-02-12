package icu.secnotes.controller.Authentication;

import com.google.code.kaptcha.impl.DefaultKaptcha;
import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserLoginLogService;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.time.LocalDateTime;

@RestController
@Slf4j
@RequestMapping("/authentication/passwordBased")
public class PassBasedAuthVulnController {

    @Autowired
    private UserService userService;

    @Autowired
    private DefaultKaptcha defaultKaptcha;

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

    /**
     * 基于HTTP Basic认证的用户登录
     */
    @PostMapping("/httpBasicLogin")
    public Result httpBasicLogin(HttpServletRequest request, HttpServletResponse response) {
        String USERNAME = "zhangsan"; // 硬编码用户名
        String PASSWORD = "123"; // 硬编码密码

        // 处理HTTP Basic Auth登录
        String token = request.getHeader("token");
        if (token == null || !token.startsWith("Basic ")) {
            log.info("HTTP Basic Auth登录，token缺失或者token格式错误");
            return Result.success("HTTP Basic Auth登录，token缺失或者token格式错误");
        }

        String[] credentials = Security.decodeBasicAuth(token);
        if (credentials == null || credentials.length != 2) {
            return Result.success("HTTP Basic Auth登录，token解析失败");
        }

        String username = credentials[0];
        String password = credentials[1];

        if (!USERNAME.equals(username) || !PASSWORD.equals(password)) {
            log.info("HTTP Basic Auth登录，账号密码错误，token：{}" , token);
            return Result.success("HTTP Basic Auth登录失败，账号：" + username + "，密码：" + password);
        }

        log.info("HTTP Basic Auth登录，放行，token：{}" , token);
        return Result.success("HTTP Basic Auth登录成功，账号：" + username + "，密码：" + password);
    }

    @GetMapping("/captcha")
    public void getCaptcha(HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.info("有人请求验证码了.....");
        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/jpeg");

        // 生成验证码文本
        String capText = defaultKaptcha.createText();
        // 将验证码文本存储到 Session
        HttpSession session = request.getSession();
        System.out.println("存储时候的session对象" + session);
        session.setAttribute("captcha", capText);
        // 生成验证码图片
        BufferedImage bi = defaultKaptcha.createImage(capText);
        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(bi, "jpg", out);
        out.flush();
        out.close();

        System.out.println("获取验证码接口-----》Stored captcha in session: " + session.getAttribute("captcha"));
    }

    @PostMapping("/vuln3")
    public Result passwordLoginVuln3( @RequestParam String username, // 接收用户名
                                             @RequestParam String password, // 接收密码
                                             @RequestParam String captcha,  // 接收验证码
                                             HttpServletRequest request) {

        //获取服务端生成的验证码
        HttpSession session = request.getSession();
        System.out.println("读取时候的session对象" + session);

        // 从 Session 中获取验证码
        System.out.println("登录接口-------》提交的验证码：" + captcha);
        System.out.println("登录接口-------》Stored captcha in session: " + session.getAttribute("captcha"));

        String sessionCaptcha = (String) request.getSession().getAttribute("captcha");
        // 校验验证码
        if (sessionCaptcha == null || !sessionCaptcha.equalsIgnoreCase(captcha)) {
            return Result.success("验证码错误");
        }

        // 校验用户名和密码
        User u = userService.passwordLogin2(username, password);

        if (u != null) {
            // 登录成功
            log.info("{} 登录成功！", u.getUsername());
            return Result.success("登录成功，账号：" + username + "，密码：" + password);
        } else {
            // 登录失败
            log.error("登录失败，账号密码是：{},{}", username, password);
            return Result.success("登录失败，账号：" + username + "，密码：" + password);
        }
    }

    /**
     * 用户登录，通过图形验证码防刷（简单实现图形验证码）
     *
     * @param username
     * @param password
     * @return
     */
    @PostMapping("/sec2")
    public Result passwordLoginSecByCaptcha( @RequestParam String username, // 接收用户名
                                            @RequestParam String password, // 接收密码
                                            @RequestParam String captcha,  // 接收验证码
                                            HttpServletRequest request) {

        //获取服务端生成的验证码
        HttpSession session = request.getSession();
        System.out.println("读取时候的session对象" + session);

        // 从 Session 中获取验证码
        System.out.println("登录接口-------》提交的验证码：" + captcha);
        System.out.println("登录接口-------》Stored captcha in session: " + session.getAttribute("captcha"));

        String sessionCaptcha = (String) request.getSession().getAttribute("captcha");
        // 校验验证码
        if (sessionCaptcha == null || !sessionCaptcha.equalsIgnoreCase(captcha)) {
            return Result.success("验证码错误，账号：" + username + "，密码：" + password);
        }

        // 清除验证码
        session.removeAttribute("captcha");

        // 校验用户名和密码
        User u = userService.passwordLogin2(username, password);

        if (u != null) {
            // 登录成功
            log.info("{} 登录成功！", u.getUsername());
            return Result.success("登录成功，账号：" + username + "，密码：" + password);
        } else {
            // 登录失败
            log.error("登录失败，账号密码是：{},{}", username, password);
            return Result.success("登录失败，账号：" + username + "，密码：" + password);
        }
    }

}
