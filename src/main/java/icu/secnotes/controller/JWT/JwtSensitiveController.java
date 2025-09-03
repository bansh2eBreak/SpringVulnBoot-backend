package icu.secnotes.controller.JWT;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.JwtSensitiveUtils;
import icu.secnotes.utils.JwtSecureUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@Slf4j
@RestController
@RequestMapping("/jwt/sensitive")
public class JwtSensitiveController {

    @Autowired
    private UserService userService;

    /**
     * JWT存储敏感信息漏洞登录接口
     * @param user
     * @return
     */
    @PostMapping("/vulnLogin")
    public Result jwtSensitiveVulnLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT（包含敏感信息）
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());
            
            // 模拟从数据库查询敏感信息并存储到JWT中（实际应用中这些信息应该从数据库获取）
            // 这里演示JWT存储敏感信息的漏洞
            claims.put("idCard", "110101199001011234"); // 身份证号
            claims.put("phone", "13800138000"); // 手机号
            claims.put("bankCard", "6222021234567890123"); // 银行卡号
            claims.put("address", "北京市朝阳区xxx街道xxx号"); // 家庭住址

            String jwttoken = JwtSensitiveUtils.generateJwt(claims);

            log.info("用户:{} JWT存储敏感信息漏洞登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT存储敏感信息漏洞登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * JWT安全实现登录接口
     * @param user
     * @return
     */
    @PostMapping("/secLogin")
    public Result jwtSensitiveSecLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT（不包含敏感信息）
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());

            String jwttoken = JwtSecureUtils.generateJwt(claims);

            log.info("用户:{} JWT安全实现登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT安全实现登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }
}
