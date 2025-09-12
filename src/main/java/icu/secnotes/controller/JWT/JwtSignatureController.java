package icu.secnotes.controller.JWT;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.JwtSignatureUtils;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

@Slf4j
@RestController
@RequestMapping("/jwt/signature")
public class JwtSignatureController {

    @Autowired
    private UserService userService;

    /**
     * JWT签名漏洞登录接口
     * @param user
     * @return
     */
    @PostMapping("/vulnLogin")
    public Result jwtSignatureVulnLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());

            String jwttoken = JwtSignatureUtils.generateJwt(claims);

            log.info("用户:{} JWT签名漏洞登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT签名漏洞登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * JWT签名漏洞获取用户信息
     */
    @GetMapping("/vulnGetInfo")
    public Result jwtSignatureVulnGetInfo(HttpServletRequest request) {
        // 获取请求头的JWT令牌
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            Claims claims = JwtSignatureUtils.parseVulnJwt(jwttoken);
            if (claims == null) {
                return Result.error("JWT解析失败");
            }

            // 从claims中获取用户ID，然后从数据库查询用户信息
            String id = claims.get("id").toString();
            User user = userService.selectUserById(id).get(0);

            if (user != null) {
                HashMap<String, Object> userInfo = new HashMap<>();
                userInfo.put("id", user.getId());
                userInfo.put("username", user.getUsername());
                userInfo.put("name", user.getName());
                userInfo.put("jwt", jwttoken);
                
                log.info("JWT签名漏洞解析成功，用户信息:{}", userInfo);
                return Result.success(userInfo);
            } else {
                return Result.error("未查到相关用户");
            }
        } catch (Exception e) {
            log.error("JWT签名漏洞解析失败", e);
            return Result.error("JWT解析失败: " + e.getMessage());
        }
    }

    /**
     * JWT安全签名登录接口
     * @param user
     * @return
     */
    @PostMapping("/secureLogin")
    public Result jwtSignatureSecureLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());

            String jwttoken = JwtSignatureUtils.generateJwt(claims);

            log.info("用户:{} JWT安全签名登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT安全签名登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * JWT安全签名获取用户信息
     */
    @GetMapping("/secureGetInfo")
    public Result jwtSignatureSecureGetInfo(HttpServletRequest request) {
        // 获取请求头的JWT令牌
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            Claims claims = JwtSignatureUtils.parseSecureJwt(jwttoken);
            
            // 从claims中获取用户ID，然后从数据库查询用户信息
            String id = claims.get("id").toString();
            User user = userService.selectUserById(id).get(0);

            if (user != null) {
                HashMap<String, Object> userInfo = new HashMap<>();
                userInfo.put("id", user.getId());
                userInfo.put("username", user.getUsername());
                userInfo.put("name", user.getName());
                userInfo.put("jwt", jwttoken);
                
                log.info("JWT安全签名解析成功，用户信息:{}", userInfo);
                return Result.success(userInfo);
            } else {
                return Result.error("未查到相关用户");
            }
        } catch (Exception e) {
            log.error("JWT安全签名解析失败", e);
            return Result.error("JWT解析失败: " + e.getMessage());
        }
    }
}
