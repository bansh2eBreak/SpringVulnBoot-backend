package icu.secnotes.controller.JWT;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.JwtRS256Utils;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

/**
 * JWT RS256签名算法控制器
 * 演示RSA非对称加密的JWT签名和验证
 */
@Slf4j
@RestController
@RequestMapping("/jwt/algorithmConfusion")
public class JwtRS256Controller {

    @Autowired
    private UserService userService;


    /**
     * RS256登录接口
     * 使用私钥签名JWT
     */
    @PostMapping("/login")
    public Result rs256Login(@RequestBody User user) {
        try {
            User loginUser = userService.passwordLogin(user);
            if (loginUser != null) {
                // 登录成功，生成RS256签名的JWT
                HashMap<String, Object> claims = new HashMap<>();
                claims.put("id", loginUser.getId());
                claims.put("username", loginUser.getUsername());
                claims.put("name", loginUser.getName());

                String jwt = JwtRS256Utils.generateRS256Jwt(claims);
                
                log.info("用户:{} RS256登录成功，JWT:{}", loginUser.getUsername(), jwt);
                return Result.success(jwt);
            } else {
                log.info("RS256登录失败，用户名:{}", user.getUsername());
                return Result.error("用户名或密码错误");
            }
        } catch (Exception e) {
            log.error("RS256登录异常", e);
            return Result.error("登录失败: " + e.getMessage());
        }
    }

    /**
     * 验证RS256 JWT
     * 使用公钥验证JWT签名
     */
    @GetMapping("/verify")
    public Result verifyJwt(HttpServletRequest request) {
        // 获取请求头的JWT令牌
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            String id = JwtRS256Utils.parseRS256Jwt(jwttoken).get("id").toString();
            User user = userService.selectUserById(id).get(0);

            if (user != null) {
                HashMap<String, Object> userInfo = new HashMap<>();
                userInfo.put("id", user.getId());
                userInfo.put("username", user.getUsername());
                userInfo.put("name", user.getName());
                userInfo.put("jwt", jwttoken);
                return Result.success(userInfo);
            } else {
                return Result.error("未查到相关用户");
            }
        } catch (Exception e) {
            log.error("RS256 JWT验证失败", e);
            return Result.error("JWT验证失败");
        }
    }

    /**
     * 易受算法混淆攻击的JWT验证接口
     * 完全按照Burp Suite官方文档的伪代码实现
     * 注意：此接口存在严重安全漏洞，仅用于学习目的
     */
    @GetMapping("/verifyVulnerable")
    public Result verifyJwtVulnerable(HttpServletRequest request) {
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            // 使用易受攻击的验证方法
            Claims claims = JwtRS256Utils.verifyVulnerable(jwttoken, JwtRS256Utils.getRsaPublicKeyObject());
            String id = claims.get("id").toString();
            User user = userService.selectUserById(id).get(0);

            if (user != null) {
                HashMap<String, Object> userInfo = new HashMap<>();
                userInfo.put("id", user.getId());
                userInfo.put("username", user.getUsername());
                userInfo.put("name", user.getName());
                userInfo.put("jwt", jwttoken);
                return Result.success(userInfo);
            } else {
                return Result.error("未查到相关用户");
            }
        } catch (Exception e) {
            log.error("易受攻击的JWT验证失败", e);
            return Result.error("JWT验证失败: " + e.getMessage());
        }
    }

    /**
     * 获取用于算法混淆攻击的公钥
     */
    @GetMapping("/public")
    public Result getAttackKey() {
        try {
            String publicKeyBase64 = JwtRS256Utils.getPublicKeyForAlgorithmConfusion();
            
            HashMap<String, Object> result = new HashMap<>();
            result.put("publicKeyBase64", publicKeyBase64);
            
            log.info("获取算法混淆攻击公钥成功");
            return Result.success(result);
        } catch (Exception e) {
            log.error("获取算法混淆攻击公钥失败", e);
            return Result.error("获取公钥失败: " + e.getMessage());
        }
    }

    /**
     * 安全的JWT验证接口 - 修复算法混淆漏洞
     * 强制校验JWT必须是RS256算法
     */
    @GetMapping("/verifySecure")
    public Result verifyJwtSecure(HttpServletRequest request) {
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            // 使用安全的验证方法
            Claims claims = JwtRS256Utils.verifySecure(jwttoken);
            String id = claims.get("id").toString();
            User user = userService.selectUserById(id).get(0);

            if (user != null) {
                HashMap<String, Object> userInfo = new HashMap<>();
                userInfo.put("id", user.getId());
                userInfo.put("username", user.getUsername());
                userInfo.put("name", user.getName());
                userInfo.put("jwt", jwttoken);
                return Result.success(userInfo);
            } else {
                return Result.error("未查到相关用户");
            }
        } catch (Exception e) {
            log.error("安全JWT验证失败", e);
            return Result.error("JWT验证失败: " + e.getMessage());
        }
    }

}
