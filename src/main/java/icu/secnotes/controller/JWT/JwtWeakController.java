package icu.secnotes.controller.JWT;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.JwtWeakUtils;
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
@RequestMapping("/jwt/weak")
public class JwtWeakController {

    @Autowired
    private UserService userService;

    /**
     * JWT弱密码漏洞登录接口
     * @param user
     * @return
     */
    @PostMapping("/weakLogin")
    public Result jwtWeakLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());

            String jwttoken = JwtWeakUtils.generateWeakJwt(claims);

            log.info("用户:{} JWT弱密码漏洞登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT弱密码漏洞登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * JWT弱密码漏洞获取用户信息
     */
    @GetMapping("/weakGetInfo")
    public Result jwtWeakGetInfo(HttpServletRequest request) {
        // 获取请求头的JWT令牌
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            String id = JwtWeakUtils.parseWeakJwt(jwttoken).get("id").toString();
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
            log.error("JWT弱密码漏洞解析失败", e);
            return Result.error("JWT解析失败");
        }
    }

    /**
     * JWT强密码安全登录接口
     * @param user
     * @return
     */
    @PostMapping("/strongLogin")
    public Result jwtStrongLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());

            String jwttoken = JwtWeakUtils.generateStrongJwt(claims);

            log.info("用户:{} JWT强密码安全登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT强密码安全登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * JWT强密码安全获取用户信息
     */
    @GetMapping("/strongGetInfo")
    public Result jwtStrongGetInfo(HttpServletRequest request) {
        // 获取请求头的JWT令牌
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            String id = JwtWeakUtils.parseStrongJwt(jwttoken).get("id").toString();
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
            log.error("JWT强密码安全解析失败", e);
            return Result.error("JWT解析失败");
        }
    }

}
