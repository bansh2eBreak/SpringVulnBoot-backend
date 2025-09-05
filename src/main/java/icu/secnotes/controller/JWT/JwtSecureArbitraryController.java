package icu.secnotes.controller.JWT;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.JwtSecureArbitraryUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

@Slf4j
@RestController
@RequestMapping("/jwt/secureArbitrary")
public class JwtSecureArbitraryController {

    @Autowired
    private UserService userService;

    /**
     * JWT安全实现登录接口
     * @param user
     * @return
     */
    @PostMapping("/login")
    public Result jwtSecureArbitraryLogin(@RequestBody User user) {
        User loginUser = userService.passwordLogin(user);
        if (loginUser != null) {
            // 登录成功，生成JWT
            HashMap<String, Object> claims = new HashMap<>();
            claims.put("id", loginUser.getId());
            claims.put("username", loginUser.getUsername());
            claims.put("name", loginUser.getName());

            String jwttoken = JwtSecureArbitraryUtils.generateJwt(claims);

            log.info("用户:{} JWT安全实现登录成功，分配的jwttoken是:{}", loginUser.getUsername(), jwttoken);
            return Result.success(jwttoken);
        } else {
            // 登录失败
            log.info("JWT安全实现登录失败，登录账号:{}， 密码: {}", user.getUsername(), user.getPassword());
            return Result.error("用户名或密码错误");
        }
    }

    /**
     * JWT安全实现获取用户信息
     */
    @GetMapping("/getInfo")
    public Result jwtSecureArbitraryGetInfo(HttpServletRequest request) {
        // 获取请求头的JWT令牌
        String jwttoken = request.getHeader("jwt");
        if (jwttoken == null || jwttoken.isEmpty()) {
            return Result.error("JWT令牌不能为空");
        }

        try {
            String id = JwtSecureArbitraryUtils.parseJwt(jwttoken).get("id").toString();
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
            log.error("JWT安全实现解析失败", e);
            return Result.error("JWT解析失败: " + e.getMessage());
        }
    }
}
