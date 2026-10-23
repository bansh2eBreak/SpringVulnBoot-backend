package icu.secnotes.controller.JWT;

import com.alibaba.fastjson.JSONObject;
import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.JwtJkuUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JWT jku 远程公钥。
 * 登录中心用自己的私钥签发员工令牌，公钥放在固定地址。
 * 漏洞版工资查询按令牌头里的 jku 选择公钥；安全版只接受登录中心那个地址。
 */
@Slf4j
@RestController
@RequestMapping("/jwt/jku")
@Tag(name = "JWT jku 远程公钥", description = "工资系统信任令牌头里的 jku，攻击者可换成自己的公钥地址伪造老板令牌")
public class JwtJkuController {

    @Autowired
    private UserService userService;

    @Operation(summary = "登录中心登录，使用登录中心私钥签发 RS256")
    @PostMapping("/login")
    public Result login(@RequestBody User user, HttpServletRequest request) {
        if (user == null || user.getUsername() == null) {
            return fail("账号或密码错误");
        }
        if ("boss".equals(user.getUsername())) {
            return fail("登录中心没有老板的密码，无法签发老板令牌");
        }
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            return fail("账号或密码错误");
        }
        User loginUser = userService.passwordLogin(user);
        if (loginUser == null) {
            return fail("账号或密码错误");
        }
        String jku = origin(request) + JwtJkuUtils.LOGIN_CENTER_PATH;
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("username", loginUser.getUsername());
        claims.put("name", loginUser.getName());
        claims.put("role", "employee");
        String token = JwtJkuUtils.signAsLoginCenter(claims, jku);
        log.info("登录中心签发令牌, username={}", loginUser.getUsername());
        return Result.success(token);
    }

    @Operation(summary = "登录中心公钥，浏览器可直接打开")
    @GetMapping("/login-center/jwks.json")
    public Map<String, Object> loginCenterJwks() {
        return JwtJkuUtils.loginCenterJwks();
    }

    @Operation(summary = "发布攻击者公钥，只保存公钥字段")
    @PostMapping("/attacker/jwks")
    public Result publishAttacker(@RequestBody Map<String, Object> body) {
        try {
            JwtJkuUtils.publishAttackerJwk(body);
            return Result.success("公钥已发布");
        } catch (IllegalArgumentException e) {
            return fail(e.getMessage());
        }
    }

    @Operation(summary = "攻击者公钥地址，浏览器可直接打开")
    @GetMapping("/attacker/jwks.json")
    public Map<String, Object> attackerJwks() {
        return JwtJkuUtils.attackerJwks();
    }

    @Operation(summary = "正常工资查询，只使用登录中心公钥")
    @PostMapping("/salary")
    public Result salary(@RequestBody Map<String, String> body) {
        return querySalary(body, false, true);
    }

    @Operation(summary = "漏洞工资查询，按令牌里的 jku 选择公钥")
    @PostMapping("/vuln/salary")
    public Result vulnSalary(@RequestBody Map<String, String> body) {
        return querySalary(body, false, false);
    }

    @Operation(summary = "安全工资查询，只接受登录中心的 jku")
    @PostMapping("/sec/salary")
    public Result secSalary(@RequestBody Map<String, String> body) {
        return querySalary(body, true, false);
    }

    private Result querySalary(Map<String, String> body, boolean loginCenterOnly, boolean fixedLoginCenterKey) {
        String token = body == null ? null : body.get("token");
        if (token == null || token.trim().isEmpty()) {
            return fail("缺少令牌");
        }
        try {
            JSONObject header = JwtJkuUtils.readHeader(token);
            if (!"RS256".equals(header.getString("alg"))) {
                return fail("验签失败");
            }
            PublicKey key = fixedLoginCenterKey
                    ? JwtJkuUtils.loginCenterPublicKey()
                    : JwtJkuUtils.publicKeyForJku(header.getString("jku"), loginCenterOnly);
            Claims claims = JwtJkuUtils.verify(token, key);
            Object username = claims.get("username");
            if (!(username instanceof String) || ((String) username).isEmpty()) {
                return fail("令牌里没有用户名");
            }
            Map<String, Object> payroll = userService.selectPayroll((String) username);
            Object salary = value(payroll, "salary");
            if (payroll == null || salary == null) {
                return fail("没有查到该员工的工资");
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("username", username);
            data.put("name", value(payroll, "name"));
            data.put("salary", ((Number) salary).intValue());
            return Result.success(data);
        } catch (IllegalArgumentException e) {
            return fail(e.getMessage());
        } catch (JwtException e) {
            return fail(fixedLoginCenterKey
                    ? "验签失败。张三没有登录中心私钥，改过的令牌无法通过。"
                    : "验签失败");
        }
    }

    private String origin(HttpServletRequest request) {
        String scheme = request.getScheme();
        int port = request.getServerPort();
        boolean omitPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + request.getServerName() + (omitPort ? "" : ":" + port);
    }

    private Object value(Map<String, Object> row, String key) {
        if (row == null) {
            return null;
        }
        if (row.containsKey(key)) {
            return row.get(key);
        }
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private Result fail(String message) {
        return new Result(1, message, message);
    }
}
