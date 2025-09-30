package icu.secnotes.controller.Other;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserLoginLogService;
import icu.secnotes.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * IP地址伪造漏洞演示控制器
 */
@RestController
@RequestMapping("/ipspoofing")
@Slf4j
@Tag(name = "IP地址伪造漏洞", description = "IP地址伪造漏洞演示")
public class IpSpoofingController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserLoginLogService userLoginLogService;

    /**
     * IP地址伪造漏洞 - 可绕过IP限制
     * 通过伪造X-Forwarded-For等HTTP头来绕过IP限制
     */
    @PostMapping("/vuln")
    @Operation(summary = "IP地址伪造漏洞测试", description = "通过伪造HTTP头绕过IP限制")
    public Result ipSpoofingVuln(@RequestBody User user, HttpServletRequest request) {
        // 1. 获取用户登录IP - 存在漏洞：信任HTTP头
        String ip = getClientIpVuln(request);
        
        log.info("IP地址伪造测试 - 获取到的IP: {}", ip);

        // 2. 登录
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功，记录登录成功日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "成功");
            log.info("{} 登录成功！IP: {}", u.getUsername(), ip);
            return Result.success("登录成功，账号：" + user.getUsername() + "，IP: " + ip);
        } else {
            // 登录失败，记录登录失败日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "失败");
            log.error("登录失败，账号密码是：{},{}，IP: {}", user.getUsername(), user.getPassword(), ip);
            return Result.success("登录失败，账号：" + user.getUsername() + "，IP: " + ip);
        }
    }

    /**
     * 正常登录接口 - 不携带XFF头
     * 用于对比IP伪造效果
     */
    @PostMapping("/login")
    @Operation(summary = "正常登录测试", description = "正常登录，不携带XFF头")
    public Result normalLogin(@RequestBody User user, HttpServletRequest request) {
        // 1. 获取用户登录IP - 正常方式：只使用request.getRemoteAddr()
        String ip = request.getRemoteAddr();
        
        log.info("正常登录测试 - 获取到的IP: {}", ip);

        // 2. 登录
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功，记录登录成功日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "成功");
            log.info("{} 正常登录成功！IP: {}", u.getUsername(), ip);
            return Result.success("正常登录成功，账号：" + user.getUsername() + "，IP: " + ip);
        } else {
            // 登录失败，记录登录失败日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "失败");
            log.error("正常登录失败，账号密码是：{},{}，IP: {}", user.getUsername(), user.getPassword(), ip);
            return Result.success("正常登录失败，账号：" + user.getUsername() + "，IP: " + ip);
        }
    }

    /**
     * 安全的IP获取方式 - 防止IP伪造
     * 只信任直接连接的IP，不信任HTTP头
     */
    @PostMapping("/sec")
    @Operation(summary = "安全IP获取测试", description = "使用安全的IP获取方式防止伪造")
    public Result ipSpoofingSec(@RequestBody User user, HttpServletRequest request) {
        // 1. 获取用户登录IP - 安全方式：只使用request.getRemoteAddr()
        String ip = getClientIpSec(request);
        
        log.info("安全IP获取测试 - 获取到的IP: {}", ip);

        // 2. 登录
        User u = userService.passwordLogin(user);

        if (u != null) {
            // 登录成功，记录登录成功日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "成功");
            log.info("{} 登录成功！IP: {}", u.getUsername(), ip);
            return Result.success("登录成功，账号：" + user.getUsername() + "，IP: " + ip);
        } else {
            // 登录失败，记录登录失败日志
            userLoginLogService.insertUserLoginLog(ip, user.getUsername(), LocalDateTime.now(), "失败");
            log.error("登录失败，账号密码是：{},{}，IP: {}", user.getUsername(), user.getPassword(), ip);
            return Result.success("登录失败，账号：" + user.getUsername() + "，IP: " + ip);
        }
    }

    /**
     * 获取客户端IP - 存在漏洞的方式
     * 信任HTTP头，容易被伪造
     */
    private String getClientIpVuln(HttpServletRequest request) {
        // 漏洞：直接信任X-Forwarded-For头
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        
        // 处理多个IP的情况，取第一个
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        
        return ip;
    }

    /**
     * 获取客户端IP - 安全的方式
     * 只信任直接连接的IP
     */
    private String getClientIpSec(HttpServletRequest request) {
        // 安全：只使用request.getRemoteAddr()，不信任任何HTTP头
        return request.getRemoteAddr();
    }

    /**
     * 查询所有用户登录日志
     */
    @GetMapping("/logs")
    @Operation(summary = "查询所有用户登录日志", description = "查询所有用户的最新登录日志")
    public Result getAllUserLoginLogs() {
        List<Map<String, Object>> logs = userLoginLogService.getAllUserLoginLogs();
        log.info("查询所有用户的登录日志，共 {} 条", logs.size());
        return Result.success(logs);
    }
}
