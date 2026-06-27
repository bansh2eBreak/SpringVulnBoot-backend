package icu.secnotes.controller.PasswordSecurity;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.LoginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 密码安全 - 种子可预测漏洞演示控制器（密码重置 token 可预测 → 账户接管）
 *
 * 漏洞版：用 new Random(System.currentTimeMillis()) 生成 reset token。
 *        java.util.Random 是线性同余生成器（LCG），种子就是毫秒时间戳，
 *        而时间戳通过 HTTP Date 头泄露到秒级。攻击者枚举那一秒的 1000 个毫秒种子，
 *        在本地复刻同样的算法即可生成全部候选 token，在线爆破 /reset 即可接管账号。
 *
 * 安全版：用 SecureRandom 生成 token，状态不可预测，爆破无效。
 *
 * 注意：接口只返回"秒级"服务器时间（模拟 HTTP Date 头精度），不返回 token 本身，
 *      token 进入"受害人邮箱"，攻击者只能通过预测+爆破拿到。
 */
@RestController
@RequestMapping("/passwordSecurity/predictableSeed")
@Slf4j
@Tag(name = "种子可预测漏洞", description = "密码重置 token 使用可预测随机数（java.util.Random）导致账户接管")
public class PredictableSeedController {

    @Autowired
    private LoginService loginService;

    /**
     * token → username 的内存映射（演示用，进程重启即清空）
     */
    private static final Map<String, String> RESET_TOKENS = new ConcurrentHashMap<>();

    /**
     * 安全版使用的随机源
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * 漏洞版"忘记密码"：用可预测的 java.util.Random 生成 token
     */
    @PostMapping("/forgot-password/vuln")
    @Operation(summary = "忘记密码-漏洞版", description = "new Random(System.currentTimeMillis()) 生成可预测 token")
    public Result forgotPasswordVuln(@RequestBody Map<String, String> body) {
        String username = body == null ? null : body.get("username");
        if (username == null || username.trim().isEmpty()) {
            return Result.error("用户名不能为空");
        }

        // ❌ 漏洞点：种子是毫秒时间戳，可预测；java.util.Random 是 LCG，输出可复算
        long seed = System.currentTimeMillis();
        long raw = new Random(seed).nextLong();
        String token = Long.toHexString(raw);

        RESET_TOKENS.put(token, username);

        System.out.println("================================================");
        System.out.println("token: " + token);
        System.out.println("seed: " + seed);
        System.out.println("username: " + username);
        System.out.println("================================================");

        // 只返回秒级时间（模拟 HTTP Date 头精度），不返回 token
        long serverTimeSecond = (seed / 1000L) * 1000L;

        log.warn("【PredictableSeed-VULN】username={}, seed={}, token={}, 返回秒级时间={}",
                username, seed, token, serverTimeSecond);

        Map<String, Object> data = new HashMap<>();
        data.put("to", username + "@secnotes.icu");
        data.put("serverTimeSecond", serverTimeSecond);
        data.put("hint", "token 已发往受害人邮箱，攻击者无法直接获取。但 token = Long.toHexString(new Random(serverTime毫秒).nextLong())，可预测。");
        return Result.success(data);
    }

    /**
     * 安全版"忘记密码"：用 SecureRandom 生成不可预测 token
     */
    @PostMapping("/forgot-password/sec")
    @Operation(summary = "忘记密码-安全版", description = "SecureRandom 生成不可预测 token，爆破无效")
    public Result forgotPasswordSec(@RequestBody Map<String, String> body) {
        String username = body == null ? null : body.get("username");
        if (username == null || username.trim().isEmpty()) {
            return Result.error("用户名不能为空");
        }

        // ✅ SecureRandom：从操作系统熵池取随机，状态不可预测
        long raw = SECURE_RANDOM.nextLong();
        String token = Long.toHexString(raw);

        RESET_TOKENS.put(token, username);

        long serverTimeSecond = (System.currentTimeMillis() / 1000L) * 1000L;

        log.info("【PredictableSeed-SEC】username={}, token={}（SecureRandom，不可预测）", username, token);

        Map<String, Object> data = new HashMap<>();
        data.put("to", username + "@secnotes.icu");
        data.put("serverTimeSecond", serverTimeSecond);
        data.put("hint", "token 由 SecureRandom 生成，与时间戳无关，无法通过枚举种子预测。");
        return Result.success(data);
    }

    /**
     * 用 token 重置密码（爆破目标）。命中则修改对应用户密码，模拟账号接管。
     */
    @PostMapping("/reset")
    @Operation(summary = "用 token 重置密码", description = "凭 reset token 修改对应用户密码；爆破命中即接管")
    public Result reset(@RequestBody Map<String, String> body) {
        if (body == null) {
            return Result.error("请求体不能为空");
        }
        String token = body.get("token");
        String newPassword = body.get("newPassword");

        if (token == null || token.trim().isEmpty()) {
            return Result.error("token 不能为空");
        }
        if (newPassword == null || newPassword.trim().isEmpty()) {
            return Result.error("新密码不能为空");
        }

        String username = RESET_TOKENS.remove(token);
        if (username == null) {
            return Result.error("token 无效或已使用");
        }

        int affected = loginService.changePassword(username, newPassword);
        if (affected <= 0) {
            return Result.error("密码重置失败，用户不存在：" + username);
        }

        log.warn("【PredictableSeed-RESET】用户 {} 密码已被 token {} 重置为：{}", username, token, newPassword);
        return Result.success("用户 " + username + " 密码已被重置为：" + newPassword);
    }
}
