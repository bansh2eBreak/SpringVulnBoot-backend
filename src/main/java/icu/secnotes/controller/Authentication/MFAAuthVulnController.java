package icu.secnotes.controller.Authentication;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import icu.secnotes.service.MfaSecretService;
import icu.secnotes.utils.GoogleAuthenticatorUtil;
import icu.secnotes.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/authentication/mfaBased")
public class MFAAuthVulnController {

    @Autowired
    private UserService userService;

    @Autowired
    private MfaSecretService mfaSecretService;

    /**
     * 漏洞场景：管理员修改用户密码 - 仅前端验证MFA，后端不校验
     * 攻击者可以通过直接调用API绕过MFA验证
     */
    @PostMapping("/changePasswordVuln")
    public Result changePasswordVuln(@RequestBody Map<String, Object> requestData, HttpServletRequest request) {
        try {
            // 获取JWT Token
            String jwttoken = request.getHeader("Authorization");
            if (jwttoken == null) {
                return Result.error("未提供身份验证令牌");
            }

            // 解析JWT获取用户ID
            String tokenUserName = JwtUtils.parseJwt(jwttoken).get("username").toString();
            log.info("当前操作的管理员是: {}", tokenUserName);

            // 获取请求参数
            Integer targetUserId = (Integer) requestData.get("targetUserId");
            String newPassword = (String) requestData.get("newPassword");
            // 处理mfaCode可能是字符串的情况
            Object mfaCodeObj = requestData.get("mfaCode");
            Integer mfaCode = null;
            if (mfaCodeObj != null) {
                if (mfaCodeObj instanceof String) {
                    try {
                        mfaCode = Integer.parseInt((String) mfaCodeObj);
                    } catch (NumberFormatException e) {
                        log.warn("MFA验证码格式错误: {}", mfaCodeObj);
                    }
                } else if (mfaCodeObj instanceof Integer) {
                    mfaCode = (Integer) mfaCodeObj;
                }
            }

            if (targetUserId == null || newPassword == null) {
                return Result.error("参数不完整");
            }

            // 漏洞：这里没有验证MFA代码，直接执行密码修改
            // 攻击者可以通过直接调用此API绕过MFA验证
            log.warn("漏洞场景：MFA验证被绕过，直接修改用户密码");
            
            // 执行密码修改
            User user = new User();
            user.setId(targetUserId);
            user.setPassword(newPassword);
            
            int result = userService.updateUserPassword(user);
            if (result > 0) {
                log.info("用户 {} 的密码已被用户 {} 修改", targetUserId, tokenUserName);
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }

        } catch (Exception e) {
            log.error("修改密码时发生错误", e);
            return Result.error("操作失败");
        }
    }

    /**
     * 安全场景：管理员修改用户密码 - 后端严格校验MFA
     */
    @PostMapping("/changePasswordSec")
    public Result changePasswordSec(@RequestBody Map<String, Object> requestData, HttpServletRequest request) {
        try {
            // 获取JWT Token
            String jwttoken = request.getHeader("Authorization");
            if (jwttoken == null) {
                return Result.error("未提供身份验证令牌");
            }

            // 解析JWT获取用户ID
            String tokenUserId = JwtUtils.parseJwt(jwttoken).get("id").toString();
            log.info("当前操作用户ID: {}", tokenUserId);

            // 获取请求参数
            Integer targetUserId = (Integer) requestData.get("targetUserId");
            String newPassword = (String) requestData.get("newPassword");

            // 处理mfaCode可能是字符串的情况
            Object mfaCodeObj = requestData.get("mfaCode");
            Integer mfaCode = null;
            if (mfaCodeObj != null) {
                if (mfaCodeObj instanceof String) {
                    try {
                        mfaCode = Integer.parseInt((String) mfaCodeObj);
                    } catch (NumberFormatException e) {
                        log.warn("MFA验证码格式错误: {}", mfaCodeObj);
                    }
                } else if (mfaCodeObj instanceof Integer) {
                    mfaCode = (Integer) mfaCodeObj;
                }
            }

            if (targetUserId == null || newPassword == null || mfaCode == null) {
                return Result.error("参数不完整");
            }

            // 安全：严格验证MFA代码
            // 获取当前用户的MFA密钥
            var mfaSecret = mfaSecretService.getSecretByUserId(Integer.parseInt(tokenUserId));
            if (mfaSecret == null) {
                return Result.error("用户未绑定MFA，无法执行敏感操作");
            }

            // 验证MFA代码
            boolean isValidMfa = GoogleAuthenticatorUtil.verifyCode(mfaSecret.getSecret(), mfaCode);
            if (!isValidMfa) {
                log.warn("用户 {} 提供的MFA验证码错误: {}", tokenUserId, mfaCode);
                return Result.error("MFA验证码错误");
            }

            log.info("MFA验证通过，执行密码修改操作");
            
            // 执行密码修改
            User user = new User();
            user.setId(targetUserId);
            user.setPassword(newPassword);
            
            int result = userService.updateUserPassword(user);
            if (result > 0) {
                log.info("用户 {} 的密码已被用户 {} 修改（MFA验证通过）", targetUserId, tokenUserId);
                return Result.success("密码修改成功");
            } else {
                return Result.error("密码修改失败");
            }

        } catch (Exception e) {
            log.error("修改密码时发生错误", e);
            return Result.error("操作失败");
        }
    }

    /**
     * 获取用户列表（用于测试）
     */
    @GetMapping("/users")
    public Result getUsers() {
        try {
            var users = userService.getAllUsers();
            return Result.success(users);
        } catch (Exception e) {
            log.error("获取用户列表失败", e);
            return Result.error("获取用户列表失败");
        }
    }
}
