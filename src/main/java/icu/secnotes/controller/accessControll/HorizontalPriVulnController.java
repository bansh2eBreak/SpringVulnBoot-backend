package icu.secnotes.controller.accessControll;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import icu.secnotes.pojo.MfaSecret;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.MfaSecretService;
import icu.secnotes.utils.GoogleAuthenticatorUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import java.time.LocalDateTime;

@Controller
@Slf4j
@RequestMapping("/accessControl/HorizontalPri")
public class HorizontalPriVuln {

    @Autowired
    private MfaSecretService mfaSecretService;

    /**
     * 用户绑定MFA密钥
     * @param mfaSecret
     * @return
     */
    @PostMapping("/bindMfa")
    public Result bindMfaSecret(@RequestBody MfaSecret mfaSecret) {
        // 检查用户是否已有MFA密钥
        MfaSecret existingSecret = mfaSecretService.getSecretByUserId(mfaSecret.getUserId());
        if (existingSecret != null) {
            // 表示用户已绑定MFA
            return Result.error("用户已经绑定过MFA");
        }

        // 生成google mfa secreate
        GoogleAuthenticatorKey credentials = GoogleAuthenticatorUtil.createCredentials();
        String secret = credentials.getKey();
        log.info("生成的MFA密钥: {}", secret);

        // 设置GoogleAuthenticatorKey
        mfaSecret.setSecret(secret);

        // 设置创建时间为当前，update_time为null
        mfaSecret.setCreateTime(LocalDateTime.now());

        Integer res = mfaSecretService.createMfaSecret(mfaSecret);

        // 进行判断
        if (res > 0) {
            // 表示用户mfa生成成功
            return Result.success("用户MFA绑定成功");
        } else {
            // 表示用户mfa生成成功
            return Result.error("用户MFA绑定失败");
        }
    }

}
