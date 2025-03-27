package icu.secnotes.controller.Authentication;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.SmsCode;
import icu.secnotes.service.SmsCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/authentication/smsBased")
public class SmsBasedAuthVulnController {

    @Autowired
    private SmsCodeService smsCodeService;

    // 发送短信接口:接口直接将验证码返回给前端 + 短信轰炸
    @PostMapping("/sendVuln1")
    public Result sendVuln1(@Valid @RequestBody SmsCode smsCode) {
        // 生成四位随机数作为验证码
        smsCode.setCode(String.valueOf((int) ((Math.random() * 9 + 1) * 1000)));
        // 设置验证码的创建时间为当前时间
        smsCode.setCreateTime(LocalDateTime.now());
        // 设置验证码的过期时间为当前时间加5分钟
        smsCode.setExpireTime(LocalDateTime.now().plusMinutes(5));
        // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
        smsCodeService.generateCode(smsCode);
        return Result.success("短信验证码已发送，" + smsCode.getCode());
    }

    // 发送短信接口:验证码不返回给前端 + 短信轰炸
    @PostMapping("/sendSafe1")
    public Result sendSafe1(@Valid @RequestBody SmsCode smsCode) {
        // 生成四位随机数作为验证码
        smsCode.setCode(String.valueOf((int) ((Math.random() * 9 + 1) * 1000)));
        // 设置验证码的创建时间为当前时间
        smsCode.setCreateTime(LocalDateTime.now());
        // 设置验证码的过期时间为当前时间加5分钟
        smsCode.setExpireTime(LocalDateTime.now().plusMinutes(5));
        // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
        smsCodeService.generateCode(smsCode);
        return Result.success("短信验证码已发送");
    }

    // 发送短信接口:图形验证码防短信轰炸
    @PostMapping("/sendSafe2")
    public Result sendSafe2(@RequestParam String phone, @RequestParam String captcha, HttpServletRequest request) {

        //获取服务端生成的验证码
        HttpSession session = request.getSession();
        System.out.println("读取时候的session对象" + session);
        // 从 Session 中获取验证码
        System.out.println("登录接口-------》提交的验证码：" + captcha);
        System.out.println("登录接口-------》Stored captcha in session: " + session.getAttribute("captcha"));
        String sessionCaptcha = (String) request.getSession().getAttribute("captcha");
        // 校验验证码
        if (sessionCaptcha == null || !sessionCaptcha.equalsIgnoreCase(captcha)) {
            return Result.success("图形验证码错误");
        }

        // 清除验证码
        session.removeAttribute("captcha");


        // 生成四位随机数作为验证码
        String smsCode = String.valueOf((int) ((Math.random() * 9 + 1) * 1000));
        // 设置验证码的创建时间为当前时间
        LocalDateTime createTime = LocalDateTime.now();
        // 设置验证码的过期时间为当前时间加5分钟
        LocalDateTime expireTime = LocalDateTime.now().plusMinutes(5);

        // 验证的使用状态和重试次数默认是0，所以生成验证码的时候可以不设置
        smsCodeService.generateCodeByPhoneAndCode(phone, smsCode, createTime, expireTime);
        return Result.success("短信验证码已发送");
    }

    // 验证短信接口:验证码未限制校验次数，可以暴力破解验证码
    @PostMapping("/verifyVuln1")
    public Result verifyVuln1(@Valid @RequestBody SmsCode smsCode) {
        SmsCode code = smsCodeService.verifyCode(smsCode.getPhone(), smsCode.getCode());
        if (code != null) {
            // 设置验证码为已使用
            smsCodeService.updateSmsCodeUsed(smsCode);
            return Result.success();
        } else {
            return Result.error("验证码错误");
        }
    }

    // 验证短信接口:验证码校验次数限制，防止暴力破解
    @PostMapping("/verifySafe1")
    public Result verifySafe1(@Valid @RequestBody SmsCode smsCode) {
        SmsCode code = smsCodeService.verifyCode(smsCode.getPhone(), smsCode.getCode());
        if (code != null) {
            // 设置验证码为已使用
            smsCodeService.updateSmsCodeUsed(smsCode);
            return Result.success();
        } else {
            // 更新验证码的重试次数
            smsCodeService.updateSmsCodeRetryCount(smsCode.getPhone());
            // 做一个判断，如果验证码的重试次数小于5，返回验证码错误，否则返回错误次数过多
            if (smsCodeService.selectRetryCount(smsCode.getPhone()) < 5) {
                return Result.error("验证码错误");
            } else {
                return Result.error("错误次数过多，请重新获取短信验证码");
            }
        }
    }

    // 验证短信接口:验证码可重复使用
    @PostMapping("/verifyVuln2")
    public Result verifyVuln2(@Valid @RequestBody SmsCode smsCode) {
        // 虽然验证成功后修改了验证码未已使用，但是查询的时候并没有校验使用状态
        SmsCode code = smsCodeService.verifyCode2(smsCode.getPhone(), smsCode.getCode());
        if (code != null) {
            // 设置验证码为已使用
            smsCodeService.updateSmsCodeUsed(smsCode);
            return Result.success();
        } else {
            return Result.error("验证码错误");
        }
    }
}
