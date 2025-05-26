package icu.secnotes.service;

import icu.secnotes.pojo.SmsCode;
import java.time.LocalDateTime;

public interface SmsCodeService {
    /**
     * 生成短信验证码
     * @param smsCode
     */
    void generateCode(SmsCode smsCode);

    void generateCodeByPhoneAndCode(String phone, String code, LocalDateTime createTime, LocalDateTime expireTime);

    /**
     * 更新验证码的使用状态和重试次数，第一次使用更新使用状态，后续每次使用增加重试次数
     * @param smsCode
     */
    void updateSmsCodeUsed(SmsCode smsCode);

    void updateSmsCodeRetryCount(String phone);

    Integer selectRetryCount(String phone);

    /**
     * 验证短信验证码
     * @param phone
     * @param code
     * @return
     */
    SmsCode verifyCode(String phone, String code);

    SmsCode verifyCode2(String phone, String code);

}
