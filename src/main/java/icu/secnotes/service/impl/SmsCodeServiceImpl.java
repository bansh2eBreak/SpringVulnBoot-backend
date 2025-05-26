package icu.secnotes.service.impl;

import icu.secnotes.mapper.SmsCodeMapper;
import icu.secnotes.pojo.SmsCode;
import icu.secnotes.service.SmsCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class SmsCodeServiceImpl implements SmsCodeService {

    @Autowired
    private SmsCodeMapper smsCodeMapper;

    @Override
    public void generateCode(SmsCode smsCode) {
        smsCodeMapper.insertSmsCode(smsCode);
    }

    @Override
    public void generateCodeByPhoneAndCode(String phone, String code, LocalDateTime createTime, LocalDateTime expireTime) {
        smsCodeMapper.insertSmsCodeByPhoneAndCode(phone, code, createTime, expireTime);
    }

    @Override
    public void updateSmsCodeUsed(SmsCode smsCode) {
        smsCodeMapper.updateSmsCodeUsed(smsCode);
    }

    @Override
    public void updateSmsCodeRetryCount(String phone) {
        smsCodeMapper.updateSmsCodeRetryCount(phone);
    }

    @Override
    public Integer selectRetryCount(String phone) {
        return smsCodeMapper.selectRetryCount(phone);
    }

    @Override
    public SmsCode verifyCode(String phone, String code) {
        return smsCodeMapper.selectByPhoneAndCode(phone, code);
    }

    @Override
    public SmsCode verifyCode2(String phone, String code) {
        return smsCodeMapper.selectByPhoneAndCode2(phone, code);
    }

}
