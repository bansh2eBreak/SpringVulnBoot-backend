package icu.secnotes.service.impl;

import icu.secnotes.mapper.UserLoginLogMapper;
import icu.secnotes.service.UserLoginLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class UserLoginLogServiceImpl implements UserLoginLogService {

    @Autowired
    private UserLoginLogMapper userLoginLogMapper;

    @Override
    public void insertUserLoginLog(String username, String ip, LocalDateTime loginTime) {
        userLoginLogMapper.insertUserLoginLog(username, ip , loginTime);
    }

    @Override
    public void deleteUserLoginLogByIp(String ip) {
        userLoginLogMapper.deleteUserLoginLogByIp(ip);
    }

    @Override
    public int countUserLoginLogByIp(String ip) {
        return userLoginLogMapper.countUserLoginLogByIp(ip);
    }
}
