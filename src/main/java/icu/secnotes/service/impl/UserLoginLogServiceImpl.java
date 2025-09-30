package icu.secnotes.service.impl;

import icu.secnotes.mapper.UserLoginLogMapper;
import icu.secnotes.service.UserLoginLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class UserLoginLogServiceImpl implements UserLoginLogService {

    @Autowired
    private UserLoginLogMapper userLoginLogMapper;

    @Override
    public void insertUserLoginLog(String username, String ip, LocalDateTime loginTime, String loginResult) {
        userLoginLogMapper.insertUserLoginLog(username, ip , loginTime, loginResult);
    }

    @Override
    public void deleteUserLoginLogByIp(String ip) {
        userLoginLogMapper.deleteUserLoginLogByIp(ip);
    }

    @Override
    public int countUserLoginLogByIp(String ip) {
        return userLoginLogMapper.countUserLoginLogByIp(ip);
    }
    
    @Override
    public List<Map<String, Object>> getAllUserLoginLogs() {
        return userLoginLogMapper.getAllUserLoginLogs();
    }
}
