package icu.secnotes.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public interface UserLoginLogService {

    void insertUserLoginLog(String username, String ip, LocalDateTime loginTime, String loginResult);

    void deleteUserLoginLogByIp(String ip);

    int countUserLoginLogByIp(String ip);
    
    List<Map<String, Object>> getAllUserLoginLogs();
}
