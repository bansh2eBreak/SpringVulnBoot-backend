package icu.secnotes.service;

import java.time.LocalDateTime;

public interface UserLoginLogService {

    void insertUserLoginLog(String username, String ip, LocalDateTime loginTime);

    void deleteUserLoginLogByIp(String ip);

    int countUserLoginLogByIp(String ip);
}
