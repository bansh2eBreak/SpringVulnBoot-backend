package icu.secnotes.service;

import icu.secnotes.pojo.Admin;

public interface LoginService {
    Admin login(Admin admin);

    Admin getAdminById(String id);
    
    /**
     * 修改密码 - 存在CSRF漏洞（不验证旧密码）
     * @param userId 用户ID
     * @param newPassword 新密码
     * @return 是否修改成功
     */
    boolean changePassword(String userId, String newPassword);
    
    /**
     * 修改密码 - CSRF防护（验证旧密码）
     * @param userId 用户ID
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     * @return 是否修改成功
     */
    boolean changePasswordSecure(String userId, String oldPassword, String newPassword);
    
    /**
     * 验证旧密码
     * @param userId 用户ID
     * @param oldPassword 旧密码
     * @return 是否验证成功
     */
    boolean verifyOldPassword(String userId, String oldPassword);
}
