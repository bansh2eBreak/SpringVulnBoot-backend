package icu.secnotes.service;

import icu.secnotes.pojo.Admin;

public interface LoginService {
    Admin login(Admin admin);

    Admin getAdminById(String id);
    
    /**
     * 修改密码 - 二次注入版本（通过 username）
     * @param username 用户名
     * @param newPassword 新密码
     * @return 影响的行数
     */
    int changePassword(String username, String newPassword);
    
    /**
     * 修改密码 - CSRF演示版本（通过 userId，不验证旧密码）
     * @param userId 用户ID
     * @param newPassword 新密码
     * @return 是否修改成功
     */
    boolean changePasswordByUserId(String userId, String newPassword);
    
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
    
    /**
     * 更新管理员信息（用于 Mass Assignment 漏洞演示）
     * @param admin 管理员对象
     * @return 是否更新成功
     */
    boolean updateAdmin(Admin admin);
    
    /**
     * 检查用户名是否存在
     * @param username 用户名
     * @return 是否存在
     */
    boolean checkUsernameExists(String username);
    
    /**
     * 用户注册
     * @param admin 用户信息
     * @return 是否注册成功
     */
    boolean register(Admin admin);
}
