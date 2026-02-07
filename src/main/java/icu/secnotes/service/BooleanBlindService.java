package icu.secnotes.service;

/**
 * 布尔盲注 Service
 */
public interface BooleanBlindService {
    
    /**
     * 使用 ${} 检查用户是否存在（漏洞版本）
     * @param username 用户名
     * @return 用户数量
     */
    int checkUserExistsByDollar(String username);
    
    /**
     * 使用 #{} 检查用户是否存在（安全版本）
     * @param username 用户名
     * @return 用户数量
     */
    int checkUserExistsBySharp(String username);
}
