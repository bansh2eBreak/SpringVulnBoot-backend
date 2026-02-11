package icu.secnotes.service;

import icu.secnotes.pojo.PageBean;
import icu.secnotes.pojo.User;
import java.util.List;

public interface UserService {
    List<User> selectUserById(String id);

    List<User> selectUserByUsername(String username);

    /**
     * ORDER BY 注入 - 漏洞版本（使用 ${}）
     */
    PageBean<User> pageOrderByVuln(String orderBy, Integer page, Integer pageSize);

    List<User> selectUserSecByUsername(String username);

    User passwordLogin(User user);

    User passwordLogin2(String username, String password);

    // 新增方法：更新用户密码
    int updateUserPassword(User user);

    // 新增方法：获取所有用户
    List<User> getAllUsers();
}
