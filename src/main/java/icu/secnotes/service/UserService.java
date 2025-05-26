package icu.secnotes.service;

import icu.secnotes.pojo.PageBean;
import icu.secnotes.pojo.User;
import java.util.List;

public interface UserService {
    List<User> selectUserById(String id);

    List<User> selectUserByUsername(String username);

    PageBean<User> pageOrderBy(String orderBy, Integer page, Integer pageSize);

    List<User> selectUserSecByUsername(String username);

    User passwordLogin(User user);

    User passwordLogin2(String username, String password);
}
