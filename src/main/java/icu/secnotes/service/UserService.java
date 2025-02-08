package icu.secnotes.service;

import icu.secnotes.pojo.PageBean;
import icu.secnotes.pojo.User;
import java.util.List;

public interface UserService {
    List<User> selectUserById(String id);

    List<User> selecctUserByUsername(String username);

    PageBean pageOrderBy(String orderBy, Integer page, Integer pageSize);

    List<User> selecctUserSecByUsername(String username);

    User passwordLogin(User user);

    User passwordLogin2(String username, String password);
}
