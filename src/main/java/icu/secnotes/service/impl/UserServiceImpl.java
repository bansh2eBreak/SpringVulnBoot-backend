package icu.secnotes.service.impl;

import icu.secnotes.mapper.UserMapper;
import icu.secnotes.pojo.PageBean;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public List<User> selectUserById(String id) {
        return userMapper.selectUserById(id);
    }

    @Override
    public List<User> selectUserByUsername(String username) {
        return userMapper.selectUserByUsername(username);
    }

    @Override
    public PageBean<User> pageOrderBy(String orderBy, Integer page, Integer pageSize) {
        //1.获取总记录数
        int count = userMapper.count();

        //2.获取分页查询结果
        int start = (page - 1) * pageSize;
        List<User> userList = userMapper.pageOrderBy(orderBy, start, pageSize);

        //3.分装PageBean对象
        return new PageBean<>(count, userList);
    }

    @Override
    public List<User> selectUserSecByUsername(String username) {
        return userMapper.selectUserSecByUsername(username);
    }

    @Override
    public User passwordLogin(User user) {
        return userMapper.passwordLogin(user);
    }

    @Override
    public User passwordLogin2(String username, String password) {
        return userMapper.passwordLogin2(username, password);
    }

    @Override
    public int updateUserPassword(User user) {
        return userMapper.updateUserPassword(user);
    }

    @Override
    public List<User> getAllUsers() {
        return userMapper.getAllUsers();
    }
}
