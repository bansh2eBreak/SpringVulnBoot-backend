package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * SQL注入漏洞 - 报错注入
 */
@Slf4j
@RequestMapping("/sqli/error")
@RestController
public class ErrorInjectionController {

    @Value("${spring.datasource.url}")
    private String db_url;

    @Value("${spring.datasource.username}")
    private String db_user;

    @Value("${spring.datasource.password}")
    private String db_pass;

    /**
     * updatexml报错注入 - 字符串型
     * @Poc http://127.0.0.1:8080/sqli/error/getUserByUsernameError?username=zhangsan' and updatexml(1,concat(0x7e,(select database()),0x7e),1) --
     * @param username
     * @return
     * @throws Exception
     */
    @GetMapping("/getUserByUsernameError")
    public Result getUserByUsernameError(String username) throws Exception {
        List<User> users = new ArrayList<>();

        try {
            //1、注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");

            //2.获取连接
            Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

            //3.定义sql语句 - 存在报错注入
            String sql = "select * from user where username = '" + username + "'";

            //4.获取statement对象
            Statement statement = conn.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            log.info("sql语句被执行: {}", sql);

            //5.判断是否查询到数据
            while (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getInt("id"));
                user.setName(resultSet.getString("name"));
                user.setUsername(resultSet.getString("username"));
                user.setPassword(resultSet.getString("password"));
                users.add(user);
            }
            resultSet.close();
            statement.close();
            conn.close();
            return Result.success(users);
        } catch (Exception e) {
            // 错误信息直接返回，存在信息泄露
            log.error("数据库查询异常", e);
            return Result.success("查询失败: " + e.getMessage());
        }
    }

    /**
     * extractvalue报错注入 - 数字型
     * @Poc http://127.0.0.1:8080/sqli/error/getUserByIdError?id=1 and extractvalue(1,concat(0x7e,(select version()),0x7e))
     * @param id
     * @return
     * @throws Exception
     */
    @GetMapping("/getUserByIdError")
    public Result getUserByIdError(String id) throws Exception {
        List<User> users = new ArrayList<>();

        try {
            //1、注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");

            //2.获取连接
            Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

            //3.定义sql语句 - 存在报错注入
            String sql = "select * from user where id = " + id;

            //4.获取statement对象
            Statement statement = conn.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            log.info("sql语句被执行: {}", sql);

            //5.判断是否查询到数据
            while (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getInt("id"));
                user.setName(resultSet.getString("name"));
                user.setUsername(resultSet.getString("username"));
                user.setPassword(resultSet.getString("password"));
                users.add(user);
            }
            resultSet.close();
            statement.close();
            conn.close();
            return Result.success(users);
        } catch (Exception e) {
            // 错误信息直接返回，存在信息泄露
            log.error("数据库查询异常", e);
            return Result.success("查询失败: " + e.getMessage());
        }
    }

    /**
     * 安全版本 - 使用预编译语句
     * @param username
     * @return
     * @throws Exception
     */
    @GetMapping("/getUserSecByUsername")
    public Result getUserSecByUsername(String username) throws Exception {
        List<User> users = new ArrayList<>();

        try {
            //1、注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");

            //2.获取连接
            Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

            //3.定义sql语句 - 非预编译，直接拼接
            String sql = "select * from user where username = '" + username + "'";

            //4.获取statement对象
            Statement statement = conn.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            log.info("sql语句被执行: {}", sql);

            //5.判断是否查询到数据
            while (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getInt("id"));
                user.setName(resultSet.getString("name"));
                user.setUsername(resultSet.getString("username"));
                user.setPassword(resultSet.getString("password"));
                users.add(user);
            }

            resultSet.close();
            statement.close();
            conn.close();
            return Result.success(users);
        } catch (Exception e) {
            // 统一错误处理，不泄露详细信息
            log.error("数据库查询异常", e);
            return Result.success("系统繁忙，请稍后重试");
        }
    }

    /**
     * 安全版本 - 数字型预编译
     * @param id
     * @return
     * @throws Exception
     */
    @GetMapping("/getUserSecById")
    public Result getUserSecById(String id) throws Exception {
        List<User> users = new ArrayList<>();

        try {
            //1、注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");

            //2.获取连接
            Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

            //3.定义sql语句 - 使用预编译
            String sql = "select * from user where id = ?";

            //4.获取statement对象
            PreparedStatement preparedStatement = conn.prepareStatement(sql);
            preparedStatement.setInt(1, Integer.parseInt(id));
            ResultSet resultSet = preparedStatement.executeQuery();
            log.info("sql语句被执行: {}", sql);

            //5.判断是否查询到数据
            while (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getInt("id"));
                user.setName(resultSet.getString("name"));
                user.setUsername(resultSet.getString("username"));
                user.setPassword(resultSet.getString("password"));
                users.add(user);
            }
            resultSet.close();
            preparedStatement.close();
            conn.close();
            return Result.success(users);
        } catch (Exception e) {
            // 统一错误处理，不泄露详细信息
            log.error("数据库查询异常", e);
            return Result.error("系统繁忙，请稍后重试");
        }
    }
} 