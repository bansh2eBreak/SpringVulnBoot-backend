package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * sql注入漏洞-jdbc
 */
@Slf4j
@RequestMapping("/sqli/jdbc")
@RestController
public class JdbcController {

    @Value("${spring.datasource.url}")
    private String db_url;

    @Value("${spring.datasource.username}")
    private String db_user;

    @Value("${spring.datasource.password}")
    private String db_pass;

    /**
     * Jdbc：数字型sql注入-普通参数
     * @Poc http://127.0.0.1:8080/sqli/jdbc/getUserById?id=1 or 1=1
     * @param id
     * @return
     * @throws Exception
     */
    @GetMapping("/getUserById")
    public Result getUserById(String id) throws Exception {
        List<User> users = new ArrayList<>();

        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

        //3.定义sql语句
        String sql = "select id, username, name from user where id = " + id;

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
            
            users.add(user);
        }
        resultSet.close();
        statement.close();
        conn.close();
        return Result.success(users);
    }

    /**
     * Jdbc：字符串型sql注入-普通参数
     * @Poc http://127.0.0.1:8080/sqli/jdbc/getUserByUsername?username=zhangsan' or 1=1 --
     * @param username
     * @return
     * @throws Exception
     */
    @GetMapping("/getUserByUsername")
    public Result getUserByUsername(String username) throws Exception {
        List<User> users = new ArrayList<>();

        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

        //3.定义sql语句
        String sql = "select id, username, name, password from user where username = '" + username + "'";

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
    }

    /**
     * Jdbc：数字型sql注入-普通参数
     * @Poc http://127.0.0.1:8080/sqli/jdbc/getUserById?id=1 or 1=1
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

            //3.定义sql语句
            String sql = "select id, username, name from user where id = " + id;
            log.info("sql语句被执行: {}", sql);

            //4.获取statement对象
            Statement statement = conn.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);

            //5.判断是否查询到数据
            while (resultSet.next()) {
                User user = new User();
                user.setId(resultSet.getInt("id"));
                user.setName(resultSet.getString("name"));
                user.setUsername(resultSet.getString("username"));

                users.add(user);
            }
            resultSet.close();
            statement.close();
            conn.close();
            return Result.success(users);
        } catch (Exception e) {
            return Result.error(e.toString());
        }
    }

    /**
     * Jdbc：数字型sql注入-预编译参数
     * @Poc http://
     */
    @GetMapping("/getUserSecById")
    public Result getUserSecById(String id) throws Exception {
        List<User> users = new ArrayList<>();

        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

        //3.定义sql语句
        String sql = "select id, username, name from user where id = ?";

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

            users.add(user);
        }
        resultSet.close();
        preparedStatement.close();
        conn.close();
        return Result.success(users);
    }

    /**
     * Jdbc：字符串型sql注入-恶意字符过滤
     */
     @GetMapping("/getUserSecByUsernameFilter")
     public Result getUserByUsernameFilter(String username) throws Exception {
         if (!Security.checkSql(username)) {
             List<User> users = new ArrayList<>();
             //1、注册驱动
             Class.forName("com.mysql.cj.jdbc.Driver");

             //2.获取连接
             Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

             //3.定义sql语句
             String sql = "select id, username, name from user where username = '" + username + "'";

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

                 users.add(user);
             }
             resultSet.close();
             statement.close();
             conn.close();
             return Result.success(users);
         } else {
             log.warn("检测到非法注入字符: {}", username);
             return Result.error("检测到非法注入字符");
         }
    }

    /**
     * Jdbc：字符串型sql注入-预编译参数
     * @Poc http://
     */
    @GetMapping("/getUserSecByUsername")
    public Result getUserSecByUsername(String username) throws Exception {
        List<User> users = new ArrayList<>();

        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

        //3.定义sql语句
        String sql = "select id, username, name from user where username = ?";

        //4.获取statement对象
        PreparedStatement preparedStatement = conn.prepareStatement(sql);
        preparedStatement.setString(1, username);
        ResultSet resultSet = preparedStatement.executeQuery();
        log.info("sql语句被执行: {}", sql);

        //5.判断是否查询到数据
        while (resultSet.next()) {
            User user = new User();
            user.setId(resultSet.getInt("id"));
            user.setName(resultSet.getString("name"));
            user.setUsername(resultSet.getString("username"));

            users.add(user);
        }
        resultSet.close();
        preparedStatement.close();
        conn.close();
        return Result.success(users);
    }

    /**
     * Jdbc：字符串型sql注入-预编译参数-但未使用占位符
     */
    @GetMapping("/getUserSecByUsernameError")
    public Result getUserSecByUsernameError(String username) throws Exception {
        List<User> users = new ArrayList<>();

        //1、注册驱动
        Class.forName("com.mysql.cj.jdbc.Driver");

        //2.获取连接
        Connection conn = DriverManager.getConnection(db_url, db_user, db_pass);

        //3.定义sql语句
        String sql = "select id, username, name, password from user where username = '" + username + "'";

        //4.获取statement对象
        PreparedStatement preparedStatement = conn.prepareStatement(sql);
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
    }
}
