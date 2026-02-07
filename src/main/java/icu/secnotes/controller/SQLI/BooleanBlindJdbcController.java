package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Result;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

/**
 * 布尔盲注漏洞 - JDBC版本
 * 
 * 场景：用户注册时检查用户名是否已存在
 * 
 * ⚠️ 布尔盲注（Boolean-Based Blind SQL Injection）特点：
 * 1. 应用程序只返回"真"或"假"两种状态（如"用户名已存在"/"用户名可用"）
 * 2. 不直接返回数据库数据，无法使用 UNION 等直接注入
 * 3. 攻击者通过构造条件判断语句（如 AND/OR），根据返回的布尔值推断数据库信息
 * 4. 典型利用：逐字符猜测数据（如用户密码、表名等）
 * 
 * 与时间盲注的区别：
 * - 布尔盲注：根据页面返回内容差异判断（快速）
 * - 时间盲注：根据响应时间判断（慢速，用于无任何回显的场景）
 */
@Slf4j
@RequestMapping("/sqli/boolean/jdbc")
@RestController
@CrossOrigin
@Tag(name = "布尔盲注-JDBC", description = "JDBC类型的布尔盲注漏洞演示")
public class BooleanBlindJdbcController {

    @Value("${spring.datasource.url}")
    private String db_url;

    @Value("${spring.datasource.username}")
    private String db_user;

    @Value("${spring.datasource.password}")
    private String db_pass;

    /**
     * 布尔盲注 - 漏洞版本（字符串拼接）
     * 
     * 场景：用户注册时检查用户名是否已被占用
     * 漏洞：直接拼接 SQL，允许注入条件判断语句
     * 
     * @Poc1（正常）: http://127.0.0.1:8080/sqli/boolean/jdbc/checkUserExistsVuln?username=admin
     *       返回: { "exists": true, "message": "用户名已存在" }
     * 
     * @Poc2（布尔盲注 - 猜测 admin 密码第1位是否为 'a'）:
     *       username=admin' AND SUBSTRING(password,1,1)='a' -- 
     *       如果返回 exists=true，说明密码第1位是 'a'
     *       如果返回 exists=false，说明密码第1位不是 'a'
     * 
     * @Poc3（布尔盲注 - 猜测 admin 密码长度是否 >= 30）:
     *       username=admin' AND LENGTH(password)>=30 -- 
     *       返回值判断密码长度范围
     * 
     * @Poc4（布尔盲注 - 猜测数据库版本）:
     *       username=admin' AND SUBSTRING(VERSION(),1,1)='8' -- 
     *       判断 MySQL 版本第一位是否为 '8'
     * 
     * @param username 用户名
     * @return 用户名是否存在
     */
    @GetMapping("/checkUserExistsVuln")
    public Result checkUserExistsVuln(String username) {
        Connection conn = null;
        Statement statement = null;
        ResultSet resultSet = null;
        
        try {
            // 1. 注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");
            
            // 2. 获取连接
            conn = DriverManager.getConnection(db_url, db_user, db_pass);
            
            // 3. 拼接 SQL（漏洞点）
            String sql = "SELECT COUNT(*) as count FROM admin WHERE username = '" + username + "'";
            
            log.warn("【布尔盲注漏洞】执行SQL: {}", sql);
            
            // 4. 执行查询
            statement = conn.createStatement();
            resultSet = statement.executeQuery(sql);
            
            // 5. 判断用户是否存在
            if (resultSet.next()) {
                int count = resultSet.getInt("count");
                boolean exists = count > 0;
                
                Map<String, Object> data = new HashMap<>();
                data.put("exists", exists);
                data.put("message", exists ? "❌ 用户名已存在" : "✅ 用户名可用");
                data.put("sql", sql);  // 返回执行的 SQL 供前端展示
                
                log.warn("【布尔盲注漏洞】查询结果: count={}, exists={}", count, exists);
                return Result.success(data);
            }
            
            return Result.error("查询失败");
            
        } catch (Exception e) {
            log.error("【布尔盲注漏洞】执行失败: {}", e.getMessage());
            // ⚠️ 漏洞加剧：直接返回详细错误信息（可能暴露数据库结构）
            return Result.error("查询失败：" + e.getMessage());
        } finally {
            // 6. 关闭资源
            try {
                if (resultSet != null) resultSet.close();
                if (statement != null) statement.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                log.error("关闭连接失败", e);
            }
        }
    }

    /**
     * 布尔盲注 - 安全版本（预编译）
     * 
     * 防御方法：使用 PreparedStatement 预编译 + 参数绑定
     * 原理：SQL 语句结构在编译时就已确定，用户输入仅作为数据值，无法改变 SQL 逻辑
     * 
     * @param username 用户名
     * @return 用户名是否存在
     */
    @GetMapping("/checkUserExistsSec")
    public Result checkUserExistsSec(String username) {
        Connection conn = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        
        try {
            // 1. 注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");
            
            // 2. 获取连接
            conn = DriverManager.getConnection(db_url, db_user, db_pass);
            
            // 3. 使用预编译（安全点）
            String sql = "SELECT COUNT(*) as count FROM admin WHERE username = ?";
            
            log.info("【安全】执行SQL: {}, 参数: {}", sql, username);
            
            // 4. 参数绑定
            preparedStatement = conn.prepareStatement(sql);
            preparedStatement.setString(1, username);  // 自动转义特殊字符
            
            // 5. 执行查询
            resultSet = preparedStatement.executeQuery();
            
            // 6. 判断用户是否存在
            if (resultSet.next()) {
                int count = resultSet.getInt("count");
                boolean exists = count > 0;
                
                Map<String, Object> data = new HashMap<>();
                data.put("exists", exists);
                data.put("message", exists ? "❌ 用户名已存在" : "✅ 用户名可用");
                data.put("sql", sql + " (参数: " + username + ")");
                
                log.info("【安全】查询结果: count={}, exists={}", count, exists);
                return Result.success(data);
            }
            
            return Result.error("查询失败");
            
        } catch (Exception e) {
            log.error("【安全】执行失败: {}", e.getMessage());
            // ✅ 安全实践：不返回详细错误信息
            return Result.error("查询失败，请稍后重试");
        } finally {
            // 7. 关闭资源
            try {
                if (resultSet != null) resultSet.close();
                if (preparedStatement != null) preparedStatement.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                log.error("关闭连接失败", e);
            }
        }
    }
}
