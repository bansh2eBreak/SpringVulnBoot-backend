package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Article;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.UnionInjectionService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * UNION 联合注入漏洞演示 - MyBatis 版本
 * 
 * 场景：文章详情查询
 * 
 * ⚠️ UNION 注入特点：
 * 1. 页面有明确的数据回显（能看到查询结果）
 * 2. 使用 UNION 操作符合并多个 SELECT 结果集
 * 3. 可以一次性获取大量敏感数据
 * 4. 是 SQL 注入中最经典、最直接的类型
 * 
 * MyBatis 版本特点：
 * - 使用 ${} 进行字符串拼接（漏洞）
 * - 使用 #{} 进行参数绑定（安全）
 */
@Slf4j
@RequestMapping("/sqli/union/mybatis")
@RestController
@CrossOrigin
@Tag(name = "UNION联合注入-MyBatis", description = "MyBatis类型的UNION注入漏洞演示")
public class UnionInjectionMybatisController {

    @Autowired
    private UnionInjectionService unionInjectionService;

    /**
     * UNION 注入 - 漏洞版本（使用 ${} 拼接）
     * 
     * 场景：根据文章 ID 查询文章详情
     * 漏洞：使用 ${} 直接拼接 SQL，允许使用 UNION 操作符注入额外查询
     * 
     * @Poc1（正常查询）: http://127.0.0.1:8080/sqli/union/mybatis/getArticleVuln?id=1
     *       返回: 文章标题、作者、内容等
     * 
     * @Poc2（测试注入点）: id=1'
     *       返回: SQL 语法错误（说明存在注入点）
     * 
     * @Poc3（判断列数）: id=1 ORDER BY 5
     *       返回: 正常（说明有5列）
     * 
     * @Poc4（确定回显位置）: id=-1 UNION SELECT 1,2,3,4,5
     *       返回: 页面显示 2,3,4,5 的位置
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
        try {
            // 调用 Service 层（使用 ${} 拼接，存在漏洞）
            List<Article> articles = unionInjectionService.getArticleByIdVuln(id);
            
            List<Map<String, Object>> results = new ArrayList<>();
            for (Article article : articles) {
                Map<String, Object> item = new HashMap<>();
                item.put("id", article.getId());
                item.put("title", article.getTitle());
                item.put("author", article.getAuthor());
                item.put("content", article.getContent());
                item.put("create_time", article.getCreateTime());
                results.add(item);
            }
            
            Map<String, Object> data = new HashMap<>();
            data.put("sql", "SELECT id, title, author, content, create_time FROM articles WHERE id = " + id);
            data.put("results", results);
            
            log.warn("【UNION注入漏洞-MyBatis】查询成功，返回 {} 条记录", results.size());
            return Result.success(data);
            
        } catch (Exception e) {
            log.error("【UNION注入漏洞-MyBatis】执行失败: {}", e.getMessage());
            // ⚠️ 漏洞加剧：返回详细错误信息（可能暴露数据库结构）
            return Result.error("查询失败：" + e.getMessage());
        }
    }

    /**
     * UNION 注入 - 安全版本（使用 #{} 参数绑定）
     * 
     * 防御方法：使用 MyBatis 的 #{} 进行参数绑定（预编译）
     * 原理：#{} 底层使用 PreparedStatement，SQL 结构在编译时确定，用户输入仅作为数据值
     * 
     * @param id 文章ID
     * @return 文章详情
     */
    @GetMapping("/getArticleSec")
    public Result getArticleSec(String id) {
        try {
            // 调用 Service 层（使用 #{} 参数绑定，安全）
            List<Article> articles = unionInjectionService.getArticleByIdSec(id);
            
            List<Map<String, Object>> results = new ArrayList<>();
            for (Article article : articles) {
                Map<String, Object> item = new HashMap<>();
                item.put("id", article.getId());
                item.put("title", article.getTitle());
                item.put("author", article.getAuthor());
                item.put("content", article.getContent());
                item.put("create_time", article.getCreateTime());
                results.add(item);
            }
            
            Map<String, Object> data = new HashMap<>();
            data.put("sql", "SELECT id, title, author, content, create_time FROM articles WHERE id = ? (参数: " + id + ")");
            data.put("results", results);
            
            log.info("【安全-MyBatis】查询成功，返回 {} 条记录", results.size());
            return Result.success(data);
            
        } catch (Exception e) {
            log.error("【安全-MyBatis】执行失败: {}", e.getMessage());
            // ✅ 安全实践：不返回详细错误信息
            return Result.error("查询失败，请稍后重试");
        }
    }
}
