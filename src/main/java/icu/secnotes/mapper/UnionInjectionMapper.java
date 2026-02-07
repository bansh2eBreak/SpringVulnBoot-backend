package icu.secnotes.mapper;

import icu.secnotes.pojo.Article;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

/**
 * UNION 联合注入 Mapper
 * 
 * 演示 MyBatis 中 ${} 和 #{} 在 UNION 注入场景下的安全差异
 */
@Mapper
public interface UnionInjectionMapper {
    
    /**
     * 使用 ${} 查询文章（漏洞版本）
     * 
     * ⚠️ 漏洞原因：
     * 1. ${} 是字符串替换，直接将参数值拼接到 SQL 中
     * 2. 不进行任何转义和预编译，相当于 JDBC 的字符串拼接
     * 3. 攻击者可以注入 UNION SELECT 语句，获取其他表的数据
     * 
     * 示例：
     * - 正常输入：id = "1"
     *   生成SQL：SELECT id, title, author, content, create_time FROM articles WHERE id = 1
     * 
     * - 恶意输入：id = "-1 UNION SELECT 1,username,password,avatar,5 FROM admin"
     *   生成SQL：SELECT id, title, author, content, create_time FROM articles WHERE id = -1 UNION SELECT 1,username,password,avatar,5 FROM admin
     *   结果：返回所有管理员的账号密码！
     * 
     * @param id 文章ID
     * @return 文章列表
     */
    @Select("SELECT id, title, author, content, create_time FROM articles WHERE id = ${id}")
    List<Article> getArticleByIdVuln(@Param("id") String id);
    
    /**
     * 使用 #{} 查询文章（安全版本）
     * 
     * ✅ 安全原因：
     * 1. #{} 是参数绑定，底层使用 PreparedStatement
     * 2. 自动进行 SQL 预编译和参数转义
     * 3. 用户输入仅作为数据值，无法改变 SQL 结构
     * 
     * 示例：
     * - 正常输入：id = "1"
     *   预编译SQL：SELECT id, title, author, content, create_time FROM articles WHERE id = ?
     *   参数绑定：setString(1, "1")
     * 
     * - 恶意输入：id = "-1 UNION SELECT 1,username,password,avatar,5 FROM admin"
     *   预编译SQL：SELECT id, title, author, content, create_time FROM articles WHERE id = ?
     *   参数绑定：setString(1, "-1 UNION SELECT 1,username,password,avatar,5 FROM admin")
     *   结果：整个字符串被当作 ID 查询，找不到结果，注入失败！
     * 
     * @param id 文章ID
     * @return 文章列表
     */
    @Select("SELECT id, title, author, content, create_time FROM articles WHERE id = #{id}")
    List<Article> getArticleByIdSec(@Param("id") String id);
}
