package icu.secnotes.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

/**
 * 布尔盲注 Mapper
 * 
 * 演示 MyBatis 中 ${} 和 #{} 的安全差异
 */
@Mapper
public interface BooleanBlindMapper {
    
    /**
     * 使用 ${} 检查用户是否存在（漏洞版本）
     * 
     * ⚠️ 漏洞原因：
     * 1. ${} 是字符串替换，直接将参数值拼接到 SQL 中
     * 2. 不进行任何转义和预编译，相当于 JDBC 的字符串拼接
     * 3. 攻击者可以注入任意 SQL 语句
     * 
     * 示例：
     * - 正常输入：username = "admin"
     *   生成SQL：SELECT COUNT(*) FROM admin WHERE username = 'admin'
     * 
     * - 恶意输入：username = "admin' AND SUBSTRING(password,1,1)='1' -- "
     *   生成SQL：SELECT COUNT(*) FROM admin WHERE username = 'admin' AND SUBSTRING(password,1,1)='1' -- '
     * 
     * @param username 用户名
     * @return 用户数量
     */
    @Select("SELECT COUNT(*) FROM admin WHERE username = '${username}'")
    int checkUserExistsByDollar(@Param("username") String username);
    
    /**
     * 使用 #{} 检查用户是否存在（安全版本）
     * 
     * ✅ 安全原因：
     * 1. #{} 是参数绑定，底层使用 PreparedStatement
     * 2. 自动进行 SQL 预编译和参数转义
     * 3. 用户输入仅作为数据值，无法改变 SQL 结构
     * 
     * 示例：
     * - 正常输入：username = "admin"
     *   预编译SQL：SELECT COUNT(*) FROM admin WHERE username = ?
     *   参数绑定：setString(1, "admin")
     * 
     * - 恶意输入：username = "admin' AND SUBSTRING(password,1,1)='1' -- "
     *   预编译SQL：SELECT COUNT(*) FROM admin WHERE username = ?
     *   参数绑定：setString(1, "admin' AND SUBSTRING(password,1,1)='1' -- ")
     *   结果：整个字符串被当作用户名查询，注入失败
     * 
     * @param username 用户名
     * @return 用户数量
     */
    @Select("SELECT COUNT(*) FROM admin WHERE username = #{username}")
    int checkUserExistsBySharp(@Param("username") String username);
}
