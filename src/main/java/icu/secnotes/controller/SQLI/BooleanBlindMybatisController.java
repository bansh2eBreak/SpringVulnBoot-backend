package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.BooleanBlindService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

/**
 * 布尔盲注漏洞 - MyBatis版本
 * 
 * 场景：用户注册时检查用户名是否已存在
 * 
 * ⚠️ 布尔盲注（Boolean-Based Blind SQL Injection）特点：
 * 1. 应用程序只返回"真"或"假"两种状态（如"用户名已存在"/"用户名可用"）
 * 2. 不直接返回数据库数据，无法使用 UNION 等直接注入
 * 3. 攻击者通过构造条件判断语句（如 AND/OR），根据返回的布尔值推断数据库信息
 * 4. 典型利用：逐字符猜测数据（如用户密码、表名等）
 * 
 * MyBatis 版本特点：
 * - 使用 ${} 进行字符串拼接（漏洞）
 * - 使用 #{} 进行参数绑定（安全）
 */
@Slf4j
@RequestMapping("/sqli/boolean/mybatis")
@RestController
@CrossOrigin
@Tag(name = "布尔盲注-MyBatis", description = "MyBatis类型的布尔盲注漏洞演示")
public class BooleanBlindMybatisController {

    @Autowired
    private BooleanBlindService booleanBlindService;

    /**
     * 布尔盲注 - 漏洞版本（使用 ${} 拼接）
     * 
     * 场景：用户注册时检查用户名是否已被占用
     * 漏洞：使用 ${} 直接拼接 SQL，允许注入条件判断语句
     * 
     * @Poc1（正常）: http://127.0.0.1:8080/sqli/boolean/mybatis/checkUserExistsVuln?username=admin
     *       返回: { "exists": true, "message": "用户名已存在" }
     * 
     * @Poc2（布尔盲注 - 猜测 admin 密码第1位是否为 '1'）:
     *       username=admin' AND SUBSTRING(password,1,1)='1' -- 
     *       如果返回 exists=true，说明密码第1位是 '1'
     *       如果返回 exists=false，说明密码第1位不是 '1'
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
        try {
            // 调用 Service 层（使用 ${} 拼接，存在漏洞）
            int count = booleanBlindService.checkUserExistsByDollar(username);
            
            boolean exists = count > 0;
            
            Map<String, Object> data = new HashMap<>();
            data.put("exists", exists);
            data.put("message", exists ? "❌ 用户名已存在" : "✅ 用户名可用");
            data.put("sql", "SELECT COUNT(*) FROM admin WHERE username = '" + username + "'");
            
            log.warn("【布尔盲注漏洞-MyBatis】查询结果: count={}, exists={}", count, exists);
            return Result.success(data);
            
        } catch (Exception e) {
            log.error("【布尔盲注漏洞-MyBatis】执行失败: {}", e.getMessage());
            // ⚠️ 漏洞加剧：直接返回详细错误信息（可能暴露数据库结构）
            return Result.error("查询失败：" + e.getMessage());
        }
    }

    /**
     * 布尔盲注 - 安全版本（使用 #{} 参数绑定）
     * 
     * 防御方法：使用 MyBatis 的 #{} 进行参数绑定（预编译）
     * 原理：#{} 底层使用 PreparedStatement，SQL 结构在编译时确定，用户输入仅作为数据值
     * 
     * @param username 用户名
     * @return 用户名是否存在
     */
    @GetMapping("/checkUserExistsSec")
    public Result checkUserExistsSec(String username) {
        try {
            // 调用 Service 层（使用 #{} 参数绑定，安全）
            int count = booleanBlindService.checkUserExistsBySharp(username);
            
            boolean exists = count > 0;
            
            Map<String, Object> data = new HashMap<>();
            data.put("exists", exists);
            data.put("message", exists ? "❌ 用户名已存在" : "✅ 用户名可用");
            data.put("sql", "SELECT COUNT(*) FROM admin WHERE username = ? (参数: " + username + ")");
            
            log.info("【安全-MyBatis】查询结果: count={}, exists={}", count, exists);
            return Result.success(data);
            
        } catch (Exception e) {
            log.error("【安全-MyBatis】执行失败: {}", e.getMessage());
            // ✅ 安全实践：不返回详细错误信息
            return Result.error("查询失败，请稍后重试");
        }
    }
}
