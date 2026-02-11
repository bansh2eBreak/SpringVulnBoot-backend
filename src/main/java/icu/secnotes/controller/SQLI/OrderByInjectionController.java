package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.PageBean;
import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import icu.secnotes.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * ORDER BY 注入漏洞演示
 * 
 * 核心特点：
 * 1. ORDER BY 子句无法使用预编译（PreparedStatement）
 * 2. 必须使用字符串拼接或 MyBatis 的 ${}
 * 3. 容易被忽视的注入点
 * 
 * @author SecNotes
 */
@RestController
@RequestMapping("/sqli/orderby")
@Slf4j
@CrossOrigin
@Tag(name = "ORDER BY 注入", description = "ORDER BY 排序参数注入漏洞演示")
public class OrderByInjectionController {

    @Autowired
    private UserService userService;

    /**
     * 漏洞版本1：直接拼接 ORDER BY（最危险）
     * 
     * 漏洞原理：
     * - orderBy 参数直接拼接到 SQL 中
     * - 可以注入任意 SQL 表达式
     * 
     * POC 测试：
     * 正常：?orderBy=id&page=1&pageSize=5
     * CASE WHEN 盲注：?orderBy=(CASE WHEN (SELECT COUNT(*) FROM user)>0 THEN id ELSE name END)
     * IF() 盲注：?orderBy=IF((SELECT COUNT(*) FROM user)>0, id, name)
     * SLEEP() 时间盲注：?orderBy=IF(1=1, id, (SELECT SLEEP(3)))
     * AND 注入：?orderBy=id AND 1=1
     * 
     * @param orderBy 排序字段
     * @param page 页码
     * @param pageSize 每页大小
     * @return 分页结果
     */
    @GetMapping("/vuln")
    public Result orderByVuln(
            @RequestParam(defaultValue = "id") String orderBy,
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "5") Integer pageSize) {
        
        log.warn("收到参数 - orderBy: {}, page: {}, pageSize: {}", orderBy, page, pageSize);
        
        try {
            PageBean<User> result = userService.pageOrderByVuln(orderBy, page, pageSize);
            
            log.warn("查询成功，返回 {} 条记录", result.getRows().size());
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("查询失败: {}", e.getMessage());
            return Result.error("查询失败: " + e.getMessage());
        }
    }

    /**
     * 安全版本1：白名单校验
     * 
     * 防御原理：
     * - 只允许预定义的字段名
     * - 拒绝其他所有输入
     * 
     * 优点：简单有效
     * 缺点：需要维护白名单
     * 
     * @param orderBy 排序字段
     * @param page 页码
     * @param pageSize 每页大小
     * @return 分页结果
     */
    @GetMapping("/sec1")
    public Result orderBySecWhitelist(
            @RequestParam(defaultValue = "id") String orderBy,
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "5") Integer pageSize) {
        
        log.info("收到参数 - orderBy: {}, page: {}, pageSize: {}", orderBy, page, pageSize);
        
        // 白名单校验
        Set<String> allowedFields = new HashSet<>(Arrays.asList("id", "username", "name"));
        
        if (!allowedFields.contains(orderBy.toLowerCase())) {
            log.warn("非法排序字段: {}", orderBy);
            return Result.error("非法的排序字段");
        }
        
        try {
            PageBean<User> result = userService.pageOrderByVuln(orderBy, page, pageSize);
            
            log.info("查询成功，返回 {} 条记录", result.getRows().size());
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("查询失败: {}", e.getMessage());
            return Result.error("查询失败: " + e.getMessage());
        }
    }

    /**
     * 安全版本2：枚举类型限制
     * 
     * 防御原理：
     * - 使用枚举类型限制可选值
     * - 编译期类型安全
     * 
     * 优点：类型安全，不会出错
     * 缺点：需要定义枚举
     * 
     * @param orderBy 排序字段（枚举）
     * @param page 页码
     * @param pageSize 每页大小
     * @return 分页结果
     */
    @GetMapping("/sec2")
    public Result orderBySecEnum(
            @RequestParam(defaultValue = "ID") OrderByField orderBy,
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "5") Integer pageSize) {
        
        log.info("收到参数 - orderBy: {}, page: {}, pageSize: {}", orderBy.getFieldName(), page, pageSize);
        
        try {
            PageBean<User> result = userService.pageOrderByVuln(orderBy.getFieldName(), page, pageSize);
            
            log.info("查询成功，返回 {} 条记录", result.getRows().size());
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("查询失败: {}", e.getMessage());
            return Result.error("查询失败: " + e.getMessage());
        }
    }

    /**
     * 排序字段枚举
     */
    public enum OrderByField {
        ID("id"),
        USERNAME("username"),
        NAME("name");

        private final String fieldName;

        OrderByField(String fieldName) {
            this.fieldName = fieldName;
        }

        public String getFieldName() {
            return fieldName;
        }
    }
}
