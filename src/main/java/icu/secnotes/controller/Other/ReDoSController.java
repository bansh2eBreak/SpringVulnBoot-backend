package icu.secnotes.controller.Other;

import icu.secnotes.pojo.Result;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 正则表达式拒绝服务漏洞（ReDoS）演示控制器
 */
@RestController
@RequestMapping("/redos")
@Slf4j
@Tag(name = "ReDoS漏洞", description = "正则表达式拒绝服务漏洞演示")
public class ReDoSController {

    /**
     * ReDoS漏洞测试接口
     * 使用复杂嵌套模式 ((a+)+)+b 触发回溯爆炸
     */
    @PostMapping("/vuln")
    @Operation(summary = "ReDoS漏洞测试", description = "使用复杂嵌套模式触发回溯爆炸")
    public Result testReDoS(@RequestBody Map<String, String> request) {
        long startTime = System.currentTimeMillis();
        
        try {
            String input = request.get("input");
            if (input == null || input.trim().isEmpty()) {
                return Result.error("输入参数不能为空");
            }
            
            // 复杂嵌套模式，这个在Java中确实会产生ReDoS
            String dangerousPattern = "((a+)+)+b";
            log.info("测试ReDoS模式: {}, 输入长度: {}", dangerousPattern, input.length());
            
            boolean matches = input.matches(dangerousPattern);
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            log.info("ReDoS测试完成，耗时: {}ms", duration);
            return Result.success("匹配结果: " + matches + ", 耗时: " + duration + "ms");
            
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            log.error("ReDoS测试异常，耗时: {}ms", duration, e);
            return Result.error("处理异常: " + e.getMessage() + ", 耗时: " + duration + "ms");
        }
    }

    /**
     * 安全的正则表达式接口
     * 使用简单量词 a+ 模式
     */
    @PostMapping("/sec")
    @Operation(summary = "安全正则表达式测试", description = "测试简单量词正则表达式")
    public Result testSafeRegex(@RequestBody Map<String, String> request) {
        long startTime = System.currentTimeMillis();
        
        try {
            String input = request.get("input");
            if (input == null || input.trim().isEmpty()) {
                return Result.error("输入参数不能为空");
            }
            
            // 安全的正则表达式：简单量词
            String safePattern = "a+";
            log.info("测试安全模式: {}, 输入长度: {}", safePattern, input.length());
            
            boolean matches = input.matches(safePattern);
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            log.info("安全模式测试完成，耗时: {}ms", duration);
            return Result.success("匹配结果: " + matches + ", 耗时: " + duration + "ms");
            
        } catch (Exception e) {
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            log.error("安全模式测试异常，耗时: {}ms", duration, e);
            return Result.error("处理异常: " + e.getMessage() + ", 耗时: " + duration + "ms");
        }
    }
}
