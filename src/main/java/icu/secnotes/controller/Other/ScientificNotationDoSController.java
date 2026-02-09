package icu.secnotes.controller.Other;

import icu.secnotes.pojo.Result;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import java.math.BigDecimal;

/**
 * 科学记数法拒绝服务漏洞（Scientific Notation DoS）
 * 
 * 核心原理：BigDecimal 在进行算术运算时需要对齐两个数字的 scale（小数位数）
 * 当输入极端 scale 的科学记数法（如 0.1e-121312222，scale=121312223）
 * 与普通数字运算时，需要创建超大数组进行精度对齐，导致 CPU 和内存资源耗尽
 */
@Slf4j
@RestController
@RequestMapping("/scientificNotationDoS")
@Tag(name = "科学记数法DoS漏洞")
public class ScientificNotationDoSController {

    /**
     * 漏洞端点 - 未验证就直接接收 BigDecimal 参数
     */
    @PostMapping("/vuln")
    @Operation(summary = "科学记数法DoS漏洞测试", description = "极端scale导致运算DoS")
    public Result testVuln(@RequestParam(name = "num") BigDecimal num) {
        long startTime = System.currentTimeMillis();
        
        try {
            log.warn("收到科学记数法DoS测试请求");
            log.warn("BigDecimal: precision={}, scale={}", num.precision(), num.scale());
            
            // ⚠️ 危险操作：直接与另一个 BigDecimal 进行运算
            BigDecimal num1 = new BigDecimal(0.005);
            
            log.warn("开始执行 subtract 运算...");
            
            // ⚠️ 精度对齐 DoS：
            // 当两个 BigDecimal 的 scale 相差巨大时（如 3 vs 121312223）
            // BigDecimal 需要创建一个能容纳 max(scale1, scale2) 位小数的超大数组
            // 然后遍历整个数组进行运算，消耗大量 CPU 和内存
            BigDecimal result = num1.subtract(num);
            
            log.warn("subtract 运算完成");
            
            // 限制返回字符串的长度，避免传输超大结果
            String resultStr = result.toPlainString();
            String displayResult = resultStr.length() > 100 ? 
                resultStr.substring(0, 100) + "..." : resultStr;
            
            long duration = System.currentTimeMillis() - startTime;
            
            log.warn("请求处理完成，耗时: {} ms", duration);
            
            return Result.success("运算完成！结果: " + displayResult + "，耗时: " + duration + " ms");
            
        } catch (OutOfMemoryError e) {
            // 极端情况下可能触发 OOM
            long duration = System.currentTimeMillis() - startTime;
            log.error("内存溢出: {}, 耗时: {} ms", e.getMessage(), duration);
            return Result.error("内存溢出，DoS攻击成功！耗时: " + duration + " ms");
            
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("处理请求时发生异常: {}, 耗时: {} ms", e.getMessage(), duration);
            return Result.error("处理失败: " + e.getMessage() + "，耗时: " + duration + " ms");
        }
    }

    /**
     * 安全端点 - 添加验证
     */
    @PostMapping("/sec")
    @Operation(summary = "科学记数法安全版本", description = "添加scale范围验证")
    public Result testSec(@RequestParam(name = "num") BigDecimal num) {
        long startTime = System.currentTimeMillis();
        
        try {
            log.info("收到安全版本测试请求");
            
            // ✅ 验证：检查 scale 的绝对值
            // scale 是小数点后的位数，过大的 scale 会导致运算时的数组过大
            int scale = Math.abs(num.scale());
            if (scale > 1000) {
                long duration = System.currentTimeMillis() - startTime;
                log.warn("拒绝：数字精度过高，scale={}", scale);
                return Result.error("数字精度过高，scale=" + scale + " 超过限制（最大1000），耗时: " + duration + " ms");
            }
            
            log.info("验证通过，precision={}, scale={}", num.precision(), scale);
            
            // ✅ 执行安全的运算
            BigDecimal num1 = new BigDecimal(0.005);
            BigDecimal result = num1.subtract(num);
            
            long duration = System.currentTimeMillis() - startTime;
            
            log.info("安全运算完成，耗时: {} ms", duration);
            
            return Result.success("运算完成，结果: " + result + "，耗时: " + duration + " ms");
            
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("处理请求时发生异常: {}, 耗时: {} ms", e.getMessage(), duration);
            return Result.error("处理失败: " + e.getMessage() + "，耗时: " + duration + " ms");
        }
    }
}
