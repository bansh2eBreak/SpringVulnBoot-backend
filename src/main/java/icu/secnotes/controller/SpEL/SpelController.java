package icu.secnotes.controller.SpEL;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * SpEL表达式注入漏洞演示Controller
 * SpEL (Spring Expression Language) 是Spring框架提供的表达式语言
 * 当用户输入被直接拼接到SpEL表达式中时，可能导致任意代码执行
 */
@Slf4j
@RestController
@RequestMapping("/spel")
public class SpelController {

    /**
     * SpEL表达式注入 - 漏洞代码
     * 使用StandardEvaluationContext，允许执行任意代码
     * 
     * 危险的Payload示例：
     * - T(java.lang.Runtime).getRuntime().exec('calc')
     * - T(java.lang.System).getProperty('user.dir')
     * - new java.io.File('/tmp/test.txt').createNewFile()
     */
    @PostMapping("/vuln")
    public Result spelVulnerable(@RequestBody Map<String, String> request) {
        String expression = request.get("expression");
        
        if (expression == null || expression.trim().isEmpty()) {
            return Result.error("表达式不能为空");
        }
        
        try {
            log.warn("执行SpEL表达式（漏洞代码）: {}", expression);
            
            // 危险：使用StandardEvaluationContext，允许访问所有类和方法
            ExpressionParser parser = new SpelExpressionParser();
            StandardEvaluationContext context = new StandardEvaluationContext();
            
            Expression exp = parser.parseExpression(expression);
            Object result = exp.getValue(context);
            
            String resultStr = result != null ? result.toString() : "null";
            log.info("SpEL表达式执行结果: {}", resultStr);
            
            return Result.success(resultStr);
        } catch (Exception e) {
            log.error("SpEL表达式执行失败", e);
            return Result.error("表达式执行失败: " + e.getMessage());
        }
    }

    /**
     * SpEL表达式注入 - 不安全的黑名单过滤（可被绕过）
     * 尝试通过黑名单过滤危险字符，但过滤不完善，存在绕过方式
     * 
     * 绕过方式示例：
     * 1. 使用字符串拼接绕过：''.class.forName('java.la'+'ng.Ru'+'ntime')
     * 2. 使用反射绕过：''.class.getClass()
     * 3. 使用Unicode编码绕过
     */
    @PostMapping("/filter")
    public Result spelBlacklistFilter(@RequestBody Map<String, String> request) {
        String expression = request.get("expression");
        
        if (expression == null || expression.trim().isEmpty()) {
            return Result.error("表达式不能为空");
        }
        
        // 不完善的黑名单过滤：只过滤了部分危险关键字
        // 注意：这个黑名单不完善，很多危险操作并未被过滤
        String[] blacklist = {"Runtime", "exec"};
        for (String keyword : blacklist) {
            if (expression.contains(keyword)) {
                log.warn("检测到危险关键字，拒绝执行: {}", keyword);
                return Result.error("表达式包含危险关键字: " + keyword);
            }
        }
        
        try {
            log.warn("执行SpEL表达式（黑名单过滤）: {}", expression);
            
            // 危险：即使有黑名单过滤，依然使用StandardEvaluationContext
            ExpressionParser parser = new SpelExpressionParser();
            StandardEvaluationContext context = new StandardEvaluationContext();
            
            Expression exp = parser.parseExpression(expression);
            Object result = exp.getValue(context);
            
            String resultStr;
            
            // 特殊处理Process对象
            if (result instanceof Process) {
                Process process = (Process) result;
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    resultStr = reader.lines().collect(Collectors.joining("\n"));
                    process.waitFor();
                    if (resultStr.isEmpty()) {
                        resultStr = "命令执行成功，但无输出";
                    }
                } catch (Exception e) {
                    resultStr = "Process对象，无法直接获取输出: " + result.toString();
                }
            } else {
                resultStr = result != null ? result.toString() : "null";
            }
            
            log.info("SpEL表达式执行结果: {}", resultStr);
            
            return Result.success(resultStr);
        } catch (Exception e) {
            log.error("SpEL表达式执行失败", e);
            return Result.error("表达式执行失败: " + e.getMessage());
        }
    }

    /**
     * SpEL表达式注入 - 安全代码
     * 使用SimpleEvaluationContext，限制SpEL的能力
     * 只允许访问属性和调用预定义的方法，不能执行任意代码
     */
    @PostMapping("/sec")
    public Result spelSecure(@RequestBody Map<String, String> request) {
        String expression = request.get("expression");
        
        if (expression == null || expression.trim().isEmpty()) {
            return Result.error("表达式不能为空");
        }
        
        try {
            log.info("执行SpEL表达式（安全代码）: {}", expression);
            
            // 安全：使用SimpleEvaluationContext，限制SpEL能力
            // 不允许访问类型引用（T()）、构造函数、反射等危险功能
            ExpressionParser parser = new SpelExpressionParser();
            SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
            
            Expression exp = parser.parseExpression(expression);
            Object result = exp.getValue(context);
            
            String resultStr = result != null ? result.toString() : "null";
            log.info("SpEL表达式执行结果: {}", resultStr);
            
            return Result.success(resultStr);
        } catch (Exception e) {
            log.error("SpEL表达式执行失败", e);
            return Result.error("表达式执行失败: " + e.getMessage());
        }
    }
}

