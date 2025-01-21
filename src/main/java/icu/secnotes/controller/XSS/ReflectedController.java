package icu.secnotes.controller.XSS;

import icu.secnotes.pojo.Result;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@Slf4j
@RestController
@RequestMapping("/xss/reflected")
public class ReflectedController {

    @GetMapping("/vuln1")
    public Result Vuln1(String name) {
        log.info("请求参数: {}", name);
        return Result.success("Hello, " + name);
    }

    @GetMapping("/sec1")
    public Result Sec1(String name) {
        log.info("请求参数: {}", name);
        String newName = Security.xssFilter(name);
        return Result.success("Hello, " + newName);
    }

    /**
     * 采用Spring自带的HtmlUtils方法防止xss脚本攻击
     */
    @GetMapping("/sec2")
    public Result Sec2(String name) {
        log.info("请求参数: {}", name);
        String newName = HtmlUtils.htmlEscape(name);
        return Result.success("Hello, " + newName);
    }

    /**
     * 采用OWASP Java Encoder方法防止xss攻击
     */
    @GetMapping("/sec3")
    public Result Sec3(String name) {
        log.info("请求参数: {}", name);
        String newName = Encode.forHtml(name);
        return Result.success("Hello, " + newName);
    }
}
