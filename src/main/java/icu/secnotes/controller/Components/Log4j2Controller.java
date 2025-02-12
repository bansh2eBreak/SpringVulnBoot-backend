package icu.secnotes.controller.Components;

import icu.secnotes.pojo.Result;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/components/log4j2")
@Slf4j
public class Log4j2Controller {

    private static final Logger LOGGER = LogManager.getLogger(Log4j2Controller.class);

    @GetMapping("/vuln1")
    public Result Vuln1(String input) {
        LOGGER.info("用户输入: {}", input);
        return Result.success(String.format("用户输入: %s", input));
    }

    @GetMapping("/sec1")
    public Result Sec1(String input) {
        if (!Security.checkSql(input)) {
            LOGGER.warn("检测到非法注入字符");
            return Result.error("检测到非法注入");
        }
        LOGGER.info("用户输入的内容: {}", input);
        return Result.success(String.format("用户输入的内容: %s", input));
    }

}
