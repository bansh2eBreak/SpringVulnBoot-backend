package icu.secnotes.controller.Components;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * SnakeYAML反序列化漏洞演示控制器
 */
@RestController
@RequestMapping("/components/snakeyaml")
@Slf4j
public class SnakeYAMLController {

    /**
     * SnakeYAML反序列化漏洞接口
     * 使用默认的Yaml构造函数，存在反序列化漏洞
     */
    @PostMapping("/vuln1")
    public Result snakeyamlVuln1(@RequestBody String yaml) {
        log.info("SnakeYAML漏洞测试 - 请求参数: {}", yaml);
        try {
            // 使用默认的Yaml构造函数，存在反序列化漏洞
            Yaml yamlParser = new Yaml();
            Object object = yamlParser.load(yaml);
            log.info("SnakeYAML反序列化成功: {}", object);
            return Result.success("SnakeYAML反序列化成功: " + object.toString());
        } catch (Exception e) {
            log.error("SnakeYAML反序列化异常: ", e);
            return Result.error("SnakeYAML反序列化异常: " + e.getMessage());
        }
    }

    /**
     * SnakeYAML安全代码接口
     * 使用SafeConstructor防止反序列化漏洞
     */
    @SuppressWarnings("deprecation")
    @PostMapping("/sec1")
    public Result snakeyamlSec1(@RequestBody String yaml) {
        log.info("SnakeYAML安全测试 - 请求参数: {}", yaml);
        try {
            // 使用SafeConstructor防止反序列化漏洞
            Yaml yamlParser = new Yaml(new SafeConstructor());
            Object object = yamlParser.load(yaml);
            log.info("SnakeYAML安全反序列化成功: {}", object);
            return Result.success("SnakeYAML安全反序列化成功: " + object.toString());
        } catch (Exception e) {
            log.error("SnakeYAML安全反序列化异常: ", e);
            return Result.error("SnakeYAML安全反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 测试正常YAML解析
     */
    @PostMapping("/basictest")
    public Result snakeyamlTest(@RequestBody String yaml) {
        log.info("SnakeYAML正常测试 - 请求参数: {}", yaml);
        try {
            Yaml yamlParser = new Yaml();
            Object object = yamlParser.load(yaml);
            log.info("SnakeYAML反序列化成功: {}", object);
            return Result.success("SnakeYAML反序列化成功: " + object.toString());
        } catch (Exception e) {
            log.error("SnakeYAML反序列化异常: ", e);
            return Result.error("SnakeYAML反序列化异常: " + e.getMessage());
        }
    }
} 