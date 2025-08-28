package icu.secnotes.controller.Components;

import com.fasterxml.jackson.databind.ObjectMapper;
import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.Person;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

/**
 * Jackson基础使用和安全代码演示控制器
 */
@RestController
@RequestMapping("/components/jackson")
@Slf4j
public class JacksonController {

    /**
     * Jackson序列化和反序列化介绍 - 基础功能演示
     */
    @PostMapping("/serializePersonToJson")
    public Result serializePersonToJson(@RequestBody Person person) {
        log.info("JSON序列化Person对象 - 请求参数: {}", person);
        try {
            String jsonResult = serializeToJSON(person);
            log.info("Jackson JSON序列化Person对象成功: {}", jsonResult);
            return Result.success("Jackson JSON序列化Person对象成功: " + jsonResult);
        } catch (Exception e) {
            log.error("Jackson JSON序列化异常: ", e);
            return Result.error("Jackson JSON序列化异常: " + e.getMessage());
        }
    }

    /**
     * Jackson JSON反序列化演示 - 基础功能演示
     */
    @PostMapping("/deserializePersonFromJson")
    public Result deserializePersonFromJson(@RequestBody String jsonData) {
        log.info("Jackson JSON反序列化测试 - 请求参数: {}", jsonData);
        try {
            if (jsonData == null || jsonData.trim().isEmpty()) {
                return Result.error("JSON数据不能为空");
            }
            
            // 反序列化JSON数据为Person对象
            Object result = deserializeFromJSON(jsonData);
            log.info("Jackson JSON反序列化成功: {}", result);
            return Result.success("Jackson JSON反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("Jackson JSON反序列化异常: ", e);
            return Result.error("Jackson JSON反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 安全代码示例1 - 使用白名单验证
     */
    @PostMapping("/vuln")
    public void jacksonVuln1(@RequestBody String jsonData) {
        // 以后再写
    }

    /**
     * 安全代码示例1 - 使用白名单验证
     */
    @PostMapping("/sec")
    public void jacksonSec1(@RequestBody String jsonData) {
        // 以后再写
    }

    /**
     * 将对象序列化为JSON字符串
     */
    private String serializeToJSON(Object obj) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(obj);
    }

    /**
     * 从JSON字符串反序列化对象
     */
    private Object deserializeFromJSON(String jsonStr) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(jsonStr, Person.class);
    }

}
