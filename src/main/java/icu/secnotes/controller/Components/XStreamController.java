package icu.secnotes.controller.Components;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.json.JettisonMappedXmlDriver;
import com.thoughtworks.xstream.security.NoTypePermission;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.Person;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

/**
 * XStream反序列化漏洞演示控制器
 */
@RestController
@RequestMapping("/components/xstream")
@Slf4j
public class XStreamController {

    /**
     * 根据传入的Person对象进行XML序列化
     */
    @PostMapping("/serializePersonToXml")
    public Result serializePersonToXml(@RequestBody Person person) {
        log.info("XML序列化Person对象 - 请求参数: {}", person);
        try {
            String xmlResult = serializeToXML(person);
            log.info("XStream XML序列化Person对象成功: {}", xmlResult);
            return Result.success("XStream XML序列化Person对象成功: " + xmlResult);
        } catch (Exception e) {
            log.error("XStream XML序列化异常: ", e);
            return Result.error("XStream XML序列化异常: " + e.getMessage());
        }
    }

    /**
     * XStream XML反序列化演示 - 通过读取前端提交的XML内容进行反序列化
     */
    @PostMapping("/deserializePersonFromXml")
    public Result deserializePersonFromXml(@RequestBody String xmlData) {
        log.info("XStream XML反序列化测试 - 请求参数: {}", xmlData);
        try {
            if (xmlData == null || xmlData.trim().isEmpty()) {
                return Result.error("XML数据不能为空");
            }
            
            // 反序列化XML数据为Person对象
            Object result = deserializeFromXML(xmlData);
            log.info("XStream XML反序列化成功: {}", result);
            return Result.success("XStream XML反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XStream XML反序列化异常: ", e);
            return Result.error("XStream XML反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 根据传入的Person对象进行JSON序列化
     */
    @PostMapping("/serializePersonToJson")
    public Result serializePersonToJson(@RequestBody Person person) {
        log.info("JSON序列化Person对象 - 请求参数: {}", person);
        try {
            String jsonResult = serializeToJSON(person);
            log.info("XStream JSON序列化Person对象成功: {}", jsonResult);
            return Result.success("XStream JSON序列化Person对象成功: " + jsonResult);
        } catch (Exception e) {
            log.error("XStream JSON序列化异常: ", e);
            return Result.error("XStream JSON序列化异常: " + e.getMessage());
        }
    }

    /**
     * XStream JSON反序列化演示 - 通过读取前端提交的JSON内容进行反序列化
     */
    @PostMapping("/deserializePersonFromJson")
    public Result deserializePersonFromJson(@RequestBody String jsonData) {
        log.info("XStream JSON反序列化测试 - 请求参数: {}", jsonData);
        try {
            if (jsonData == null || jsonData.trim().isEmpty()) {
                return Result.error("JSON数据不能为空");
            }
            
            // 反序列化JSON数据为Person对象
            Object result = deserializeFromJSON(jsonData);
            log.info("XStream JSON反序列化成功: {}", result);
            return Result.success("XStream JSON反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XStream JSON反序列化异常: ", e);
            return Result.error("XStream JSON反序列化异常: " + e.getMessage());
        }
    }

    /**
     * XStream反序列化恶意对象-执行危险命令（漏洞接口）
     */
    @PostMapping("/vuln1")
    public Result xstreamVuln1(@RequestBody String xmlData) {
        log.info("XStream漏洞测试 - 请求参数: {}", xmlData);
        try {
            // 使用XStream反序列化，存在安全漏洞
            Object result = deserializeFromXML(xmlData);
            log.info("XStream恶意对象反序列化成功: {}", result);
            return Result.success("XStream恶意对象反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XStream恶意对象反序列化异常: ", e);
            return Result.error("XStream恶意对象反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 安全代码 - 使用白名单验证
     */
    @PostMapping("/sec1")
    public Result xstreamSec1(@RequestBody String xmlData) {
        log.info("XStream安全测试 - 请求参数: {}", xmlData);
        try {
            // 检查是否在白名单中
            if (!isAllowedClass(xmlData)) {
                log.warn("检测到非白名单类，拒绝反序列化");
                return Result.error("安全策略：检测到非白名单类，拒绝反序列化");
            }
            
            // 安全反序列化
            Object result = deserializeFromXML(xmlData);
            log.info("XStream安全反序列化成功: {}", result);
            return Result.success("XStream安全反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XStream安全反序列化异常: ", e);
            return Result.error("XStream安全反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 安全代码 - 使用XStream安全配置
     */
    @PostMapping("/sec2")
    public Result xstreamSec2(@RequestBody String xmlData) {
        log.info("XStream安全配置测试 - 请求参数: {}", xmlData);
        try {
            // 使用安全配置的XStream进行反序列化
            Object result = deserializeFromXMLSecurely(xmlData);
            log.info("XStream安全配置反序列化成功: {}", result);
            return Result.success("XStream安全配置反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XStream安全配置反序列化异常: ", e);
            return Result.error("XStream安全配置反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 从XML字符串反序列化对象
     */
    private Object deserializeFromXML(String xmlStr) throws IOException {
        XStream xstream = new XStream();
        xstream.alias("person", Person.class);
        return xstream.fromXML(xmlStr);
    }

    /**
     * 将对象序列化为XML字符串
     */
    private String serializeToXML(Object obj) throws IOException {
        XStream xstream = new XStream();
        xstream.alias("person", Person.class);
        return xstream.toXML(obj);
    }

    /**
     * 将对象序列化为JSON字符串
     */
    private String serializeToJSON(Object obj) throws IOException {
        XStream xstream = new XStream(new JettisonMappedXmlDriver());
        xstream.alias("person", Person.class);
        return xstream.toXML(obj);
    }

    /**
     * 从JSON字符串反序列化对象
     */
    private Object deserializeFromJSON(String jsonStr) throws IOException {
        XStream xstream = new XStream(new JettisonMappedXmlDriver());
        xstream.alias("person", Person.class);
        return xstream.fromXML(jsonStr);
    }

    /**
     * 使用安全配置的XStream进行反序列化
     */
    private Object deserializeFromXMLSecurely(String xmlStr) throws IOException {
        XStream xstream = new XStream();

        // 1. 阻止所有类型，这是安全白名单的第一步
        xstream.addPermission(NoTypePermission.NONE);
        
        // 安全配置：只允许特定类
        xstream.allowTypes(new Class[]{Person.class});
        
        return xstream.fromXML(xmlStr);
    }

    /**
     * 检查XML数据是否在白名单中
     */
    private boolean isAllowedClass(String xmlData) {
        log.info("检查XML数据: {}", xmlData);
        String[] allowedClasses = {
            "icu.secnotes.pojo.Person",
            "java.lang.String",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Double",
            "java.lang.Float",
            "java.lang.Boolean",
            "java.util.ArrayList",
            "java.util.HashMap",
            "java.util.LinkedHashMap"
        };
        
        // 检查XML中是否包含允许的类
        for (String allowedClass : allowedClasses) {
            if (xmlData.contains(allowedClass)) {
                return true;
            }
        }
        return false;
    }
}
