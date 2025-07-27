package icu.secnotes.controller.Components;

import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.Person;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * XMLDecoder反序列化漏洞演示控制器
 */
@RestController
@RequestMapping("/components/xmldecoder")
@Slf4j
public class XMLDecoderController {

    /**
     * XMLEncoder序列化和XMLDecoder反序列化演示
     */
    @PostMapping("/basictest")
    public Result xmlEncoderTest(@RequestBody String xmlData) {
        log.info("XMLEncoder和XMLDecoder测试 - 请求参数: {}", xmlData);
        try {
            if (xmlData == null || xmlData.trim().isEmpty()) {
                // 如果没有传入XML数据，则进行序列化演示
                Person person = new Person();
                person.setName("张三");
                person.setAge(25);
                String xmlResult = serializeToXML(person);
                log.info("XMLEncoder序列化Person对象成功: {}", xmlResult);
                return Result.success("XMLEncoder序列化Person对象成功: " + xmlResult);
            } else {
                // 如果传入了XML数据，则进行反序列化演示
                Object result = deserializeFromXML(xmlData);
                log.info("XMLDecoder反序列化成功: {}", result);
                return Result.success("XMLDecoder反序列化成功: " + result.toString());
            }
        } catch (Exception e) {
            log.error("XMLEncoder/XMLDecoder操作异常: ", e);
            return Result.error("XMLEncoder/XMLDecoder操作异常: " + e.getMessage());
        }
    }

    /**
     * 根据传入的Person对象进行序列化
     */
    @PostMapping("/serializePerson")
    public Result serializePerson(@RequestBody Person person) {
        log.info("序列化Person对象 - 请求参数: {}", person);
        try {
            String xmlResult = serializeToXML(person);
            log.info("XMLEncoder序列化Person对象成功: {}", xmlResult);
            return Result.success("XMLEncoder序列化Person对象成功: " + xmlResult);
        } catch (Exception e) {
            log.error("XMLEncoder序列化异常: ", e);
            return Result.error("XMLEncoder序列化异常: " + e.getMessage());
        }
    }

    /**
     * XMLDecoder反序列化恶意对象-执行危险命令（漏洞接口）
     */
    @PostMapping("/vuln1")
    public Result xmlDecoderVuln1(@RequestBody String xmlData) {
        log.info("XMLDecoder漏洞测试 - 请求参数: {}", xmlData);
        try {
            // 使用XMLDecoder反序列化，存在安全漏洞
            Object result = deserializeFromXML(xmlData);
            log.info("XMLDecoder恶意对象反序列化成功: {}", result);
            return Result.success("XMLDecoder恶意对象反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XMLDecoder恶意对象反序列化异常: ", e);
            return Result.error("XMLDecoder恶意对象反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 安全代码 - 使用白名单验证
     */
    @PostMapping("/sec1")
    public Result xmlDecoderSec1(@RequestBody String xmlData) {
        log.info("XMLDecoder安全测试 - 请求参数: {}", xmlData);
        try {
            // 检查是否在白名单中
            if (!isAllowedClass(xmlData)) {
                log.warn("检测到非白名单类，拒绝反序列化");
                return Result.error("安全策略：检测到非白名单类，拒绝反序列化");
            }
            
            // 安全反序列化
            Object result = deserializeFromXML(xmlData);
            log.info("XMLDecoder安全反序列化成功: {}", result);
            return Result.success("XMLDecoder安全反序列化成功: " + result.toString());
        } catch (Exception e) {
            log.error("XMLDecoder安全反序列化异常: ", e);
            return Result.error("XMLDecoder安全反序列化异常: " + e.getMessage());
        }
    }

    /**
     * 从XML字符串反序列化对象
     */
    private Object deserializeFromXML(String xmlStr) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(xmlStr.getBytes("UTF-8"));
        XMLDecoder decoder = new XMLDecoder(bais);
        
        try {
            return decoder.readObject();
        } finally {
            decoder.close();
            bais.close();
        }
    }

    /**
     * 将对象序列化为XML字符串
     */
    private String serializeToXML(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        
        try {
            encoder.writeObject(obj);
            encoder.flush();
            return baos.toString("UTF-8");
        } finally {
            encoder.close();
            baos.close();
        }
    }

    /**
     * 检查XML数据是否在白名单中
     */
    private boolean isAllowedClass(String xmlData) {
        System.out.println(xmlData);
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