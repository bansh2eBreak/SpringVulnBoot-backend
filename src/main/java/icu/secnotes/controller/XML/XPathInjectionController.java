package icu.secnotes.controller.XML;

import icu.secnotes.pojo.Result;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * XPath注入漏洞演示Controller
 * XPath注入是一种类似于SQL注入的攻击方式
 * 当应用程序使用用户输入直接构造XPath查询时，攻击者可以通过构造恶意XPath表达式来绕过身份验证、提取敏感数据等
 * 
 * @author secnotes
 */
@Slf4j
@RestController
@RequestMapping("/xml/xpath")
public class XPathInjectionController {

    // 模拟用户数据XML（实际应用中可能来自文件或数据库）
    private static final String USERS_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<users>\n" +
            "    <user>\n" +
            "        <id>1</id>\n" +
            "        <username>admin</username>\n" +
            "        <password>admin123</password>\n" +
            "        <role>administrator</role>\n" +
            "        <email>admin@example.com</email>\n" +
            "    </user>\n" +
            "    <user>\n" +
            "        <id>2</id>\n" +
            "        <username>zhangsan</username>\n" +
            "        <password>zhangsan123</password>\n" +
            "        <role>user</role>\n" +
            "        <email>zhangsan@example.com</email>\n" +
            "    </user>\n" +
            "    <user>\n" +
            "        <id>3</id>\n" +
            "        <username>lisi</username>\n" +
            "        <password>lisi123</password>\n" +
            "        <role>user</role>\n" +
            "        <email>lisi@example.com</email>\n" +
            "    </user>\n" +
            "</users>";

    /**
     * XPath注入漏洞 - 登录验证（漏洞代码）
     * 直接拼接用户输入到XPath表达式，存在XPath注入漏洞
     * 
     * 攻击示例：
     * 用户名：admin' or '1'='1
     * 密码：任意值
     * 
     * 生成的XPath：//user[username='admin' or '1'='1' and password='任意值']
     * 由于 '1'='1' 永远为真，可以绕过身份验证
     */
    @PostMapping("/login/vuln")
    public Result xpathLoginVulnerable(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        if (username == null || password == null) {
            return Result.error("用户名和密码不能为空");
        }

        try {
            log.warn("XPath注入漏洞 - 登录验证（漏洞代码）: username={}, password={}", username, password);

            // 危险：直接拼接用户输入到XPath表达式
            String xpathExpression = "//user[username='" + username + "' and password='" + password + "']";
            log.warn("生成的XPath表达式: {}", xpathExpression);

            // 解析XML文档
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(USERS_XML)));

            // 执行XPath查询
            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xpath = xPathFactory.newXPath();
            XPathExpression expr = xpath.compile(xpathExpression);
            NodeList nodes = (NodeList) expr.evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);

            if (nodes != null && nodes.getLength() > 0) {
                // 收集所有匹配的用户信息（演示XPath注入可以获取所有用户）
                List<Map<String, String>> allUsers = new ArrayList<>();
                for (int i = 0; i < nodes.getLength(); i++) {
                    org.w3c.dom.Element userElement = (org.w3c.dom.Element) nodes.item(i);
                    Map<String, String> userInfo = new HashMap<>();
                    userInfo.put("id", getNodeValue(userElement, "id"));
                    userInfo.put("username", getNodeValue(userElement, "username"));
                    userInfo.put("role", getNodeValue(userElement, "role"));
                    userInfo.put("email", getNodeValue(userElement, "email"));
                    allUsers.add(userInfo);
                }
                
                log.warn("登录成功（可能存在XPath注入）: 匹配到 {} 个用户", allUsers.size());
                if (allUsers.size() == 1) {
                    return Result.success("登录成功！用户信息: " + allUsers.get(0).toString());
                } else {
                    return Result.success("XPath注入成功！匹配到 " + allUsers.size() + " 个用户: " + allUsers.toString());
                }
            } else {
                return Result.error("用户名或密码错误");
            }

        } catch (Exception e) {
            log.error("XPath查询失败", e);
            return Result.error("登录失败: " + e.getMessage());
        }
    }

    /**
     * XPath注入漏洞 - 安全代码
     * 使用参数化查询或输入验证，防止XPath注入
     */
    @PostMapping("/login/sec")
    public Result xpathLoginSecure(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");

        if (username == null || password == null) {
            return Result.error("用户名和密码不能为空");
        }

        try {
            log.info("XPath注入漏洞 - 登录验证（安全代码）: username={}", username);

            // 安全：验证输入，防止特殊字符注入
            if (Security.checkXPath(username) || Security.checkXPath(password)) {
                log.warn("检测到可疑输入，拒绝登录: username={}", username);
                return Result.error("输入包含非法字符，拒绝登录");
            }

            // 安全：使用转义后的值构建XPath（虽然不如参数化查询，但比直接拼接安全）
            // 注意：Java XPath API不支持真正的参数化查询，所以这里使用输入验证作为防护措施
            String escapedUsername = Security.escapeXPath(username); // 转义单引号
            String escapedPassword = Security.escapeXPath(password);
            
            String xpathExpression = "//user[username='" + escapedUsername + "' and password='" + escapedPassword + "']";
            log.info("生成的XPath表达式（已转义）: {}", xpathExpression);

            // 解析XML文档
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(USERS_XML)));

            // 执行XPath查询
            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xpath = xPathFactory.newXPath();
            XPathExpression expr = xpath.compile(xpathExpression);
            NodeList nodes = (NodeList) expr.evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);

            if (nodes != null && nodes.getLength() > 0) {
                org.w3c.dom.Element userElement = (org.w3c.dom.Element) nodes.item(0);
                Map<String, String> userInfo = new HashMap<>();
                userInfo.put("id", getNodeValue(userElement, "id"));
                userInfo.put("username", getNodeValue(userElement, "username"));
                userInfo.put("role", getNodeValue(userElement, "role"));
                userInfo.put("email", getNodeValue(userElement, "email"));
                
                log.info("登录成功: {}", userInfo);
                return Result.success("登录成功！用户信息: " + userInfo.toString());
            } else {
                return Result.error("用户名或密码错误");
            }

        } catch (Exception e) {
            log.error("XPath查询失败", e);
            return Result.error("登录失败: " + e.getMessage());
        }
    }

    /**
     * 辅助方法：获取XML节点的文本内容
     */
    private String getNodeValue(org.w3c.dom.Element element, String tagName) {
        org.w3c.dom.NodeList nodeList = element.getElementsByTagName(tagName);
        if (nodeList != null && nodeList.getLength() > 0) {
            return nodeList.item(0).getTextContent();
        }
        return "";
    }
}

