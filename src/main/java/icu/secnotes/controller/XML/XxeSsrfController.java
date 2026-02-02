package icu.secnotes.controller.XML;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

/**
 * SSRF via XXE（XXE 触发的 SSRF）漏洞演示 Controller
 * 演示通过外部通用实体、外部参数实体等触发服务端请求内网/本机/云元数据/本地文件等
 *
 * @author secnotes
 */
@Slf4j
@RestController
@RequestMapping("/xml/xxe-ssrf")
public class XxeSsrfController {

    /**
     * 返回用于“外部参数实体 - 加载外部 DTD”演示的 DTD 内容
     */
    @GetMapping("/dtd")
    public ResponseEntity<byte[]> dtd(HttpServletRequest request) {
        String baseUrl = buildBaseUrl(request);
        String healthUrl = baseUrl + "/actuator/health";
        String dtdContent = "<!ENTITY xxe SYSTEM \"" + healthUrl + "\">";
        byte[] body = dtdContent.getBytes(StandardCharsets.UTF_8);
        log.warn("SSRF via XXE: 外部 DTD 被请求，baseUrl={}, 返回 DTD 定义实体指向: {}", baseUrl, healthUrl);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/xml-dtd; charset=UTF-8"));
        return ResponseEntity.ok().headers(headers).body(body);
    }

    private static String buildBaseUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        if (contextPath == null) contextPath = "";
        StringBuilder url = new StringBuilder().append(scheme).append("://").append(serverName);
        if (("http".equals(scheme) && serverPort != 80) || ("https".equals(scheme) && serverPort != 443)) {
            url.append(":").append(serverPort);
        }
        url.append(contextPath);
        return url.toString();
    }

    /**
     * SSRF via XXE - 漏洞接口
     */
    @PostMapping("/vuln")
    public Result xxeSsrfVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML 内容不能为空");
        }
        try {
            log.warn("SSRF via XXE - 解析（漏洞代码），输入长度: {} 字符", xmlContent.length());
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            org.w3c.dom.Element root = doc.getDocumentElement();
            if (root == null) {
                return Result.error("XML 无根元素");
            }
            String result = root.getTextContent();
            if (result != null) result = result.trim();
            log.warn("解析完成，实体扩展/SSRF 拉取的内容已进入结果，长度: {} 字符", result != null ? result.length() : 0);
            return Result.success(result);
        } catch (Exception e) {
            log.error("SSRF via XXE 解析失败", e);
            return Result.error("解析失败: " + e.getMessage());
        }
    }

    /**
     * SSRF via XXE - 安全接口
     */
    @PostMapping("/sec")
    public Result xxeSsrfSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML 内容不能为空");
        }
        try {
            log.info("SSRF via XXE - 解析（安全代码）");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            org.w3c.dom.Element root = doc.getDocumentElement();
            if (root == null) {
                return Result.error("XML 无根元素");
            }
            String result = root.getTextContent();
            if (result != null) result = result.trim();
            return Result.success(result);
        } catch (Exception e) {
            log.warn("安全解析拒绝含 DTD/外部实体的 XML: {}", e.getMessage());
            return Result.error("解析失败（安全策略）: " + e.getMessage());
        }
    }
}
