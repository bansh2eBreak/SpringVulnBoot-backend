package icu.secnotes.controller.XML;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

/**
 * XInclude 注入漏洞演示 Controller
 * 当解析器开启 XInclude（setXIncludeAware(true)）且未限制 href 时，攻击者可通过 xi:include 读文件或 SSRF
 * 仅禁用 DTD 无法防御 XInclude
 *
 * @author secnotes
 */
@Slf4j
@RestController
@RequestMapping("/xml/xinclude")
public class XIncludeController {

    /**
     * XInclude 注入 - 漏洞接口
     * 已禁用 DTD 与外部实体，仅开启 XInclude，用于说明「仅关 DTD 无法防御 XInclude」：
     * 攻击者仍可通过 xi:include href="file:///..." 或 href="http://..." 读文件或 SSRF
     */
    @PostMapping("/vuln")
    public Result xincludeVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML 内容不能为空");
        }
        try {
            log.warn("XInclude 注入 - 解析（漏洞代码），输入长度: {} 字符", xmlContent.length());
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            // 已禁用 DTD，突出 XInclude 不依赖 DTD
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(true);  // 危险：开启 XInclude，xi:include 会展开
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            org.w3c.dom.Element root = doc.getDocumentElement();
            if (root == null) {
                return Result.error("XML 无根元素");
            }
            String result = root.getTextContent();
            if (result != null) result = result.trim();
            log.warn("解析完成，XInclude 展开的内容已进入结果，长度: {} 字符", result != null ? result.length() : 0);
            return Result.success(result);
        } catch (Exception e) {
            log.error("XInclude 解析失败", e);
            return Result.error("解析失败: " + e.getMessage());
        }
    }

    /**
     * XInclude 注入 - 安全接口
     * 关闭 XInclude，xi:include 不会被展开；并禁用 DTD
     */
    @PostMapping("/sec")
    public Result xincludeSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML 内容不能为空");
        }
        try {
            log.info("XInclude 注入 - 解析（安全代码）");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            dbf.setXIncludeAware(false);  // 安全：关闭 XInclude
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
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
            log.warn("安全解析拒绝或未展开 XInclude: {}", e.getMessage());
            return Result.error("解析失败（安全策略）: " + e.getMessage());
        }
    }
}
