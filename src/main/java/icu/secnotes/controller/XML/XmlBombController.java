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
 * XML 炸弹（Billion Laughs / 实体扩展 DoS）漏洞演示 Controller
 * 通过递归定义 XML 实体，在解析时触发指数级实体扩展，导致内存耗尽或 DoS
 *
 * @author secnotes
 */
@Slf4j
@RestController
@RequestMapping("/xml/bomb")
public class XmlBombController {

    /**
     * XML 炸弹漏洞 - 漏洞接口
     * 使用默认配置解析 XML，允许 DTD 与实体扩展，存在实体扩展 DoS 风险
     */
    @PostMapping("/vuln")
    public Result xmlBombVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML 内容不能为空");
        }

        try {
            log.warn("XML 炸弹漏洞 - 解析（漏洞代码），输入长度: {} 字符", xmlContent.length());

            // 危险：默认配置允许 DTD 与实体扩展，易受 Billion Laughs 等攻击
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
            org.w3c.dom.Element root = doc.getDocumentElement();

            String rootName = root != null ? root.getNodeName() : "";
            String textContent = root != null ? root.getTextContent() : "";
            int contentLength = textContent != null ? textContent.length() : 0;

            log.warn("解析完成 - 根元素: {}, 扩展后内容长度: {} 字符", rootName, contentLength);

            String message = String.format("解析成功。根元素: %s, 扩展后内容长度: %d 字符（若为炸弹 payload 则长度异常大）", rootName, contentLength);
            return Result.success(message);

        } catch (OutOfMemoryError e) {
            log.error("XML 炸弹导致内存耗尽", e);
            return Result.error("解析失败: 实体扩展导致内存耗尽（XML 炸弹攻击生效）");
        } catch (Exception e) {
            log.error("XML 解析失败", e);
            return Result.error("解析失败: " + e.getMessage());
        }
    }

    /**
     * XML 炸弹漏洞 - 安全接口
     * 禁用 DTD，从根本上避免实体扩展类攻击
     */
    @PostMapping("/sec")
    public Result xmlBombSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML 内容不能为空");
        }

        try {
            log.info("XML 炸弹漏洞 - 解析（安全代码），输入长度: {} 字符", xmlContent.length());

            // 安全：禁用 DTD，不允许任何实体定义与扩展
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
            org.w3c.dom.Element root = doc.getDocumentElement();

            String rootName = root != null ? root.getNodeName() : "";
            String textContent = root != null ? root.getTextContent() : "";
            int contentLength = textContent != null ? textContent.length() : 0;

            log.info("安全解析完成 - 根元素: {}, 内容长度: {} 字符", rootName, contentLength);

            String message = String.format("解析成功。根元素: %s, 内容长度: %d 字符", rootName, contentLength);
            return Result.success(message);

        } catch (Exception e) {
            log.warn("安全解析拒绝含 DTD 的 XML: {}", e.getMessage());
            return Result.error("解析失败（安全策略）: 不允许 DTD/实体，疑似 XML 炸弹已被拦截。详情: " + e.getMessage());
        }
    }
}
