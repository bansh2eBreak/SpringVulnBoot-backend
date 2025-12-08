package icu.secnotes.controller.XML;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.SAXException;
import org.dom4j.io.SAXReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.io.StringWriter;

/**
 * XXE (XML External Entity) 漏洞演示Controller
 * XML外部实体注入是一种针对解析XML输入的应用程序的攻击
 * 当XML解析器配置不当时，攻击者可以通过构造恶意的XML输入来读取服务器文件、执行SSRF等
 * 
 * @author secnotes
 */
@Slf4j
@RestController
@RequestMapping("/xml/xxe")
public class XxeController {

    /**
     * XXE漏洞 - 漏洞代码
     * 未禁用外部实体，存在XXE漏洞
     * 
     * 攻击示例：
     * <?xml version="1.0"?>
     * <!DOCTYPE root [
     *   <!ENTITY xxe SYSTEM "file:///etc/passwd">
     * ]>
     * <user><name>&xxe;</name></user>
     */
    @PostMapping("/vuln")
    public Result xxeVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.warn("处理XML内容（漏洞代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 危险：默认配置的DocumentBuilderFactory允许外部实体
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            
            // 获取根元素内容
            String result = doc.getDocumentElement().getTextContent();
            
            log.info("XML解析结果: {}", result.substring(0, Math.min(200, result.length())));
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("XML解析失败", e);
            return Result.error("XML解析失败: " + e.getMessage());
        }
    }

    /**
     * XXE漏洞 - 安全代码
     * 禁用外部实体和DTD，防止XXE攻击
     */
    @PostMapping("/sec")
    public Result xxeSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.info("处理XML内容（安全代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 安全：禁用所有可能导致XXE的功能
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            
            // 禁用DTD（文档类型定义）
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            
            // 禁用外部通用实体
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            
            // 禁用外部参数实体
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            // 禁用外部DTD
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            
            // 禁用XInclude
            dbf.setXIncludeAware(false);
            
            // 禁用实体扩展
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            
            String result = doc.getDocumentElement().getTextContent();
            
            log.info("XML解析结果: {}", result.substring(0, Math.min(200, result.length())));
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("XML解析失败", e);
            return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
        }
    }

    // ==================== SAXParser 解析器 ====================
    
    /**
     * SAXParser 漏洞代码
     * SAX (Simple API for XML) 解析器，默认配置存在XXE漏洞
     */
    @PostMapping("/sax/vuln")
    public Result saxVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.warn("SAXParser处理XML（漏洞代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 危险：默认配置允许外部实体
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();
            
            // 自定义Handler收集内容
            ContentHandler handler = new ContentHandler();
            saxParser.parse(new InputSource(new StringReader(xmlContent)), handler);
            
            String result = handler.getContent();
            log.info("SAXParser解析结果: {}", result.substring(0, Math.min(200, result.length())));
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("SAXParser解析失败", e);
            return Result.error("XML解析失败: " + e.getMessage());
        }
    }
    
    /**
     * SAXParser 安全代码
     * 禁用外部实体和DTD，防止XXE攻击
     */
    @PostMapping("/sax/sec")
    public Result saxSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.info("SAXParser处理XML（安全代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 安全：禁用外部实体
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            
            SAXParser saxParser = factory.newSAXParser();
            ContentHandler handler = new ContentHandler();
            saxParser.parse(new InputSource(new StringReader(xmlContent)), handler);
            
            String result = handler.getContent();
            log.info("SAXParser解析结果: {}", result);
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("SAXParser解析失败", e);
            return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
        }
    }

    // ==================== XMLStreamReader (StAX) 解析器 ====================
    
    /**
     * XMLStreamReader 漏洞代码
     * StAX (Streaming API for XML) 解析器，默认配置存在XXE漏洞
     */
    @PostMapping("/stax/vuln")
    public Result staxVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.warn("StAX处理XML（漏洞代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 危险：默认配置允许外部实体
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            StringBuilder content = new StringBuilder();
            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLStreamReader.CHARACTERS) {
                    content.append(reader.getText());
                }
            }
            
            String result = content.toString().trim();
            log.info("StAX解析结果: {}", result.substring(0, Math.min(200, result.length())));
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("StAX解析失败", e);
            return Result.error("XML解析失败: " + e.getMessage());
        }
    }
    
    /**
     * XMLStreamReader 安全代码
     * 禁用外部实体和DTD，防止XXE攻击
     */
    @PostMapping("/stax/sec")
    public Result staxSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.info("StAX处理XML（安全代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 安全：禁用外部实体和DTD
            XMLInputFactory factory = XMLInputFactory.newInstance();
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
            
            StringBuilder content = new StringBuilder();
            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLStreamReader.CHARACTERS) {
                    content.append(reader.getText());
                }
            }
            
            String result = content.toString().trim();
            log.info("StAX解析结果: {}", result);
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("StAX解析失败", e);
            return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
        }
    }

    // ==================== Unmarshaller (JAXB) 解析器 ====================
    
    /**
     * Unmarshaller 漏洞代码
     * JAXB (Java Architecture for XML Binding) 解析器，默认配置存在XXE漏洞
     */
    @PostMapping("/jaxb/vuln")
    public Result jaxbVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.warn("JAXB处理XML（漏洞代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 危险：默认配置允许外部实体
            JAXBContext context = JAXBContext.newInstance(XmlUser.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            
            XmlUser user = (XmlUser) unmarshaller.unmarshal(new StringReader(xmlContent));
            String result = user.getName();
            
            log.info("JAXB解析结果: {}", result.substring(0, Math.min(200, result.length())));
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("JAXB解析失败", e);
            return Result.error("XML解析失败: " + e.getMessage());
        }
    }
    
    /**
     * Unmarshaller 安全代码
     * 使用安全的XMLReader，防止XXE攻击
     */
    @PostMapping("/jaxb/sec")
    public Result jaxbSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.info("JAXB处理XML（安全代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 安全：使用配置了安全特性的SAXParser
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            
            SAXParser saxParser = spf.newSAXParser();
            
            JAXBContext context = JAXBContext.newInstance(XmlUser.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            
            // 使用安全的SAXSource
            javax.xml.transform.sax.SAXSource source = new javax.xml.transform.sax.SAXSource(
                saxParser.getXMLReader(), 
                new InputSource(new StringReader(xmlContent))
            );
            
            XmlUser user = (XmlUser) unmarshaller.unmarshal(source);
            String result = user.getName();
            
            log.info("JAXB解析结果: {}", result);
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("JAXB解析失败", e);
            return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
        }
    }

    // ==================== SAXReader (dom4j) 解析器 ====================
    
    /**
     * SAXReader 漏洞代码
     * dom4j库的SAXReader解析器，默认配置存在XXE漏洞
     */
    @PostMapping("/dom4j/vuln")
    public Result dom4jVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.warn("dom4j SAXReader处理XML（漏洞代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 危险：默认配置允许外部实体
            SAXReader reader = new SAXReader();
            org.dom4j.Document doc = reader.read(new StringReader(xmlContent));
            
            // 获取根元素下name元素的文本内容，用于显示XXE攻击结果
            String result = doc.getRootElement().elementText("name");
            if (result == null || result.trim().isEmpty()) {
                result = doc.getRootElement().asXML();
            }
            log.info("dom4j SAXReader解析结果: {}", result.substring(0, Math.min(200, result.length())));
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("dom4j SAXReader解析失败", e);
            return Result.error("XML解析失败: " + e.getMessage());
        }
    }
    
    /**
     * SAXReader 安全代码
     * 禁用外部实体和DTD，防止XXE攻击
     */
    @PostMapping("/dom4j/sec")
    public Result dom4jSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.info("dom4j SAXReader处理XML（安全代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 安全：禁用外部实体
            SAXReader reader = new SAXReader();
            reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
            reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            
            org.dom4j.Document doc = reader.read(new StringReader(xmlContent));
            
            // 获取根元素下name元素的文本内容
            String result = doc.getRootElement().elementText("name");
            if (result == null || result.trim().isEmpty()) {
                result = doc.getRootElement().asXML();
            }
            
            log.info("dom4j SAXReader解析结果: {}", result);
            
            return Result.success(result);
        } catch (Exception e) {
            log.error("dom4j SAXReader解析失败", e);
            return Result.error("XML解析失败（安全机制生效）: " + e.getMessage());
        }
    }

    // ==================== TransformerFactory (XSLT) 解析器 ====================
    
    /**
     * TransformerFactory 漏洞代码
     * XSLT转换器，默认配置存在XXE漏洞
     */
    @PostMapping("/xslt/vuln")
    public Result xsltVulnerable(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.warn("TransformerFactory处理XML（漏洞代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 危险：默认配置允许外部实体
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
            
            StreamSource source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            
            transformer.transform(source, result);
            String output = writer.toString();
            
            log.info("TransformerFactory转换结果: {}", output.substring(0, Math.min(200, output.length())));
            
            return Result.success(output);
        } catch (Exception e) {
            log.error("TransformerFactory转换失败", e);
            return Result.error("XML转换失败: " + e.getMessage());
        }
    }
    
    /**
     * TransformerFactory 安全代码
     * 禁用外部实体和DTD，防止XXE攻击
     */
    @PostMapping("/xslt/sec")
    public Result xsltSecure(@RequestBody String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return Result.error("XML内容不能为空");
        }
        
        try {
            log.info("TransformerFactory处理XML（安全代码）: {}", xmlContent.substring(0, Math.min(100, xmlContent.length())));
            
            // 安全：禁用外部实体和DTD
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer();
            
            StreamSource source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            
            transformer.transform(source, result);
            String output = writer.toString();
            
            log.info("TransformerFactory转换结果: {}", output);
            
            return Result.success(output);
        } catch (Exception e) {
            log.error("TransformerFactory转换失败", e);
            return Result.error("XML转换失败（安全机制生效）: " + e.getMessage());
        }
    }
    
    // ==================== 内部类 ====================
    
    /**
     * SAX解析器的内容处理器
     */
    private static class ContentHandler extends DefaultHandler {
        private StringBuilder content = new StringBuilder();
        
        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            content.append(new String(ch, start, length));
        }
        
        public String getContent() {
            return content.toString().trim();
        }
    }
    
    /**
     * JAXB用户实体类
     */
    @XmlRootElement(name = "user")
    public static class XmlUser {
        private String name;
        private String age;
        
        public String getName() {
            return name;
        }
        
        @XmlElement
        public void setName(String name) {
            this.name = name;
        }
        
        public String getAge() {
            return age;
        }
        
        @XmlElement
        public void setAge(String age) {
            this.age = age;
        }
    }
}

