package icu.secnotes.test;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.json.JettisonMappedXmlDriver;
import icu.secnotes.pojo.Person;

public class XStreamTest {

    public static void main(String[] args) {

        // 创建Person对象
        Person person = new Person();
        person.setName("John");
        person.setAge(20);

        // 创建XStream对象
        XStream xmlXStream = new XStream();
        // 设置别名，使生成的 XML 标签更简洁
        xmlXStream.alias("person", Person.class);

        System.out.println("1、XStream序列化为XML演示");
        String xml = xmlXStream.toXML(person);
        System.out.println("生成的 XML:\n" + xml);

        // 定义一个XML字符串
        String xml2 = "<person><name>zhangsan</name><age>28</age></person>";

        // ------------------ XML 转换 ------------------
        System.out.println("2、XStream XML反序列化演示");
        Person person2 = (Person) xmlXStream.fromXML(xml2);
        System.out.println("反序列化后的对象:\n" + person2);

        System.out.println("--- 验证反序列化结果 ---");
        System.out.println("姓名: " + person2.getName());
        System.out.println("年龄: " + person2.getAge());

        // ------------------ JSON 转换 ------------------
        System.out.println("3、XStream序列化为JSON演示");
        XStream jsonXStream = new XStream(new JettisonMappedXmlDriver());
        jsonXStream.alias("person", Person.class);
        String json = jsonXStream.toXML(person);
        System.out.println("生成的 JSON:\n" + json);

        // 定义一个JSON字符串
        String json2 = "{\"person\":{\"name\":\"lisi\",\"age\":30}}";

        System.out.println("4、XStream JSON反序列化演示");
        Person person3 = (Person) jsonXStream.fromXML(json2);
        System.out.println("反序列化后的对象:\n" + person3);

        System.out.println("--- 验证反序列化结果 ---");
        System.out.println("姓名: " + person3.getName());
        System.out.println("年龄: " + person3.getAge());
    }

}
