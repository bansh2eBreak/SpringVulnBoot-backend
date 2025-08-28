package icu.secnotes.test;

import com.fasterxml.jackson.databind.ObjectMapper;

import icu.secnotes.pojo.Person;

public class JacksonTest {

    public static void main(String[] args) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        Person person = new Person();
        person.setName("zhangsan");
        person.setAge(20);

        // 序列化
        String json = objectMapper.writeValueAsString(person);
        System.out.println(json);

        // 反序列化
        String json2 = "{\"name\":\"lisi\",\"age\":28}";
        Person person2 = objectMapper.readValue(json2, Person.class);
        System.out.println(person2.getName());
        System.out.println(person2.getAge());
    }

}
