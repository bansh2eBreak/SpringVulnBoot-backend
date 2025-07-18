package icu.secnotes.pojo;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class BadPerson implements Serializable {
    
    private String name;
    private Integer age;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getAge() {
        return age;
    }

    public void setAge(Integer age) {
        this.age = age;
    }

    // 反序列化时自动执行危险命令
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            Process process = Runtime.getRuntime().exec("id");
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            System.out.println("BadPerson反序列化时执行命令结果: " + output.toString());
        } catch (Exception e) {
            System.out.println("命令执行失败: " + e.getMessage());
        }
    }

    @Override
    public String toString() {
        return "BadPerson{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }
} 