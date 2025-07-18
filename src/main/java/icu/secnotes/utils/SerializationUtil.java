package icu.secnotes.utils;

import icu.secnotes.pojo.Person;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;

public class SerializationUtil {
    
    /**
     * 生成恶意对象的Base64序列化数据
     */
    // public static String generateMaliciousObjectData(String command) throws Exception {
    //     MaliciousObject obj = new MaliciousObject(command);
    //     return serializeToBase64(obj);
    // }
    
    /**
     * 生成DNS对象的Base64序列化数据
     */
    
    /**
     * 生成Person对象的Base64序列化数据
     */
    public static String generatePersonObjectData(String name, Integer age) throws Exception {
        Person obj = new Person();
        obj.setName(name);
        obj.setAge(age);
        return serializeToBase64(obj);
    }
    
    /**
     * 将对象序列化为Base64字符串
     */
    private static String serializeToBase64(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();
        
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
} 