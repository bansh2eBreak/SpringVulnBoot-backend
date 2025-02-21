package icu.secnotes.controller.PathTraversal;

import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@Slf4j
@RequestMapping("/pathtraversal")
public class PathTraversalController {

    @GetMapping("/vuln1")
    public ResponseEntity<byte[]> vuln1(@RequestParam String filename) throws IOException {
        // 1. 构建图片文件路径
        File file = new File("images/" + filename);

        /**
         * 1）项目的根目录通常是指包含pom.xml文件的目录
         *      -- 打印文件路径可知：/Users/liujianping/IdeaProjects/SpringVulnBoot/images/img.png
         * 2）如果是读取resources下面的图片呢
         *      File file = new File("src/main/resources/images/" + filename);
         */
        log.info("文件位置: {}", file.getAbsolutePath());

        // 2. 检查文件是否存在
        if (!file.exists()) {
            return ResponseEntity.notFound().build(); // 文件不存在，返回 404
        }

        // 3. 读取文件内容并返回
        FileInputStream fis = new FileInputStream(file);
        byte[] imageBytes = IOUtils.toByteArray(fis);
        fis.close();

        // 4. 获取图片类型 (根据实际情况修改)
        String contentType; // 默认图片类型
        if (filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".jpeg")) {
            contentType = "image/jpeg";
        } else if (filename.toLowerCase().endsWith(".gif")) {
            contentType = "image/gif";
        } else if (filename.toLowerCase().endsWith(".png")) {
            contentType = "image/png";
        } else {
            contentType = "text/plain";
        }

        // 5. 设置 Content-Type 响应头并返回 ResponseEntity
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(imageBytes);
    }

    @GetMapping("/sec1")
    public ResponseEntity<byte[]> sec1(@RequestParam String filename) throws IOException {

        // 1. 检查文件名是否合法
        if (!Security.checkFilename(filename)) {
            return ResponseEntity.badRequest().body("文件名不合法".getBytes()); // 文件名不合法，返回 400
        }

        // 2. 构建图片文件路径
        File file = new File("images/" + filename);
        log.info("文件位置: {}", file.getAbsolutePath());

        // 3. 检查文件是否存在
        if (!file.exists()) {
            return ResponseEntity.notFound().build(); // 文件不存在，返回 404
        }

        // 4. 读取文件内容并返回
        FileInputStream fis = new FileInputStream(file);
        byte[] imageBytes = IOUtils.toByteArray(fis);
        fis.close();

        // 5. 获取图片类型 (根据实际情况修改)
        String contentType; // 默认图片类型
        if (filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".jpeg")) {
            contentType = "image/jpeg";
        } else if (filename.toLowerCase().endsWith(".gif")) {
            contentType = "image/gif";
        } else if (filename.toLowerCase().endsWith(".png")) {
            contentType = "image/png";
        } else {
            contentType = "text/plain";
        }

        // 6. 设置 Content-Type 响应头并返回 ResponseEntity
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(imageBytes);
    }

    @GetMapping("/sec2")
    public ResponseEntity<byte[]> sec2(@RequestParam String filename) throws IOException {

        // 1. 构建安全的文件路径
        Path baseDir = Paths.get("images").toAbsolutePath().normalize();
        Path filePath = baseDir.resolve(filename).normalize();

        // 2. 检查路径是否在允许的目录范围内
        if (!filePath.startsWith(baseDir)) {
            return ResponseEntity.badRequest().body("Access denied".getBytes());
        }

        File file = filePath.toFile();
        log.info("文件位置: {}", file.getAbsolutePath());

        // 3. 检查文件是否存在
        if (!file.exists()) {
            return ResponseEntity.notFound().build(); // 文件不存在，返回 404
        }

        // 4. 读取文件内容并返回
        FileInputStream fis = new FileInputStream(file);
        byte[] imageBytes = IOUtils.toByteArray(fis);
        fis.close();

        // 5. 获取图片类型 (根据实际情况修改)
        String contentType; // 默认图片类型
        if (filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".jpeg")) {
            contentType = "image/jpeg";
        } else if (filename.toLowerCase().endsWith(".gif")) {
            contentType = "image/gif";
        } else if (filename.toLowerCase().endsWith(".png")) {
            contentType = "image/png";
        } else {
            contentType = "text/plain";
        }

        // 6. 设置 Content-Type 响应头并返回 ResponseEntity
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(imageBytes);
    }

}
