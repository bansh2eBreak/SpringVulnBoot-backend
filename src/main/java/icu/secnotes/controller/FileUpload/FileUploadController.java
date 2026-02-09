package icu.secnotes.controller.FileUpload;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

@RestController
@Slf4j
@RequestMapping("/fileUpload")
public class FileUploadController {

    // 应用统一文件管理目录
    private static final String APP_FILE_DIR = "/app/file/";
    
    // 上传目录（与文件包含漏洞统一使用同一目录）
    private static final String UPLOAD_DIR = APP_FILE_DIR + "upload/";
    
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("jpg", "jpeg", "png", "gif");

    @PostConstruct
    public void init() {
        try {
            // 创建上传目录
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            log.info("✅ 文件上传目录创建成功: {}", UPLOAD_DIR);
        } catch (Exception e) {
            log.error("❌ 创建上传目录失败", e);
        }
    }

    /**
     * 漏洞版本1：无任何验证的文件上传
     */
    @PostMapping("/vuln1")
    @ResponseBody
    public Result handleFileUploadVuln1(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 保存文件
            String filePath = UPLOAD_DIR + file.getOriginalFilename();
            File dest = new File(filePath);
            file.transferTo(dest);
            
            log.warn("⚠️ 文件上传成功（无验证，存在安全风险）: {}", filePath);
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            log.error("文件上传失败", e);
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

    /**
     * 漏洞版本2：仅验证 Content-Type（可绕过）
     */
    @PostMapping("/vuln2")
    @ResponseBody
    public Result handleFileUploadVuln2(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 限制上传文件类型（仅验证 Content-Type，容易绕过）
            String contentType = file.getContentType();
            log.info("上传文件 Content-Type: {}", contentType);
            
            if (!"image/jpeg".equals(contentType) && !"image/png".equals(contentType)) {
                return Result.error("只允许上传图片文件");
            }

            // 保存文件
            String filePath = UPLOAD_DIR + file.getOriginalFilename();
            File dest = new File(filePath);
            file.transferTo(dest);
            
            log.warn("⚠️ 文件上传成功（仅验证 Content-Type，可绕过）: {}", filePath);
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            log.error("文件上传失败", e);
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

    /**
     * 安全版本：限制上传文件后缀名（白名单）
     */
    @PostMapping("/sec1")
    @ResponseBody
    public Result handleFileUploadSec1(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 验证文件后缀名（白名单）
            String fileName = file.getOriginalFilename();
            if (fileName == null || !fileName.contains(".")) {
                return Result.error("文件名无效");
            }
            
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
            if (!ALLOWED_EXTENSIONS.contains(extension)) {
                log.warn("⚠️ 拒绝上传非白名单后缀的文件: {}", fileName);
                return Result.error("只允许上传图片文件（jpg、jpeg、png、gif）");
            }

            // 保存文件
            String filePath = UPLOAD_DIR + fileName;
            File dest = new File(filePath);
            file.transferTo(dest);
            
            log.info("✅ 安全上传成功（后缀白名单验证）: {}", filePath);
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            log.error("文件上传失败", e);
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

}
