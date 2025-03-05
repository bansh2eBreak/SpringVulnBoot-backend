package icu.secnotes.controller.FileUpload;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
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

    private static final String UPLOAD_DIR = System.getProperty("user.dir") + "/src/main/resources/static/file/";
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("jpg", "jpeg", "png", "gif");

    @PostMapping("/vuln1")
    @ResponseBody
    public Result handleFileUploadVuln1(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 确保上传目录存在
            if (!Files.exists(Paths.get(UPLOAD_DIR))) {
                Files.createDirectories(Paths.get(UPLOAD_DIR));
            }

            // 保存文件
            String filePath = UPLOAD_DIR + file.getOriginalFilename();
            File dest = new File(filePath);
            file.transferTo(dest);
            // 将下面的file.getOriginalFilename()改为文件完整路径
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            e.printStackTrace();
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

    /**
     * 文件类型校验，可绕过
     */
    @PostMapping("/vuln2")
    @ResponseBody
    public Result handleFileUploadVuln2(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 确保上传目录存在
            if (!Files.exists(Paths.get(UPLOAD_DIR))) {
                Files.createDirectories(Paths.get(UPLOAD_DIR));
            }

            // 限制上传文件类型
            String contentType = file.getContentType();
            System.out.println(contentType);
            if (!"image/jpeg".equals(contentType) && !"image/png".equals(contentType)) {
                return Result.error("只允许上传图片文件");
            }

            // 保存文件
            String filePath = UPLOAD_DIR + file.getOriginalFilename();
            File dest = new File(filePath);
            file.transferTo(dest);
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            e.printStackTrace();
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

    /**
     * 修复方案：限制上传文件后缀名
     */
    @PostMapping("/sec1")
    @ResponseBody
    public Result handleFileUploadSec1(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 确保上传目录存在
            if (!Files.exists(Paths.get(UPLOAD_DIR))) {
                Files.createDirectories(Paths.get(UPLOAD_DIR));
            }

            // 限制上传文件类型
            String fileName = file.getOriginalFilename();
            // 如果上传的文件后缀名不属于ALLOWED_EXTENSIONS，则返回错误
            String extension = fileName.substring(fileName.lastIndexOf(".") + 1);
            if (!ALLOWED_EXTENSIONS.contains(extension)) {
                return Result.error("只允许上传图片文件");
            }

            // 保存文件
            String filePath = UPLOAD_DIR + fileName;
            File dest = new File(filePath);
            file.transferTo(dest);
            return Result.success("文件上传成功: " + filePath);

        } catch (IOException e) {
            e.printStackTrace();
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

}
