package icu.secnotes.controller.FileUpload;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.annotation.PostConstruct;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

@RestController
@Slf4j
@RequestMapping("/fileUpload")
public class FileUploadController {

    // 应用统一文件管理目录
    private static final String APP_FILE_DIR = "/app/file/";
    
    // 上传目录（与文件包含漏洞统一使用同一目录）
    private static final String UPLOAD_DIR = APP_FILE_DIR + "upload/";
    private static final String PATH_TRAVERSAL_TARGET = APP_FILE_DIR + "upload-guard.txt";
    private static final String PATH_TRAVERSAL_TARGET_CONTENT =
            "This is a protected demo file. Do not overwrite it.";
    private static final long MAX_SECURE_IMAGE_SIZE = 2 * 1024 * 1024;
    private static final int MAX_SECURE_IMAGE_DIMENSION = 4096;
    private static final Pattern SECURE_IMAGE_NAME =
            Pattern.compile("^[0-9a-f]{32}\\.(png|jpg)$");
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("jpg", "jpeg", "png", "gif");

    @PostConstruct
    public void init() {
        try {
            // 创建上传目录
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            ensurePathTraversalTarget();
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
     * 漏洞版本2：仅验证 multipart 文件分段声明的 Content-Type（可绕过）
     * 该值由客户端提供，不能证明文件内容是真实图片。
     */
    @PostMapping("/vuln2")
    @ResponseBody
    public Result handleFileUploadVuln2(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的文件");
        }

        try {
            // 限制上传文件类型（仅验证客户端声明的 Content-Type，容易绕过）
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
     * 漏洞版本3：直接拼接原始文件名，攻击者可使用 ../ 跳出上传目录并覆盖文件
     */
    @PostMapping("/vuln3")
    @ResponseBody
    public Result handleFileUploadVuln3(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty() || file.getOriginalFilename() == null) {
            return Result.error("请选择要上传的文件");
        }

        try {
            String filePath = UPLOAD_DIR + file.getOriginalFilename();
            file.transferTo(new File(filePath));
            log.warn("⚠️ 文件上传成功（原始文件名直接拼接，存在路径穿越与覆盖风险）: {}", filePath);
            return Result.success("文件上传成功: " + filePath);
        } catch (IOException e) {
            log.error("文件上传失败", e);
            return Result.error("文件上传失败: " + e.getMessage());
        }
    }

    @GetMapping("/vuln3/target")
    public Result getPathTraversalTarget() {
        try {
            ensurePathTraversalTarget();
            return Result.success(Files.readString(Paths.get(PATH_TRAVERSAL_TARGET), StandardCharsets.UTF_8));
        } catch (IOException e) {
            log.error("读取路径穿越测试文件失败", e);
            return Result.error("读取测试文件失败: " + e.getMessage());
        }
    }

    @PostMapping("/vuln3/reset")
    public Result resetPathTraversalTarget() {
        try {
            Files.writeString(Paths.get(PATH_TRAVERSAL_TARGET), PATH_TRAVERSAL_TARGET_CONTENT,
                    StandardCharsets.UTF_8);
            return Result.success("测试文件已恢复初始内容");
        } catch (IOException e) {
            log.error("重置路径穿越测试文件失败", e);
            return Result.error("重置测试文件失败: " + e.getMessage());
        }
    }

    private void ensurePathTraversalTarget() throws IOException {
        if (Files.notExists(Paths.get(PATH_TRAVERSAL_TARGET))) {
            Files.writeString(Paths.get(PATH_TRAVERSAL_TARGET), PATH_TRAVERSAL_TARGET_CONTENT,
                    StandardCharsets.UTF_8);
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

    /**
     * 安全版本2：服务端验证图片内容、尺寸及保存路径，并使用随机文件名落盘
     */
    @PostMapping("/sec2")
    public Result handleFileUploadSec2(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择要上传的图片");
        }
        if (file.getSize() > MAX_SECURE_IMAGE_SIZE) {
            return Result.error("图片不能超过 2MB");
        }

        try {
            byte[] content = file.getBytes();
            String format = detectImageFormat(content);
            if (format == null) {
                return Result.error("只允许上传真实的 PNG 或 JPEG 图片");
            }

            validateImageDimensions(content);
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
            if (image == null) {
                return Result.error("图片内容无法解析");
            }

            Path target = createSecureImagePath(format);
            if (!ImageIO.write(image, format, target.toFile())) {
                return Result.error("图片格式不受支持");
            }

            String fileName = target.getFileName().toString();
            log.info("✅ 安全图片上传成功: {}, 原始文件名: {}", fileName, file.getOriginalFilename());
            return Result.success(Map.of(
                    "fileName", fileName,
                    "downloadUrl", "/fileUpload/sec2/download/" + fileName,
                    "message", "真实图片校验通过，已使用服务端随机文件名保存"
            ));
        } catch (IllegalArgumentException e) {
            return Result.error(e.getMessage());
        } catch (IOException e) {
            log.error("安全图片上传失败", e);
            return Result.error("图片上传失败");
        }
    }

    @GetMapping("/sec2/download/{fileName}")
    public ResponseEntity<byte[]> downloadSecureImage(@PathVariable String fileName) {
        if (!SECURE_IMAGE_NAME.matcher(fileName).matches()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            Path target = createSecureImagePath(fileName);
            if (!Files.isRegularFile(target)) {
                return ResponseEntity.notFound().build();
            }

            MediaType mediaType = fileName.endsWith(".png") ? MediaType.IMAGE_PNG : MediaType.IMAGE_JPEG;
            return ResponseEntity.ok()
                    .contentType(mediaType)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                    .header("X-Content-Type-Options", "nosniff")
                    .body(Files.readAllBytes(target));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (IOException e) {
            log.error("安全图片下载失败", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    private String detectImageFormat(byte[] content) {
        if (content.length >= 8
                && content[0] == (byte) 0x89
                && content[1] == 0x50
                && content[2] == 0x4E
                && content[3] == 0x47
                && content[4] == 0x0D
                && content[5] == 0x0A
                && content[6] == 0x1A
                && content[7] == 0x0A) {
            return "png";
        }
        if (content.length >= 3
                && content[0] == (byte) 0xFF
                && content[1] == (byte) 0xD8
                && content[2] == (byte) 0xFF) {
            return "jpg";
        }
        return null;
    }

    private void validateImageDimensions(byte[] content) throws IOException {
        try (ImageInputStream input = ImageIO.createImageInputStream(new ByteArrayInputStream(content))) {
            Iterator<ImageReader> readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) {
                throw new IllegalArgumentException("图片内容无法解析");
            }

            ImageReader reader = readers.next();
            try {
                reader.setInput(input, true, true);
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);
                if (width <= 0 || height <= 0
                        || width > MAX_SECURE_IMAGE_DIMENSION
                        || height > MAX_SECURE_IMAGE_DIMENSION) {
                    throw new IllegalArgumentException("图片尺寸不能超过 4096 × 4096");
                }
            } finally {
                reader.dispose();
            }
        }
    }

    private Path createSecureImagePath(String fileNameOrFormat) throws IOException {
        String fileName = SECURE_IMAGE_NAME.matcher(fileNameOrFormat).matches()
                ? fileNameOrFormat
                : UUID.randomUUID().toString().replace("-", "") + "." + fileNameOrFormat;
        Path uploadRoot = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();
        Path target = uploadRoot.resolve(fileName).normalize();
        if (!target.startsWith(uploadRoot)) {
            throw new IllegalArgumentException("非法文件路径");
        }
        Files.createDirectories(uploadRoot);
        return target;
    }

}
