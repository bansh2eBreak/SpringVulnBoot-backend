package icu.secnotes.controller.FileInclusion;

import groovy.lang.GroovyShell;
import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * 文件包含漏洞演示控制器
 * 使用 Groovy 脚本实现类似 PHP include 的效果
 */
@Slf4j
@RestController
@RequestMapping("/fileInclusion")
@CrossOrigin(origins = "*", maxAge = 3600)
public class FileInclusionController {

    // 上传目录（使用容器外部的临时目录）
    private static final String UPLOAD_DIR = "/tmp/file-inclusion/";
    
    // 示例文件存放路径
    private static final String EXAMPLES_DIR = "src/main/resources/examples/";

    @PostConstruct
    public void init() {
        try {
            // 创建上传目录
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            log.info("✅ 文件包含上传目录创建成功: {}", UPLOAD_DIR);
            
            // 创建示例目录
            Files.createDirectories(Paths.get(EXAMPLES_DIR));
            log.info("✅ 示例文件目录创建成功: {}", EXAMPLES_DIR);
            
        } catch (Exception e) {
            log.error("❌ 创建目录失败", e);
        }
    }

    /**
     * 上传文件接口（漏洞：未验证文件类型）
     */
    @PostMapping("/upload")
    public Result uploadScript(@RequestParam("file") MultipartFile file) {
        try {
            if (file.isEmpty()) {
                return Result.error("文件不能为空");
            }

            String filename = file.getOriginalFilename();
            Path uploadPath = Paths.get(UPLOAD_DIR + filename);
            file.transferTo(uploadPath.toFile());

            log.warn("⚠️ 文件上传（未验证类型，存在安全风险）: {}", uploadPath);
            
            return Result.success(Map.of(
                "message", "文件上传成功",
                "filename", filename,
                "path", uploadPath.toString(),
                "size", file.getSize()
            ));

        } catch (Exception e) {
            log.error("文件上传失败", e);
            return Result.error("上传失败: " + e.getMessage());
        }
    }

    /**
     * Groovy 脚本文件包含漏洞（类似 PHP include）
     * 漏洞：直接执行用户上传的 Groovy 脚本
     */
    @GetMapping("/groovy/vuln")
    public void groovyIncludeVuln(
            @RequestParam String file,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // 必须在 getWriter() 之前设置字符编码
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();

        try {
            // 漏洞：包含并执行用户指定的Groovy脚本
            String scriptPath = UPLOAD_DIR + file;
            File scriptFile = new File(scriptPath);

            if (!scriptFile.exists()) {
                out.println("<h2 style='color: red;'>❌ 文件不存在: " + file + "</h2>");
                out.println("<p>路径: " + scriptPath + "</p>");
                return;
            }

            log.warn("⚠️ 【漏洞触发】包含并执行脚本: {}", scriptPath);

            // 读取脚本内容
            String scriptContent = Files.readString(scriptFile.toPath());

            // ⚠️ 漏洞核心：直接执行 Groovy 脚本（类似 PHP include）
            GroovyShell shell = new GroovyShell();

            // 将 request、response、out 绑定到脚本环境
            // 脚本中可以直接使用这些变量
            shell.setVariable("request", request);
            shell.setVariable("response", response);
            shell.setVariable("out", out);

            // 执行脚本
            Object result = shell.evaluate(scriptContent);

            log.warn("✅ 脚本执行成功，返回结果: {}", result);

        } catch (Exception e) {
            log.error("❌ 脚本执行失败", e);
            out.println("<h2 style='color: red;'>❌ 脚本执行失败</h2>");
            out.println("<pre>" + e.getMessage() + "</pre>");
            
            // 打印堆栈跟踪
            out.println("<h3>堆栈跟踪：</h3>");
            out.println("<pre>");
            e.printStackTrace(out);
            out.println("</pre>");
        }
    }

    /**
     * Groovy 脚本安全执行（白名单验证）
     */
    @GetMapping("/groovy/sec")
    public Result groovyIncludeSecure(@RequestParam String file) {
        try {
            // 防御1: 白名单验证
            Set<String> allowedScripts = Set.of(
                "utils.groovy",
                "helpers.groovy",
                "validators.groovy"
            );

            if (!allowedScripts.contains(file)) {
                log.warn("⚠️ 拒绝执行非白名单脚本: {}", file);
                return Result.error("非法脚本名称: " + file + "。只允许执行: " + allowedScripts);
            }

            // 防御2: 固定脚本目录，不允许路径遍历
            if (file.contains("..") || file.contains("/") || file.contains("\\")) {
                return Result.error("检测到路径遍历攻击");
            }

            // 防御3: 使用受限的 Groovy 环境（沙箱）
            // 实际应用中应该配置更严格的安全策略
            String scriptPath = UPLOAD_DIR + file;
            File scriptFile = new File(scriptPath);

            if (!scriptFile.exists()) {
                return Result.error("脚本文件不存在: " + file);
            }

            String scriptContent = Files.readString(scriptFile.toPath());
            
            // 这里应该使用沙箱执行，限制脚本的权限
            // 简化演示，实际应使用 SecureASTCustomizer 等机制
            
            log.info("✅ 安全执行白名单脚本: {}", file);
            return Result.success("安全执行成功");

        } catch (Exception e) {
            log.error("脚本执行失败", e);
            return Result.error("执行失败: " + e.getMessage());
        }
    }

    /**
     * 下载示例 Webshell 文件
     */
    @GetMapping("/downloadExample")
    public ResponseEntity<Resource> downloadExample(@RequestParam String type) {
        try {
            // 只支持基础版示例
            if (!"basic".equals(type)) {
                return ResponseEntity.badRequest().build();
            }

            String filename = "shell.groovy";

            // 从 classpath 中读取资源文件
            org.springframework.core.io.ClassPathResource resource = 
                new org.springframework.core.io.ClassPathResource("examples/" + filename);
            
            if (!resource.exists()) {
                log.warn("示例文件不存在: examples/{}", filename);
                return ResponseEntity.notFound().build();
            }

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (Exception e) {
            log.error("下载示例文件失败", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
