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

    // 应用统一文件管理目录
    private static final String APP_FILE_DIR = "/app/file/";
    
    // 上传目录（用户可控，攻击者可上传到这里）
    private static final String UPLOAD_DIR = APP_FILE_DIR + "upload/";
    
    // 安全脚本目录（白名单脚本存放位置，攻击者无法写入）
    private static final String SAFE_SCRIPTS_DIR = APP_FILE_DIR;

    @PostConstruct
    public void init() {
        try {
            // 创建上传目录（用户上传文件存放目录）
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            log.info("✅ 用户上传目录创建成功: {}", UPLOAD_DIR);
            
        } catch (Exception e) {
            log.error("❌ 创建上传目录失败", e);
        }
        
        // 检查安全脚本目录（容器部署时由 Dockerfile 创建，本地开发需手动创建）
        File safeScriptsDir = new File(SAFE_SCRIPTS_DIR);
        if (safeScriptsDir.exists()) {
            log.info("✅ 应用文件管理目录存在: {}", SAFE_SCRIPTS_DIR);
            
            // 检查白名单脚本是否存在
            File utilsScript = new File(SAFE_SCRIPTS_DIR + "utils.groovy");
            if (utilsScript.exists()) {
                log.info("✅ 白名单脚本存在: utils.groovy");
            } else {
                log.warn("⚠️ 白名单脚本不存在: utils.groovy");
            }
        } else {
            log.warn("⚠️ 应用文件管理目录不存在: {}（本地开发需手动创建，容器部署时自动创建）", SAFE_SCRIPTS_DIR);
        }
        
        // 注意：示例文件（shell.groovy, utils.groovy）已打包在 jar 内部
        // 通过 ClassPathResource 读取，不需要创建物理目录
        log.info("📂 目录结构: {} (白名单脚本) | {} (用户上传)", SAFE_SCRIPTS_DIR, UPLOAD_DIR);
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
     * 
     * 安全机制：
     * 1. 白名单验证：只允许执行预定义的脚本名称
     * 2. 固定目录：从应用统一文件管理目录 /app/file/ 读取
     * 3. 防止绕过：攻击者无法上传文件到 /app/file/ 目录（无写权限）
     * 
     * 对比漏洞版本：
     * - 漏洞版本：从 /app/file/upload/ 读取（用户上传目录，攻击者可控）
     * - 安全版本：从 /app/file/ 根目录读取（白名单脚本目录，攻击者不可控）
     */
    @GetMapping("/groovy/sec")
    public void groovyIncludeSecure(
            @RequestParam String file,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // 必须在 getWriter() 之前设置字符编码
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();

        try {
            // 防御1: 白名单验证
            Set<String> allowedScripts = Set.of(
                "utils.groovy",
                "helpers.groovy",
                "validators.groovy"
            );

            if (!allowedScripts.contains(file)) {
                log.warn("⚠️ 拒绝执行非白名单脚本: {}", file);
                out.println("<html><head><meta charset='UTF-8'><title>安全防护</title></head><body>");
                out.println("<h2 style='color: red;'>❌ 安全防护：拒绝执行非白名单脚本</h2>");
                out.println("<p><strong>尝试执行的脚本:</strong> " + file + "</p>");
                out.println("<p><strong>白名单列表:</strong> " + allowedScripts + "</p>");
                out.println("<p style='color: green;'><strong>✅ 防御成功！</strong>只有白名单内的脚本才能执行。</p>");
                out.println("</body></html>");
                return;
            }

            // 防御2: 固定脚本目录，不允许路径遍历
            if (file.contains("..") || file.contains("/") || file.contains("\\")) {
                log.warn("⚠️ 检测到路径遍历攻击: {}", file);
                out.println("<html><head><meta charset='UTF-8'><title>安全防护</title></head><body>");
                out.println("<h2 style='color: red;'>❌ 安全防护：检测到路径遍历攻击</h2>");
                out.println("<p><strong>尝试的路径:</strong> " + file + "</p>");
                out.println("<p style='color: green;'><strong>✅ 防御成功！</strong>禁止使用 .. / \\ 等路径符号。</p>");
                out.println("</body></html>");
                return;
            }

            // 防御3: 从应用统一文件管理目录读取（攻击者无法上传到这里）
            String scriptPath = SAFE_SCRIPTS_DIR + file;
            File scriptFile = new File(scriptPath);
            
            if (!scriptFile.exists()) {
                log.warn("⚠️ 白名单脚本不存在: {}", scriptPath);
                out.println("<html><head><meta charset='UTF-8'><title>错误</title></head><body>");
                out.println("<h2 style='color: red;'>❌ 脚本文件不存在</h2>");
                out.println("<p><strong>请求的脚本:</strong> " + file + "</p>");
                out.println("<p><strong>期望路径:</strong> " + scriptPath + "</p>");
                out.println("<p><strong>说明:</strong> 白名单脚本需要预先部署在 /app/file/ 目录。</p>");
                out.println("<p style='color: orange;'>⚠️ 攻击者无法通过上传文件到这个目录来绕过白名单！</p>");
                out.println("</body></html>");
                return;
            }

            // 读取并执行白名单脚本
            log.info("✅ 白名单验证通过，从 /app/file/ 安全执行脚本: {}", scriptPath);
            String scriptContent = Files.readString(scriptFile.toPath());

            // 防御4: 使用受限的 Groovy 环境（沙箱）
            // 这里演示简化版，实际应使用 SecureASTCustomizer 限制脚本权限
            GroovyShell shell = new GroovyShell();
            shell.setVariable("request", request);
            shell.setVariable("response", response);
            shell.setVariable("out", out);

            // 执行白名单脚本（来自应用内，攻击者无法修改）
            Object result = shell.evaluate(scriptContent);

            log.info("✅ 安全脚本执行成功: /app/file/{}, 返回值: {}", file, result);

        } catch (Exception e) {
            log.error("脚本执行失败", e);
            out.println("<html><head><meta charset='UTF-8'><title>执行失败</title></head><body>");
            out.println("<h2 style='color: red;'>❌ 脚本执行失败</h2>");
            out.println("<pre>" + e.getMessage() + "</pre>");
            out.println("</body></html>");
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
