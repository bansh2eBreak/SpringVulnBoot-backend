package icu.secnotes.controller.PathTraversal;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
@RestController
@RequestMapping("/zipslip")
public class ZipSlipController {

    private static final String BASE_DIR = "/app/file/zipslip/";
    private static final String UPLOAD_DIR = BASE_DIR + "uploads/";
    private static final String EXTRACT_DIR = BASE_DIR + "extracted/";

    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            Files.createDirectories(Paths.get(EXTRACT_DIR));
            log.info("ZIP Slip 目录创建成功: uploads={}, extracted={}", UPLOAD_DIR, EXTRACT_DIR);
        } catch (Exception e) {
            log.error("创建 ZIP Slip 目录失败", e);
        }
    }

    @PostMapping("/vuln")
    public Result vuln(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请上传 ZIP 文件");
        }

        byte[] zipBytes;
        try {
            zipBytes = file.getBytes();
        } catch (IOException e) {
            return Result.error("读取文件失败: " + e.getMessage());
        }

        Map<String, Object> result = new LinkedHashMap<>();
        String savedZipPath = saveOriginalZip(zipBytes, file.getOriginalFilename(), "vuln");
        result.put("originalZip", savedZipPath);

        List<Map<String, String>> entries = new ArrayList<>();

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Map<String, String> entryInfo = new LinkedHashMap<>();
                entryInfo.put("entryName", entry.getName());

                // ❌ 关键漏洞点：直接用 zipEntry.getName() 拼接路径，不做任何校验
                File outputFile = new File(EXTRACT_DIR, entry.getName());
                entryInfo.put("resolvedPath", outputFile.getAbsolutePath());

                boolean isTraversal = !outputFile.getCanonicalPath()
                        .startsWith(new File(EXTRACT_DIR).getCanonicalPath() + File.separator);
                entryInfo.put("pathTraversal", String.valueOf(isTraversal));

                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                    entryInfo.put("type", "directory");
                } else {
                    outputFile.getParentFile().mkdirs();
                    long size = 0;
                    try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                            size += len;
                        }
                    }
                    entryInfo.put("type", "file");
                    entryInfo.put("size", size + " bytes");
                    log.warn("ZIP Slip 漏洞版 - 写入文件: {}", outputFile.getAbsolutePath());
                }
                entries.add(entryInfo);
                zis.closeEntry();
            }
        } catch (IOException e) {
            log.error("ZIP 解压失败", e);
            return Result.error("解压失败: " + e.getMessage());
        }

        result.put("extractDir", EXTRACT_DIR);
        result.put("entries", entries);
        return Result.success(result);
    }

    @PostMapping("/sec")
    public Result sec(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请上传 ZIP 文件");
        }

        byte[] zipBytes;
        try {
            zipBytes = file.getBytes();
        } catch (IOException e) {
            return Result.error("读取文件失败: " + e.getMessage());
        }

        Map<String, Object> result = new LinkedHashMap<>();
        String savedZipPath = saveOriginalZip(zipBytes, file.getOriginalFilename(), "sec");
        result.put("originalZip", savedZipPath);

        List<Map<String, String>> entries = new ArrayList<>();
        File destDir = new File(EXTRACT_DIR);

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            String destDirPath = destDir.getCanonicalPath();
            ZipEntry entry;

            while ((entry = zis.getNextEntry()) != null) {
                Map<String, String> entryInfo = new LinkedHashMap<>();
                entryInfo.put("entryName", entry.getName());

                File outputFile = new File(destDir, entry.getName());
                String outputFilePath = outputFile.getCanonicalPath();
                entryInfo.put("resolvedPath", outputFilePath);

                // ✅ 安全校验：规范化路径后检查是否仍在目标目录内
                if (!outputFilePath.startsWith(destDirPath + File.separator)) {
                    entryInfo.put("pathTraversal", "true");
                    entryInfo.put("blocked", "true");
                    log.warn("ZIP Slip 攻击被拦截！条目: {} -> 实际路径: {}", entry.getName(), outputFilePath);

                    entries.add(entryInfo);
                    result.put("extractDir", EXTRACT_DIR);
                    result.put("entries", entries);
                    result.put("blocked", true);
                    result.put("blockReason", "检测到 ZIP Slip 攻击！恶意条目: " + entry.getName()
                            + " -> 试图写入: " + outputFilePath
                            + "（超出允许目录: " + destDirPath + "）");
                    return Result.success(result);
                }

                entryInfo.put("pathTraversal", "false");

                if (entry.isDirectory()) {
                    outputFile.mkdirs();
                    entryInfo.put("type", "directory");
                } else {
                    outputFile.getParentFile().mkdirs();
                    long size = 0;
                    try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                            size += len;
                        }
                    }
                    entryInfo.put("type", "file");
                    entryInfo.put("size", size + " bytes");
                }
                entries.add(entryInfo);
                log.info("ZIP 安全解压: {}", outputFile.getAbsolutePath());
                zis.closeEntry();
            }
        } catch (IOException e) {
            log.error("ZIP 解压失败", e);
            return Result.error("解压失败: " + e.getMessage());
        }

        result.put("extractDir", EXTRACT_DIR);
        result.put("entries", entries);
        result.put("blocked", false);
        return Result.success(result);
    }

    private String saveOriginalZip(byte[] zipBytes, String originalFilename, String scene) {
        String fileName = scene + "_" + System.currentTimeMillis() + "_" + originalFilename;
        File dest = new File(UPLOAD_DIR, fileName);
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(zipBytes);
            log.info("原始 ZIP 已保存: {}", dest.getAbsolutePath());
            return dest.getAbsolutePath();
        } catch (IOException e) {
            log.error("保存原始 ZIP 失败", e);
            return "保存失败: " + e.getMessage();
        }
    }
}
