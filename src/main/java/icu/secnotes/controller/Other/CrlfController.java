package icu.secnotes.controller.Other;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * CRLF 注入（HTTP 响应头注入）漏洞演示控制器
 *
 * 漏洞版：解析用户输入中的 \r\n，将提取出的头部通过 addHeader() 真实注入，
 * 将提取出的响应体内容直接写入 HTML 响应（XSS 可真实触发）。
 *
 * 安全版：过滤 \r\n 后再设置头部。
 */
@RestController
@RequestMapping("/crlf")
@Slf4j
@Tag(name = "CRLF注入漏洞", description = "HTTP响应头注入漏洞演示")
public class CrlfController {

    @GetMapping("/vuln")
    @Operation(summary = "CRLF注入漏洞版", description = "用户输入直接拼接到响应头，可注入任意头部或响应体")
    public void vuln(@RequestParam String input, HttpServletResponse response) throws IOException {
        log.info("CRLF 漏洞版测试，input: {}", input.replace("\r", "\\r").replace("\n", "\\n"));

        String[] parts = input.split("\r\n", -1);

        response.setHeader("X-Custom-Header", parts[0]);

        boolean bodyStarted = false;
        boolean hasLocation = false;
        StringBuilder injectedBody = new StringBuilder();

        for (int i = 1; i < parts.length; i++) {
            if (bodyStarted) {
                injectedBody.append(parts[i]);
                if (i < parts.length - 1) injectedBody.append("\n");
                continue;
            }
            if (parts[i].isEmpty()) {
                bodyStarted = true;
                continue;
            }
            int colonIdx = parts[i].indexOf(':');
            if (colonIdx > 0) {
                String headerName = parts[i].substring(0, colonIdx).trim();
                String headerValue = parts[i].substring(colonIdx + 1).trim();
                response.addHeader(headerName, headerValue);
                if ("location".equalsIgnoreCase(headerName)) {
                    hasLocation = true;
                }
            }
        }

        if (hasLocation) {
            response.setStatus(HttpServletResponse.SC_FOUND);
        }

        response.setContentType("text/html; charset=utf-8");
        PrintWriter writer = response.getWriter();

        if (bodyStarted && injectedBody.length() > 0) {
            writer.write(injectedBody.toString());
        } else {
            String escapedInput = escapeHtml(input.replace("\r", "\\r").replace("\n", "\\n"));
            writer.write("<html><body>");
            writer.write("<h3>CRLF 漏洞版</h3>");
            writer.write("<p>原始输入: <code>" + escapedInput + "</code></p>");
            writer.write("<p>X-Custom-Header: <code>" + escapeHtml(parts[0]) + "</code></p>");
            if (!hasLocation) {
                writer.write("<p style='color:red;'>\\r\\n 未被过滤，注入的头部已生效（请查看 F12 响应头）。</p>");
            }
            writer.write("</body></html>");
        }
        writer.flush();
    }

    @GetMapping("/sec")
    @Operation(summary = "CRLF注入安全版", description = "过滤\\r\\n字符后再设置响应头")
    public void sec(@RequestParam String input, HttpServletResponse response) throws IOException {
        log.info("CRLF 安全版测试，input: {}", input.replace("\r", "\\r").replace("\n", "\\n"));

        String sanitized = input.replaceAll("[\\r\\n]", "");

        response.setHeader("X-Custom-Header", sanitized);
        response.setContentType("text/html; charset=utf-8");

        PrintWriter writer = response.getWriter();
        writer.write("<html><body>");
        writer.write("<h3>CRLF 安全版</h3>");
        writer.write("<p>原始输入: <code>" + escapeHtml(input.replace("\r", "\\r").replace("\n", "\\n")) + "</code></p>");
        writer.write("<p>过滤后: <code>" + escapeHtml(sanitized) + "</code></p>");
        writer.write("<p>X-Custom-Header: <code>" + escapeHtml(sanitized) + "</code></p>");
        writer.write("<p style='color:green;'>\\r\\n 已被过滤，无法注入额外响应头。</p>");
        writer.write("</body></html>");
        writer.flush();
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
