package icu.secnotes.controller.Redirect;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@Slf4j
@RequestMapping("/openUrl/")
public class RedirectController {

    @GetMapping("/redirect")
    public String redirect(String url) {
        log.info("重定向到: " + url);
        return url;
    }

    @GetMapping("/redirect2")
    public void redirect2(String url, HttpServletResponse response) throws IOException {
        log.info("重定向到: " + url);
        if (url != null && !url.isEmpty() && (url.startsWith("http") || url.startsWith("https"))) {
            response.sendRedirect(url);
        } else {
            // 处理 URL 为空的情况，例如跳转到默认页面
            response.sendRedirect("http://localhost:9528/?#/dashboard");
        }
    }

    @GetMapping("/secRedirect1")
    public void secRedirect1(String url, HttpServletResponse response) throws IOException {
        log.info("重定向到: " + url);
        if (url.contains("google.com")) {
            response.sendRedirect(url);
        } else {
            // 处理 URL 为空的情况，例如跳转到默认页面
            response.sendRedirect("http://localhost:9528/?#/dashboard");
        }
    }

    @GetMapping("/secRedirect2")
    public void secRedirect2(String url, HttpServletResponse response) throws IOException {
        log.info("重定向到: " + url);
        if ("https://www.google.com".equals(url)) {
            response.sendRedirect(url);
        } else {
            // 处理 URL 为空的情况，例如跳转到默认页面
            response.sendRedirect("http://localhost:9528/?#/dashboard");
        }
    }
}
