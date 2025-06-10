package icu.secnotes.controller.SSRF;

import icu.secnotes.pojo.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.Base64;

@RestController
@Slf4j
@RequestMapping("/ssrf")
public class SSRFController {

    @GetMapping("/vuln1")
    public Result previewImageVuln(@RequestParam String url) {
        try {
            // 直接使用用户输入的URL获取图片，没有进行任何过滤
            URL imageUrl = new URL(url);
            URLConnection connection = imageUrl.openConnection();
            byte[] imageBytes = connection.getInputStream().readAllBytes();
            String base64Image = Base64.getEncoder().encodeToString(imageBytes);
            return Result.success(base64Image);
        } catch (Exception e) {
            return Result.error("图片预览失败: " + e.getMessage());
        }
    }

    @GetMapping("/sec1")
    public void previewImageSec(@RequestParam String url) {
        
    }

    private boolean isInternalIP(String host) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            return addr.isLoopbackAddress() || 
                   addr.isSiteLocalAddress() || 
                   addr.isLinkLocalAddress() ||
                   addr.isAnyLocalAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }
} 