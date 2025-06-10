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
    public Result previewImageSec(@RequestParam String url) {
        try {
            // 安全的图片预览实现，包含SSRF防护
            URL imageUrl = new URL(url);
            String host = imageUrl.getHost();
            
            // 检查是否为内网IP，防止SSRF攻击
            if (isInternalIP(host)) {
                return Result.error("不允许访问内网资源");
            }
            
            // 检查协议，只允许HTTP和HTTPS
            String protocol = imageUrl.getProtocol().toLowerCase();
            if (!protocol.equals("http") && !protocol.equals("https")) {
                return Result.error("只支持HTTP和HTTPS协议");
            }
            
            // 检查端口，只允许标准端口
            int port = imageUrl.getPort();
            if (port != -1 && port != 80 && port != 443) {
                return Result.error("只允许访问标准HTTP/HTTPS端口");
            }
            
            URLConnection connection = imageUrl.openConnection();
            connection.setConnectTimeout(5000); // 设置连接超时
            connection.setReadTimeout(10000);   // 设置读取超时
            
            byte[] imageBytes = connection.getInputStream().readAllBytes();
            String base64Image = Base64.getEncoder().encodeToString(imageBytes);
            return Result.success(base64Image);
            
        } catch (Exception e) {
            log.error("安全图片预览失败: {}", e.getMessage());
            return Result.error("图片预览失败: " + e.getMessage());
        }
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