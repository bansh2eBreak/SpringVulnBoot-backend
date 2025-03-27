package icu.secnotes.utils;

import org.springframework.util.StringUtils;

import java.util.Base64;

/**
 * 安全工具类
 */
public class Security {
    /**
     * sql注入检测
     */
    public static boolean checkSql(String content) {
        String[] black_list = {"'", ";", "and", "exec", "insert", "select", "delete", "update", "count", "*", "chr", "mid", "master", "truncate", "char", "declare", "or"};
        for (String str : black_list) {
            if (content.toLowerCase().contains(str)) {
                return true;
            }
        }
        return false;
    }

    /**
     * xss恶意字符过滤
     */
    public static String xssFilter(String content) {
        content = StringUtils.replace(content, "&", "&amp;");
        content = StringUtils.replace(content, "<", "&lt;");
        content = StringUtils.replace(content, ">", "&gt;");
        content = StringUtils.replace(content, "\"", "&quot;");
        content = StringUtils.replace(content, "'", "&#39;");
        content = StringUtils.replace(content, "/", "&#47;");
        return content;
    }

    /**
     * 命令执行恶意字符检测
     */
    public static boolean checkCommand(String content) {
        String[] black_list = {";", "&&", "||", "`", "$", "(", ")", ">", "<", "|", "\\", "[", "]", "{", "}", "echo", "exec", "system", "passthru", "popen", "proc_open", "shell_exec", "eval", "assert"};
        for (String str : black_list) {
            if (content.toLowerCase().contains(str)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 合法IP地址检测
     */
    public static boolean checkIp(String ip) {
        String[] ipArr = ip.split("\\.");
        if (ipArr.length != 4) {
            return false;
        }
        for (String ipSegment : ipArr) {
            //需要进行异常判断，万一不是数字
            try {
                int ipSegmentInt = Integer.parseInt(ipSegment);
                if (ipSegmentInt < 0 || ipSegmentInt > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /**
     * HTTP Basic Auth认证信息解码
     */
    public static String[] decodeBasicAuth(String token) {
        if (token != null && token.startsWith("Basic ")) {
            String base64Credentials = token.substring(6).trim();
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(decodedBytes);
            return credentials.split(":", 2); // 返回 [username, password]
        }
        return null;
    }

    /**
     * 过滤Log4j2日志中的特殊字符
     */
    public static boolean checkLog4j2(String content) {
        // 检查是否存在Log4j2日志中的特殊字符
        return !content.matches(".*[&${:}<>\"].*");
    }

    /**
     * 文件名检测
     */
    public static boolean checkFilename(String filename) {
        // 使用正则表达式限制文件名只能包含字母、数字、点号和下划线
        String regex = "^[a-zA-Z0-9_.-]+\\.(jpg|jpeg|png|gif)$";
        return filename.matches(regex);
    }

    /**
     * 手机号码正则校验
     */
    public static boolean checkPhone(String phone) {
        // 空值检查
        if (phone == null || phone.isEmpty()) {
            return false;
        }

        // 仅允许数字
        if (!phone.matches("^\\d+$")) {
            return false;
        }

        // 长度必须为11位
        if (phone.length() != 11) {
            return false;
        }

        // 号段验证
        String regex = "^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\\d{8}$";
        return phone.matches(regex);
    }

}