package icu.secnotes.utils;

import org.springframework.util.StringUtils;

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
}