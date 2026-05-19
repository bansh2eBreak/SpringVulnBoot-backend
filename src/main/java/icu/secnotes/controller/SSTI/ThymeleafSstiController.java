package icu.secnotes.controller.SSTI;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashSet;
import java.util.Set;

/**
 * Thymeleaf SSTI（Server-Side Template Injection）漏洞演示 Controller
 *
 * 漏洞原理（viewName 注入）：
 *   Thymeleaf 3.0.12 之前支持 Fragment Expression 语法 __${...}__::fragment，
 *   当 Controller 返回的 view 名（模板路径）包含用户可控内容时，
 *   Thymeleaf 会先把 __${...}__ 作为 SpEL 表达式求值，导致任意代码执行 (RCE)。
 *
 * 本实验使用 Thymeleaf 3.0.11.RELEASE 复现经典 viewName 注入场景。
 *
 * 演示三个场景：
 *   1) /ssti/vuln          - 漏洞版：用户输入直接控制 viewName
 *   2) /ssti/sec/whitelist - 安全版1：白名单校验 lang
 *   3) /ssti/sec/model     - 安全版2：用户输入只走 Model，不进模板路径
 */
@Slf4j
@Controller
@RequestMapping("/ssti")
public class ThymeleafSstiController {

    private static final Set<String> ALLOWED_LANGS = new HashSet<>();

    static {
        ALLOWED_LANGS.add("zh");
        ALLOWED_LANGS.add("en");
    }

    /**
     * 漏洞版：用户输入直接控制 viewName
     * 业务场景：多语言页面切换，根据 lang 参数决定加载哪个模板
     */
    @GetMapping("/vuln")
    public String vuln(@RequestParam(defaultValue = "zh") String lang, Model model) {
        log.warn("⚠️ SSTI viewName 漏洞版：lang={}", lang);
        model.addAttribute("lang", lang);
        return resolveVulnerableViewName(lang);
    }

    /**
     * 安全版1：白名单校验，非白名单 lang 一律 fallback 到 zh
     */
    @GetMapping("/sec/whitelist")
    public String secWhitelist(@RequestParam(defaultValue = "zh") String lang, Model model) {
        if (!ALLOWED_LANGS.contains(lang)) {
            log.info("✅ SSTI安全版1（白名单）：非法 lang={}, fallback 到 zh", lang);
            lang = "zh";
        }
        model.addAttribute("lang", lang);
        return "welcome/" + lang + "/welcome";
    }

    /**
     * 安全版2：view 名硬编码不变，lang 只通过 Model 传递给模板渲染
     */
    @GetMapping("/sec/model")
    public String secModel(@RequestParam(defaultValue = "zh") String lang, Model model) {
        log.info("✅ SSTI安全版2（Model 分离）：lang={}", lang);
        model.addAttribute("lang", lang);
        return "welcome/default";
    }

    private String resolveVulnerableViewName(String lang) {
        if (ALLOWED_LANGS.contains(lang)) {
            return "welcome/" + lang + "/welcome";
        }
        // ❌ 关键漏洞点：非白名单的用户输入直接作为 viewName 返回
        return lang;
    }
}
