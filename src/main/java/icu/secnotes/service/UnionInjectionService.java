package icu.secnotes.service;

import icu.secnotes.pojo.Article;
import java.util.List;

/**
 * UNION 联合注入 Service
 */
public interface UnionInjectionService {
    
    /**
     * 使用 ${} 查询文章（漏洞版本）
     * @param id 文章ID
     * @return 文章列表
     */
    List<Article> getArticleByIdVuln(String id);
    
    /**
     * 使用 #{} 查询文章（安全版本）
     * @param id 文章ID
     * @return 文章列表
     */
    List<Article> getArticleByIdSec(String id);
}
