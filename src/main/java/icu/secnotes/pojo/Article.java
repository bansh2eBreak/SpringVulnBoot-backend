package icu.secnotes.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

/**
 * 文章实体类
 * 用于 UNION 注入漏洞演示
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Article {
    
    /**
     * 文章ID
     */
    private Integer id;
    
    /**
     * 文章标题
     */
    private String title;
    
    /**
     * 作者
     */
    private String author;
    
    /**
     * 文章内容
     */
    private String content;
    
    /**
     * 发布时间
     */
    private LocalDateTime createTime;
}
