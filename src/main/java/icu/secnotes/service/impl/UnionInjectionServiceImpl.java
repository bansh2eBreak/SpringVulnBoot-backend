package icu.secnotes.service.impl;

import icu.secnotes.mapper.UnionInjectionMapper;
import icu.secnotes.pojo.Article;
import icu.secnotes.service.UnionInjectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * UNION 联合注入 Service 实现类
 */
@Service
public class UnionInjectionServiceImpl implements UnionInjectionService {
    
    @Autowired
    private UnionInjectionMapper unionInjectionMapper;
    
    @Override
    public List<Article> getArticleByIdVuln(String id) {
        return unionInjectionMapper.getArticleByIdVuln(id);
    }
    
    @Override
    public List<Article> getArticleByIdSec(String id) {
        return unionInjectionMapper.getArticleByIdSec(id);
    }
}
