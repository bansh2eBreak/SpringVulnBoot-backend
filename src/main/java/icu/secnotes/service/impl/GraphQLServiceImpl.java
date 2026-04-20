package icu.secnotes.service.impl;

import icu.secnotes.mapper.GraphQLMapper;
import icu.secnotes.pojo.GraphQLUser;
import icu.secnotes.service.GraphQLService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * GraphQL 漏洞演示 Service 实现类
 * 数据来源：Admin 表（username、role）JOIN graphql_employee 表（email、salary、ssn、internalNotes）
 */
@Service
@RequiredArgsConstructor
public class GraphQLServiceImpl implements GraphQLService {

    private final GraphQLMapper graphQLMapper;

    @Override
    public GraphQLUser findById(Long id) {
        return graphQLMapper.findById(id);
    }

    @Override
    public List<GraphQLUser> findAll(Integer limit) {
        if (limit == null || limit <= 0) {
            return graphQLMapper.findAll();
        }
        return graphQLMapper.findAllWithLimit(limit);
    }

    @Override
    public List<GraphQLUser> searchByKeyword(String keyword) {
        return graphQLMapper.searchByKeyword(keyword);
    }

    @Override
    public List<GraphQLUser> secureSearchByKeyword(String keyword) {
        return graphQLMapper.secureSearchByKeyword(keyword);
    }
}
