package icu.secnotes.service;

import icu.secnotes.mapper.GraphQLEmployeeMapper;
import icu.secnotes.pojo.GraphQLUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * GraphQL 用户服务
 * 数据来源：Admin 表（username、role）JOIN graphql_employee 表（email、salary、ssn、internalNotes）
 */
@Service
@RequiredArgsConstructor
public class GraphQLUserService {

    private final GraphQLEmployeeMapper employeeMapper;

    /**
     * 根据 ID 查询用户（含敏感字段）
     */
    public GraphQLUser findById(Long id) {
        return employeeMapper.findById(id);
    }

    /**
     * 查询用户列表（支持数量限制；limit 为 null 或 ≤0 时查全部）
     */
    public List<GraphQLUser> findAll(Integer limit) {
        if (limit == null || limit <= 0) {
            return employeeMapper.findAll();
        }
        return employeeMapper.findAllWithLimit(limit);
    }
}
