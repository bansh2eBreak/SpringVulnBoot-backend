package icu.secnotes.mapper;

import icu.secnotes.pojo.GraphQLUser;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * GraphQL 员工数据 Mapper
 *
 * 查询时 JOIN Admin 表（获取 username、role）和 graphql_employee 表（获取敏感字段），
 * 使 GraphQL 用户 ID 与登录系统（JWT）中的 Admin.id 保持一致，便于 IDOR 演示。
 */
@Mapper
@Repository
public interface GraphQLEmployeeMapper {

    /**
     * 根据 ID 查询员工完整信息（含敏感字段）
     */
    @Select("SELECT a.id, a.username, a.role, " +
            "e.email, e.salary, e.ssn, e.internal_notes AS internalNotes " +
            "FROM Admin a JOIN graphql_employee e ON a.id = e.id " +
            "WHERE a.id = #{id}")
    GraphQLUser findById(@Param("id") Long id);

    /**
     * 查询员工列表（支持数量限制）
     */
    @Select("SELECT a.id, a.username, a.role, " +
            "e.email, e.salary, e.ssn, e.internal_notes AS internalNotes " +
            "FROM Admin a JOIN graphql_employee e ON a.id = e.id " +
            "LIMIT #{limit}")
    List<GraphQLUser> findAllWithLimit(@Param("limit") int limit);

    /**
     * 查询全部员工列表（不限数量）
     */
    @Select("SELECT a.id, a.username, a.role, " +
            "e.email, e.salary, e.ssn, e.internal_notes AS internalNotes " +
            "FROM Admin a JOIN graphql_employee e ON a.id = e.id")
    List<GraphQLUser> findAll();
}
