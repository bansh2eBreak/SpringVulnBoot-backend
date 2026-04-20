package icu.secnotes.service;

import icu.secnotes.pojo.GraphQLUser;
import java.util.List;

/**
 * GraphQL 漏洞演示 Service 接口
 */
public interface GraphQLService {

    GraphQLUser findById(Long id);

    List<GraphQLUser> findAll(Integer limit);

    /** SQL注入-漏洞版：keyword 直接拼接到 SQL */
    List<GraphQLUser> searchByKeyword(String keyword);

    /** SQL注入-安全版：参数化查询 */
    List<GraphQLUser> secureSearchByKeyword(String keyword);
}
