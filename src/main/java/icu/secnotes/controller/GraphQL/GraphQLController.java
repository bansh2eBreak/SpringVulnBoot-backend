package icu.secnotes.controller.GraphQL;

import icu.secnotes.pojo.GraphQLUser;
import icu.secnotes.service.GraphQLService;
import icu.secnotes.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * GraphQL 漏洞演示 Controller
 *
 * 演示漏洞1 - 字段泄露（Introspection）：
 *   开启 Introspection（application.yml 配置），攻击者可通过 __schema
 *   获取完整 Schema，从而发现 salary/ssn/internalNotes 等敏感字段。
 *   安全建议：生产环境设置 spring.graphql.schema.introspection.enabled=false
 *
 * 演示漏洞2 - IDOR 越权查询（myProfile）：
 *   直接信任客户端传入的 id，不验证是否是当前登录用户。
 *   安全建议：从 JWT 中获取当前用户 id，与请求 id 比对校验（secureMyProfile）
 *
 * 演示漏洞3 - SQL注入（searchUsers）：
 *   keyword 参数直接拼接到 SQL，攻击入口换成了 GraphQL。
 *   安全建议：使用参数化查询（secureSearchUsers）
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class GraphQLController {

    private final GraphQLService graphQLService;

    // ================================================================
    // 字段泄露漏洞演示（Introspection + 无字段级权限控制）
    // ================================================================

    @QueryMapping
    public GraphQLUser user(@Argument Long id) {
        log.info("GraphQL 查询用户：id={}", id);
        return graphQLService.findById(id);
    }

    @QueryMapping
    public List<GraphQLUser> users(@Argument Integer limit) {
        log.info("GraphQL 查询用户列表：limit={}", limit);
        return graphQLService.findAll(limit);
    }

    /** 漏洞：无权限检查，任何人都可以查询敏感字段 salary */
    @SchemaMapping(typeName = "User", field = "salary")
    public Double userSalary(GraphQLUser user) {
        log.warn("⚠️ 查询敏感字段：salary，用户ID={}", user.getId());
        return user.getSalary();
    }

    /** 漏洞：无权限检查，任何人都可以查询敏感字段 ssn */
    @SchemaMapping(typeName = "User", field = "ssn")
    public String userSsn(GraphQLUser user) {
        log.warn("⚠️ 查询敏感字段：ssn，用户ID={}", user.getId());
        return user.getSsn();
    }

    /** 漏洞：无权限检查，任何人都可以查询敏感字段 internalNotes */
    @SchemaMapping(typeName = "User", field = "internalNotes")
    public String userInternalNotes(GraphQLUser user) {
        log.warn("⚠️ 查询敏感字段：internalNotes，用户ID={}", user.getId());
        return user.getInternalNotes();
    }

    // ================================================================
    // 安全版：字段级权限控制（SecureUser）
    // ================================================================

    @QueryMapping
    public GraphQLUser secureUser(@Argument Long id) {
        log.info("GraphQL 安全版查询用户：id={}", id);
        return graphQLService.findById(id);
    }

    @SchemaMapping(typeName = "SecureUser", field = "salary")
    @PreAuthorize("hasRole('ADMIN')")
    public Double secureUserSalary(GraphQLUser user) {
        log.info("✅ ADMIN 查询安全版敏感字段：salary，用户ID={}", user.getId());
        return user.getSalary();
    }

    @SchemaMapping(typeName = "SecureUser", field = "ssn")
    @PreAuthorize("hasRole('ADMIN')")
    public String secureUserSsn(GraphQLUser user) {
        log.info("✅ ADMIN 查询安全版敏感字段：ssn，用户ID={}", user.getId());
        return user.getSsn();
    }

    @SchemaMapping(typeName = "SecureUser", field = "internalNotes")
    @PreAuthorize("hasRole('ADMIN')")
    public String secureUserInternalNotes(GraphQLUser user) {
        log.info("✅ ADMIN 查询安全版敏感字段：internalNotes，用户ID={}", user.getId());
        return user.getInternalNotes();
    }

    // ================================================================
    // IDOR 越权查询演示
    // ================================================================

    /**
     * IDOR 漏洞版：直接信任客户端传入的 id，不验证是否是当前登录用户
     * 攻击示例：guest（id=3）调用 myProfile(id: 1) 即可拿到 admin 的敏感数据
     */
    @QueryMapping
    public GraphQLUser myProfile(@Argument Long id) {
        log.warn("⚠️ IDOR 漏洞：直接使用客户端传入的 id={}，未验证当前登录用户身份", id);
        return graphQLService.findById(id);
    }

    /**
     * IDOR 安全版：从 JWT 中提取当前用户 id，与请求 id 比对，不一致则拒绝
     */
    @QueryMapping
    public GraphQLUser secureMyProfile(@Argument Long id) {
        HttpServletRequest request = ((ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes()).getRequest();
        String token = request.getHeader("Authorization");
        Long currentUserId = Long.parseLong(JwtUtils.parseJwt(token).get("id").toString());

        if (!currentUserId.equals(id)) {
            log.warn("🚫 IDOR 防御：当前用户 id={} 尝试访问 id={} 的数据，已拦截", currentUserId, id);
            throw new RuntimeException("无权访问：只能查询自己的数据");
        }
        log.info("✅ 安全版：当前用户 id={} 查询自己的数据", currentUserId);
        return graphQLService.findById(id);
    }

    // ================================================================
    // SQL 注入演示
    // ================================================================

    /**
     * SQL注入-漏洞版：keyword 直接拼接到 SQL
     * 攻击示例：searchUsers(keyword: "' OR 1=1 -- ") → 返回所有用户的敏感数据
     */
    @QueryMapping
    public List<GraphQLUser> searchUsers(@Argument String keyword) {
        log.warn("⚠️ GraphQL SQL注入（漏洞版）：keyword={}", keyword);
        return graphQLService.searchByKeyword(keyword);
    }

    /**
     * SQL注入-安全版：参数化查询，相同 payload 无法注入
     */
    @QueryMapping
    public List<GraphQLUser> secureSearchUsers(@Argument String keyword) {
        log.info("✅ GraphQL SQL注入（安全版）：keyword={}", keyword);
        return graphQLService.secureSearchByKeyword(keyword);
    }
}
