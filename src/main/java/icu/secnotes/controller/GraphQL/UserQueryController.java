package icu.secnotes.controller.GraphQL;

import icu.secnotes.pojo.GraphQLUser;
import icu.secnotes.service.GraphQLUserService;
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
 * GraphQL 用户查询控制器
 *
 * 演示漏洞1 - 字段建议泄露（Introspection）：
 *   开启 Introspection（application.yml 配置），攻击者可通过 __schema
 *   获取完整 Schema，从而发现 salary/ssn/internalNotes 等敏感字段。
 *   安全建议：生产环境设置 spring.graphql.schema.introspection.enabled=false
 *
 * 演示安全方案 - 字段级权限控制（SecureUser）：
 *   敏感字段 Resolver 加 @PreAuthorize("hasRole('ADMIN')")，
 *   即使攻击者知道字段名，没有 ADMIN 角色也无法获取数据。
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class UserQueryController {

    private final GraphQLUserService userService;

    /**
     * 查询单个用户
     * 
     * GraphQL 查询示例：
     * query {
     *   user(id: 1) {
     *     username
     *     email
     *   }
     * }
     */
    @QueryMapping
    public GraphQLUser user(@Argument Long id) {
        log.info("GraphQL 查询用户：id={}", id);
        return userService.findById(id);
    }

    /**
     * 查询用户列表
     * 
     * GraphQL 查询示例：
     * query {
     *   users(limit: 10) {
     *     username
     *     email
     *   }
     * }
     */
    @QueryMapping
    public List<GraphQLUser> users(@Argument Integer limit) {
        log.info("GraphQL 查询用户列表：limit={}", limit);
        return userService.findAll(limit);
    }

    /**
     * User.salary 字段解析器
     * 
     * 漏洞：无权限检查，任何人都可以查询敏感字段
     * 
     * 攻击示例：
     * query {
     *   user(id: 1) {
     *     username
     *     salary     # 敏感字段，应该需要管理员权限
     *   }
     * }
     */
    @SchemaMapping(typeName = "User", field = "salary")
    public Double userSalary(GraphQLUser user) {
        log.warn("⚠️ 查询敏感字段：salary，用户ID={}", user.getId());
        // 漏洞：直接返回，无权限验证
        return user.getSalary();
    }

    /**
     * User.ssn 字段解析器
     * 
     * 漏洞：无权限检查
     */
    @SchemaMapping(typeName = "User", field = "ssn")
    public String userSsn(GraphQLUser user) {
        log.warn("⚠️ 查询敏感字段：ssn，用户ID={}", user.getId());
        return user.getSsn();
    }

    /**
     * User.internalNotes 字段解析器
     * 
     * 漏洞：无权限检查
     */
    @SchemaMapping(typeName = "User", field = "internalNotes")
    public String userInternalNotes(GraphQLUser user) {
        log.warn("⚠️ 查询敏感字段：internalNotes，用户ID={}", user.getId());
        return user.getInternalNotes();
    }

    // ================================================================
    // 安全版：SecureUser 查询（字段级权限控制演示）
    // 与漏洞版使用相同的数据，仅 Resolver 上加了 @PreAuthorize
    // ================================================================

    /**
     * 安全版查询入口：secureUser(id)
     *
     * 基本字段（id/username/email/role）不需要权限即可访问；
     * 敏感字段（salary/ssn/internalNotes）由各自的 @SchemaMapping
     * + @PreAuthorize 单独控制，实现字段级粒度的权限保护。
     */
    @QueryMapping
    public GraphQLUser secureUser(@Argument Long id) {
        log.info("GraphQL 安全版查询用户：id={}", id);
        return userService.findById(id);
    }

    /**
     * SecureUser.salary 字段解析器（安全版）
     *
     * @PreAuthorize 确保只有 ADMIN 角色才能获取薪资。
     * 普通用户查询此字段时 Spring Security 抛出 AccessDeniedException，
     * Spring GraphQL 将其转换为 errors 中的 Forbidden 错误，字段值返回 null。
     */
    @SchemaMapping(typeName = "SecureUser", field = "salary")
    @PreAuthorize("hasRole('ADMIN')")
    public Double secureUserSalary(GraphQLUser user) {
        log.info("✅ ADMIN 查询安全版敏感字段：salary，用户ID={}", user.getId());
        return user.getSalary();
    }

    /**
     * SecureUser.ssn 字段解析器（安全版）
     */
    @SchemaMapping(typeName = "SecureUser", field = "ssn")
    @PreAuthorize("hasRole('ADMIN')")
    public String secureUserSsn(GraphQLUser user) {
        log.info("✅ ADMIN 查询安全版敏感字段：ssn，用户ID={}", user.getId());
        return user.getSsn();
    }

    /**
     * SecureUser.internalNotes 字段解析器（安全版）
     */
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
     *
     * 攻击示例：guest（id=3）调用 myProfile(id: 1) 即可拿到 admin 的薪资、社保号等敏感数据。
     * 漏洞根因：服务端只查了数据库，从未问过"你是谁、你有权访问这条记录吗"。
     */
    @QueryMapping
    public GraphQLUser myProfile(@Argument Long id) {
        log.warn("⚠️ IDOR 漏洞：直接使用客户端传入的 id={}，未验证当前登录用户身份", id);
        return userService.findById(id);
    }

    /**
     * IDOR 安全版：接受 id 参数，但在查询前从 JWT 中提取当前用户 id，
     * 若两者不一致则直接拒绝，确保用户只能查询自己的数据。
     *
     * 修复原则：永远不要信任客户端传入的资源标识符——用服务端可信来源（JWT）校验所有权。
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
        return userService.findById(id);
    }
}
