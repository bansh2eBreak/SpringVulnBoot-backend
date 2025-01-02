package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.UserService;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * sql注入漏洞-mybatis
 */
@RestController
@RequestMapping("/sqli/mybatis")
@Slf4j
public class MybatisController {
    
    @Autowired
    private UserService userService;

    /**
     * Mybatis：数字型sql注入-路径参数
     * @Poc http://127.0.0.1:8080/sqlin/getUserById/1 or 1=2
     * @param id 用户id
     * @return List<User>集合
     */
    @GetMapping("/getUserById/{id}")
    public Result getUserById(@PathVariable String id) {
        return Result.success(userService.selectUserById(id));
    }

    /**
     * Mybatis：数字型sql注入-普通参数
     * @Poc http://127.0.0.1:8080/sqlin/getUserById?id=1 or 1=1
     * @param id 用户id
     * @return List<User>集合
     */
    @GetMapping("/getUserById")
    public Result getUserById2(String id) {
        return Result.success(userService.selectUserById(id));
    }

    /**
     * Mybatis：字符型sql注入-路径参数
     * @Poc http://127.0.0.1:8080/sqlin/getUserByUsername/lisi' or 'f'='f
     * @param username
     * @return
     */
    @GetMapping("/getUserByUsername/{username}")
    public Result getUserByUsername(@PathVariable String username) {
        return Result.success(userService.selecctUserByUsername(username));
    }

    /**
     * Mybatis：预编译
     * @param username
     * @return
     */
    @GetMapping("/getUserSecByUsername")
    public Result getUserSecByUsername(String username) {
        return Result.success(userService.selecctUserSecByUsername(username));
    }

    /**
     * Mybatis：恶意字符过滤
     */
    @GetMapping("/getUserSecByUsernameFilter")
    public Result getUserSecByUsernameFilter(String username) {
        if (!Security.checkSql(username)) {
            return Result.success(userService.selecctUserByUsername(username));
        } else {
            log.warn("检测到非法注入字符: {}", username);
            return Result.error("检测到非法注入");
        }
    }

    /**
     * Mybatis：字符型sql注入-普通参数
     * @Poc http://127.0.0.1:8080/sqli/mybatis/getUserByUsername?username=zhangsan' or 'f'='f
            http://127.0.0.1:8080/sqli/mybatis/getUserByUsername?username=zhangsan' or 1=1 --
     * @param username
     * @return
     */
    @GetMapping("/getUserByUsername")
    public Result getUserByUsername2(String username) {
        return Result.success(userService.selecctUserByUsername(username));
    }

    /**
     * 分页查询
     */
    @GetMapping("/getUserByPage")
    public Result getUserByPage(@RequestParam(defaultValue = "id") String orderBy, @RequestParam(defaultValue = "1") Integer page, @RequestParam(defaultValue = "5") Integer pageSize) {
        log.info("分页查询，参数：{} {} {}", page, pageSize, orderBy);
        return Result.success(userService.pageOrderBy(orderBy, page, pageSize));
    }
}
