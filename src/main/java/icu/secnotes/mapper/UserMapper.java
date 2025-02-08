package icu.secnotes.mapper;

import icu.secnotes.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;
import java.util.List;

@Mapper
@Repository
public interface UserMapper {
    /**
     * 根据id查询用户，演示sql注入
     * @param id
     * @return
     */
    @Select("select * from user where id = ${id}")
    List<User> selectUserById(String id);

    /**
     * 根据id查询用户，演示sql注入
     * @param username
     * @return
     */
    @Select("select * from user where username = '${username}'")
    List<User> selectUserByUsername(@Param("username") String username);

    /**
     * 根据username查询用户，使用预编译
     * @param username
     * @return
     */
    @Select("select * from user where username = #{username}")
    List<User> selectUserSecByUsername(@Param("username") String username);

    /**
     * 查询总记录数
     */
    @Select("select count(*) from user")
    int count();

    /**
     * 支持按字段排序的分页查询，获取用户列表数据
     */
    @Select("select * from user order by ${orderBy} limit #{start}, #{pageSize}")
    List<User> pageOrderBy(@Param("orderBy") String orderBy, @Param("start") int start, @Param("pageSize") int pageSize);

    /**
     * 账号密码登录
     */
    @Select("select * from user where username = #{username} and password = #{password}")
    User passwordLogin(User user);

    @Select("select * from user where username = #{username} and password = #{password}")
    User passwordLogin2(String username, String password);

}
