package icu.secnotes.mapper;

import icu.secnotes.pojo.Admin;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface LoginMapper {

    /**
     * 管理员登录
     * @param admin
     * @return
     */
    @Select("select id, username, token, avator from admin where username = #{username} and password = #{password}")
    Admin login(Admin admin);

    /**
     * 根据用户token获取用户信息
     * @param token
     * @return
     */
    @Select("select * from Admin where token = #{token}")
    Admin getAdminByToken(@Param("token") String token);

}
