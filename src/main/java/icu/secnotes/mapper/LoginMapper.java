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
    @Select("select * from admin where username = #{username} and password = #{password}")
    Admin login(Admin admin);

    /**
     * 根据id获取管理员信息
     */
    @Select("select * from admin where id = #{id}")
    Admin getAdminById(@Param("id") String id);

}
