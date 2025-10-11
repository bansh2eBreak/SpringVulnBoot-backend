package icu.secnotes.mapper;

import icu.secnotes.pojo.Admin;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

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
    
    /**
     * 修改密码 - 存在CSRF漏洞（不验证旧密码）
     * @param userId 用户ID
     * @param newPassword 新密码
     * @return 影响行数
     */
    @Update("update admin set password = #{newPassword} where id = #{userId}")
    int changePassword(@Param("userId") String userId, @Param("newPassword") String newPassword);
    
    /**
     * 修改密码 - CSRF防护（验证旧密码）
     * @param userId 用户ID
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     * @return 影响行数
     */
    @Update("update admin set password = #{newPassword} where id = #{userId} and password = #{oldPassword}")
    int changePasswordSecure(@Param("userId") String userId, @Param("oldPassword") String oldPassword, @Param("newPassword") String newPassword);
    
    /**
     * 验证旧密码
     * @param userId 用户ID
     * @param oldPassword 旧密码
     * @return 管理员信息
     */
    @Select("select * from admin where id = #{userId} and password = #{oldPassword}")
    Admin verifyOldPassword(@Param("userId") String userId, @Param("oldPassword") String oldPassword);

}
