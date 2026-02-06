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

    /**
     * 更新管理员信息（通用动态更新方法）
     * 
     * ⚠️ Mass Assignment 漏洞成因（通用方法被滥用）：
     * 
     * 1. 最初目的：这是为"管理员后台"设计的通用更新方法
     *    - 使用 MyBatis 动态 SQL（<if test>），自动更新传入的所有非空字段
     *    - 管理员可以灵活修改用户的任意信息（name、avatar、role、password 等）
     *    - 这种设计在管理员后台是合理的，因为管理员有权限修改任何信息
     * 
     * 2. 被误用场景：后来开发者为了方便，将这个通用方法复用到了"用户修改头像"功能
     *    - Controller 层直接接收 Admin 实体类，调用此通用方法
     *    - 由于是动态 SQL，传入什么字段就更新什么字段
     *    - 普通用户可以通过注入 role 参数来修改自己的角色（提权）
     * 
     * 3. 根本问题：不同权限场景混用了同一个通用方法
     *    - 管理员后台修改：允许更新所有字段（正常）
     *    - 用户修改头像：应该只允许更新部分字段（危险）
     * 
     * 
     * @param admin 管理员对象（传入的非空字段都会被更新）
     * @return 影响行数
     */
    @Update("<script>" +
            "UPDATE admin " +
            "<set>" +
            "  <if test='name != null'>name = #{name},</if>" +
            "  <if test='avatar != null'>avatar = #{avatar},</if>" +
            "  <if test='role != null'>role = #{role},</if>" +
            "  <if test='password != null'>password = #{password},</if>" +
            "</set>" +
            "WHERE id = #{id}" +
            "</script>")
    int updateAdmin(Admin admin);

}
