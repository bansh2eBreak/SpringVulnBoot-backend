package icu.secnotes.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.time.LocalDateTime;

@Mapper
public interface UserLoginLogMapper {

    /**
     * 插入登录失败日志
     */
    @Insert("insert into user_login_log( ip, username, loginTime) values(#{ip}, #{username}, #{loginTime})")
    void insertUserLoginLog(String ip, String username, LocalDateTime loginTime);

    /**
     * 根据ip删除所有登录日志
     */
    @Delete("delete from user_login_log where ip = #{ip}")
    void deleteUserLoginLogByIp(String ip);

    /**
     * 根据ip统计最近5分钟的登录失败次数
     */
    @Select("select count(*) from user_login_log where ip = #{ip} and loginTime > date_sub(now(), interval 5 minute)")
    int countUserLoginLogByIp(String ip);
}
