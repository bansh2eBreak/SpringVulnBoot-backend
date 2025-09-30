package icu.secnotes.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Mapper
public interface UserLoginLogMapper {

    /**
     * 插入登录日志
     */
    @Insert("insert into user_login_log( ip, username, loginTime, loginResult) values(#{ip}, #{username}, #{loginTime}, #{loginResult})")
    void insertUserLoginLog(String ip, String username, LocalDateTime loginTime, String loginResult);

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
    
    /**
     * 查询所有用户的最新登录日志
     */
    @Select("select id, ip, username, loginTime, loginResult from user_login_log order by loginTime desc limit 10")
    List<Map<String, Object>> getAllUserLoginLogs();
    
}
