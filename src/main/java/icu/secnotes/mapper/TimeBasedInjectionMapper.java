package icu.secnotes.mapper;

import icu.secnotes.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import java.util.List;

@Mapper
public interface TimeBasedInjectionMapper {
    /**
     * 根据username查询用户，用于演示基于时间盲注
     * @param username
     * @return
     */
    @Select("SELECT * FROM user WHERE username = '${username}'")
    List<User> selectUserByUsernameTime(String username);
    
    /**
     * 根据username查询用户，用于演示防御基于时间盲注
     * @param username
     * @return
     */
    @Select("SELECT * FROM user WHERE username = #{username}")
    List<User> selectUserByUsernameTimeSafe(String username);

}