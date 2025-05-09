package icu.secnotes.mapper;

import icu.secnotes.pojo.MfaSecret;
import org.apache.ibatis.annotations.*;

@Mapper
public interface MfaSecretMapper {

    /**
     * 生成用户的mfa secret字符串
     * @param mfaSecret
     * @return
     */
    @Insert("insert into mfa_secret(userId, secret, create_time, update_time) values (#{userId}, #{secret}, #{createTime}, #{updateTime})")
    int insert(MfaSecret mfaSecret);

    /**
     * 删除用户的mfa secret字符串，相当于重置MFA
     * @param mfaSecret
     * @return
     */
    @Delete("delete from mfa_secret where userId = #{userId}")
    int delete(MfaSecret mfaSecret);

    /**
     * 根据用户ID查询MFA密钥
     * @param userId
     * @return
     */
    @Select("select * from mfa_secret where userId = #{userId}")
    MfaSecret selectByUserId(Integer userId);

    /**
     * 更新用户的mfa secret字符串
     * @param mfaSecret
     * @return
     */
    @Update("update mfa_secret SET secret = #{secret}, update_time = #{updateTime} where id = #{id}")
    int update(MfaSecret mfaSecret);

}
