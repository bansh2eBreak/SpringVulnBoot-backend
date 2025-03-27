package icu.secnotes.mapper;

import icu.secnotes.pojo.SmsCode;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.time.LocalDateTime;

@Mapper
public interface SmsCodeMapper {

    /**
     * 插入短信验证码，第一次生成，状态为未使用、有效期为5分钟、重试次数为0
     */
    @Insert("insert into sms_code(phone, code, create_time, expire_time) values(#{phone}, #{code}, #{createTime}, #{expireTime})")
    void insertSmsCode(SmsCode smsCode);

    /**
     * 插入短信验证码，参数是phone和code，其他字段使用默认值
     */
    @Insert("insert into sms_code(phone, code, create_time, expire_time) values(#{phone}, #{code}, #{createTime}, #{expireTime})")
    void insertSmsCodeByPhoneAndCode(String phone, String code, LocalDateTime createTime, LocalDateTime expireTime);

    /**
     * 更新验证码的使用状态
     */
    @Update("update sms_code set used = 1 where phone = #{phone} and code = #{code}")
    void updateSmsCodeUsed(SmsCode smsCode);

    /**
     * 更新“未使用的”验证码的重试次数，每使用一次重试次数加1，并且只更新最新一条未使用的验证码的重试次数
     */
    @Update("update sms_code set retry_count = retry_count + 1 where phone = #{phone} and used = 0 order by create_time desc limit 1")
    void updateSmsCodeRetryCount(String phone);

    /**
     * 查询手机验证码的校验次数，但是根据phone可能查询到多条记录，这里需要只返回最新一条记录的重试次数
     */
    @Select("select retry_count from sms_code where phone = #{phone} order by create_time desc limit 1")
    Integer selectRetryCount(String phone);

    /**
     * 根据phone和code校验短信验证码，限制只能校验未使用且未过期且重试次数小于5的验证码
     */
    @Select("select * from sms_code where phone = #{phone} and code = #{code} and used = 0 and retry_count < 5 and expire_time > now()")
    SmsCode selectByPhoneAndCode(String phone, String code);

    /**
     * 根据phone和code校验短信验证码，未限制验证码的使用状态，可重复使用
     */
    @Select("select * from sms_code where phone = #{phone} and code = #{code} and retry_count < 5 and expire_time > now()")
    SmsCode selectByPhoneAndCode2(String phone, String code);

}
