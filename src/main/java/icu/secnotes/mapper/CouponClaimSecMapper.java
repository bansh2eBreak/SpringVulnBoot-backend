package icu.secnotes.mapper;

import icu.secnotes.pojo.CouponClaim;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface CouponClaimSecMapper {

    @Insert("insert into logic_coupon_claim_sec(admin_id, campaign_code, coupon_name, status) values(#{adminId}, #{campaignCode}, #{couponName}, 'UNUSED')")
    int insert(@Param("adminId") Integer adminId, @Param("campaignCode") String campaignCode, @Param("couponName") String couponName);

    @Select("select id, admin_id as adminId, campaign_code as campaignCode, coupon_name as couponName, status, claimed_at as claimedAt from logic_coupon_claim_sec where admin_id = #{adminId} and campaign_code = #{campaignCode} order by id")
    List<CouponClaim> selectByAdminAndCampaign(@Param("adminId") Integer adminId, @Param("campaignCode") String campaignCode);

    @Delete("delete from logic_coupon_claim_sec where admin_id = #{adminId} and campaign_code = #{campaignCode}")
    int deleteByAdminAndCampaign(@Param("adminId") Integer adminId, @Param("campaignCode") String campaignCode);
}
