package icu.secnotes.service.impl;

import icu.secnotes.mapper.CouponClaimSecMapper;
import icu.secnotes.mapper.CouponClaimVulnMapper;
import icu.secnotes.pojo.CouponClaim;
import icu.secnotes.service.CouponRaceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class CouponRaceServiceImpl implements CouponRaceService {

    private static final String COUPON_NAME = "新人满 100 减 10 元券";

    @Autowired
    private CouponClaimVulnMapper couponClaimVulnMapper;

    @Autowired
    private CouponClaimSecMapper couponClaimSecMapper;

    /**
     * 漏洞版：先查询是否领取，再插入记录。两个并发事务可同时读到 0。
     */
    @Override
    @Transactional
    public Map<String, Object> claimVuln(Integer adminId, String campaignCode) {
        requireCampaign(campaignCode);
        int count = couponClaimVulnMapper.countByAdminAndCampaign(adminId, campaignCode);
        if (count > 0) {
            return claimResult(false, "每人限领一张", count);
        }

        couponClaimVulnMapper.insert(adminId, campaignCode, COUPON_NAME);
        return claimResult(true, "领取成功", count + 1);
    }

    /**
     * 安全版：数据库联合唯一索引保证同一管理员和活动券最多一条记录。
     */
    @Override
    @Transactional
    public Map<String, Object> claimSecure(Integer adminId, String campaignCode) {
        requireCampaign(campaignCode);
        try {
            couponClaimSecMapper.insert(adminId, campaignCode, COUPON_NAME);
            return claimResult(true, "领取成功", 1);
        } catch (DuplicateKeyException e) {
            return claimResult(false, "每人限领一张", 1);
        }
    }

    @Override
    public Map<String, Object> statusVuln(Integer adminId, String campaignCode) {
        requireCampaign(campaignCode);
        return status(couponClaimVulnMapper.selectByAdminAndCampaign(adminId, campaignCode));
    }

    @Override
    public Map<String, Object> statusSecure(Integer adminId, String campaignCode) {
        requireCampaign(campaignCode);
        return status(couponClaimSecMapper.selectByAdminAndCampaign(adminId, campaignCode));
    }

    @Override
    @Transactional
    public Map<String, Object> reset(Integer adminId, String campaignCode) {
        requireCampaign(campaignCode);
        couponClaimVulnMapper.deleteByAdminAndCampaign(adminId, campaignCode);
        couponClaimSecMapper.deleteByAdminAndCampaign(adminId, campaignCode);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("message", "当前测试账户的优惠券记录已重置");
        result.put("campaignCode", campaignCode);
        return result;
    }

    private void requireCampaign(String campaignCode) {
        if (!CAMPAIGN_CODE.equals(campaignCode)) {
            throw new IllegalArgumentException("活动券不存在或已结束");
        }
    }

    private Map<String, Object> claimResult(boolean claimed, String message, int claimCount) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("claimed", claimed);
        result.put("message", message);
        result.put("claimCount", claimCount);
        return result;
    }

    private Map<String, Object> status(List<CouponClaim> claims) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("campaignCode", CAMPAIGN_CODE);
        result.put("couponName", COUPON_NAME);
        result.put("claimCount", claims.size());
        result.put("claims", claims);
        return result;
    }
}
