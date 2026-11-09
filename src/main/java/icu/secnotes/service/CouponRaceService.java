package icu.secnotes.service;

import java.util.Map;

public interface CouponRaceService {
    String CAMPAIGN_CODE = "NEWUSER-10";

    Map<String, Object> claimVuln(Integer adminId, String campaignCode);

    Map<String, Object> claimSecure(Integer adminId, String campaignCode);

    Map<String, Object> statusVuln(Integer adminId, String campaignCode);

    Map<String, Object> statusSecure(Integer adminId, String campaignCode);

    Map<String, Object> reset(Integer adminId, String campaignCode);
}
