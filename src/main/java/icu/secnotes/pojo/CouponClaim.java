package icu.secnotes.pojo;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class CouponClaim {
    private Long id;
    private Integer adminId;
    private String campaignCode;
    private String couponName;
    private String status;
    private LocalDateTime claimedAt;
}
