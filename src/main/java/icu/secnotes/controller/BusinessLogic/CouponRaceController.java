package icu.secnotes.controller.BusinessLogic;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.CouponRaceService;
import icu.secnotes.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Tag(name = "优惠券并发超用", description = "先查询后插入导致同一测试账户可并发领取多张优惠券")
@RestController
@RequestMapping("/businessLogic/couponRace")
public class CouponRaceController {

    @Autowired
    private CouponRaceService couponRaceService;

    @Operation(summary = "漏洞版领取优惠券")
    @PostMapping("/vuln/claim")
    public Result claimVuln(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            return Result.success(couponRaceService.claimVuln(currentAdminId(request), campaignCode(body)));
        } catch (IllegalArgumentException e) {
            return Result.error(e.getMessage());
        }
    }

    @Operation(summary = "正常流程领取优惠券")
    @PostMapping("/normal/claim")
    public Result claimNormal(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            return Result.success(couponRaceService.claimVuln(currentAdminId(request), campaignCode(body)));
        } catch (IllegalArgumentException e) {
            return Result.error(e.getMessage());
        }
    }

    @Operation(summary = "查询正常流程领取记录")
    @GetMapping("/normal/status")
    public Result statusNormal(HttpServletRequest request) {
        return Result.success(couponRaceService.statusVuln(currentAdminId(request), CouponRaceService.CAMPAIGN_CODE));
    }

    @Operation(summary = "查询漏洞版领取记录")
    @GetMapping("/vuln/status")
    public Result statusVuln(HttpServletRequest request) {
        return Result.success(couponRaceService.statusVuln(currentAdminId(request), CouponRaceService.CAMPAIGN_CODE));
    }

    @Operation(summary = "安全版领取优惠券")
    @PostMapping("/sec/claim")
    public Result claimSecure(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            return Result.success(couponRaceService.claimSecure(currentAdminId(request), campaignCode(body)));
        } catch (IllegalArgumentException e) {
            return Result.error(e.getMessage());
        }
    }

    @Operation(summary = "查询安全版领取记录")
    @GetMapping("/sec/status")
    public Result statusSecure(HttpServletRequest request) {
        return Result.success(couponRaceService.statusSecure(currentAdminId(request), CouponRaceService.CAMPAIGN_CODE));
    }

    @Operation(summary = "重置当前测试账户的优惠券记录")
    @PostMapping("/reset")
    public Result reset(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            return Result.success(couponRaceService.reset(currentAdminId(request), campaignCode(body)));
        } catch (IllegalArgumentException e) {
            return Result.error(e.getMessage());
        }
    }

    private Integer currentAdminId(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        return Integer.valueOf(JwtUtils.parseJwt(token).get("id").toString());
    }

    private String campaignCode(Map<String, String> body) {
        return body == null ? null : body.get("campaignCode");
    }
}
