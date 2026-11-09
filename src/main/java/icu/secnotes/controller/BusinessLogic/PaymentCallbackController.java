package icu.secnotes.controller.BusinessLogic;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.PaymentReplayService;
import icu.secnotes.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Tag(name = "支付回调模拟入口", description = "用于模拟支付网关重复发送同一笔成功回调")
@RestController
@RequestMapping("/businessLogic/paymentReplay")
public class PaymentCallbackController {

    @Autowired
    private PaymentReplayService paymentReplayService;

    @Operation(summary = "正常支付回调")
    @PostMapping("/normal/notify")
    public Result notifyNormal(@RequestBody Map<String, String> body, HttpServletRequest request) {
        return execute(() -> paymentReplayService.notifySecure(currentUserId(request), rechargeNo(body), transactionNo(body)));
    }

    @Operation(summary = "漏洞版支付回调")
    @PostMapping("/vuln/notify")
    public Result notifyVuln(@RequestBody Map<String, String> body, HttpServletRequest request) {
        return execute(() -> paymentReplayService.notifyVuln(currentUserId(request), rechargeNo(body), transactionNo(body)));
    }

    @Operation(summary = "安全版支付回调")
    @PostMapping("/sec/notify")
    public Result notifySecure(@RequestBody Map<String, String> body, HttpServletRequest request) {
        return execute(() -> paymentReplayService.notifySecure(currentUserId(request), rechargeNo(body), transactionNo(body)));
    }

    private Integer currentUserId(HttpServletRequest request) {
        return Integer.valueOf(JwtUtils.parseJwt(request.getHeader("Authorization")).get("id").toString());
    }

    private String rechargeNo(Map<String, String> body) {
        return body == null ? null : body.get("rechargeNo");
    }

    private String transactionNo(Map<String, String> body) {
        return body == null ? null : body.get("gatewayTransactionNo");
    }

    private Result execute(ServiceCall call) {
        try {
            return Result.success(call.call());
        } catch (IllegalArgumentException e) {
            return Result.error(e.getMessage());
        }
    }

    @FunctionalInterface
    private interface ServiceCall {
        Map<String, Object> call();
    }
}
