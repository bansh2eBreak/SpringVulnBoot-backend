package icu.secnotes.controller.BusinessLogic;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.PaymentReplayService;
import icu.secnotes.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Tag(name = "支付回调重复处理", description = "同一笔支付成功回调被重复处理，导致余额充值重复到账")
@RestController
@RequestMapping("/businessLogic/paymentReplay")
public class PaymentReplayController {

    @Autowired
    private PaymentReplayService paymentReplayService;

    @Operation(summary = "创建充值订单")
    @PostMapping("/order/create")
    public Result createOrder(HttpServletRequest request) {
        return execute(() -> paymentReplayService.createOrder(currentUserId(request)));
    }

    @Operation(summary = "查询充值订单与余额")
    @GetMapping("/status")
    public Result status(HttpServletRequest request) {
        return execute(() -> paymentReplayService.status(currentUserId(request)));
    }

    @Operation(summary = "重置支付回调测试数据")
    @PostMapping("/reset")
    public Result reset(HttpServletRequest request) {
        return execute(() -> paymentReplayService.reset(currentUserId(request)));
    }

    private Integer currentUserId(HttpServletRequest request) {
        return Integer.valueOf(JwtUtils.parseJwt(request.getHeader("Authorization")).get("id").toString());
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
