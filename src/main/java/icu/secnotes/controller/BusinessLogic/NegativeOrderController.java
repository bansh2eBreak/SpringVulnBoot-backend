package icu.secnotes.controller.BusinessLogic;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.NegativeOrderService;
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

@Tag(name = "负数下单", description = "遗漏购买数量下限校验，导致负数订单金额使余额反向增加")
@RestController
@RequestMapping("/businessLogic/negativeOrder")
public class NegativeOrderController {

    @Autowired
    private NegativeOrderService negativeOrderService;

    @Operation(summary = "正常流程下单")
    @PostMapping("/normal/order")
    public Result orderNormal(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        return execute(() -> negativeOrderService.orderNormal(currentUserId(request), quantity(body)));
    }

    @Operation(summary = "负数下单漏洞版")
    @PostMapping("/vuln/order")
    public Result orderVuln(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        return execute(() -> negativeOrderService.orderVuln(currentUserId(request), quantity(body)));
    }

    @Operation(summary = "负数下单安全版")
    @PostMapping("/sec/order")
    public Result orderSecure(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        return execute(() -> negativeOrderService.orderSecure(currentUserId(request), quantity(body)));
    }

    @Operation(summary = "查询正常流程订单")
    @GetMapping("/normal/status")
    public Result statusNormal(HttpServletRequest request) {
        return execute(() -> negativeOrderService.status(currentUserId(request)));
    }

    @Operation(summary = "查询漏洞版订单")
    @GetMapping("/vuln/status")
    public Result statusVuln(HttpServletRequest request) {
        return execute(() -> negativeOrderService.status(currentUserId(request)));
    }

    @Operation(summary = "查询安全版订单")
    @GetMapping("/sec/status")
    public Result statusSecure(HttpServletRequest request) {
        return execute(() -> negativeOrderService.status(currentUserId(request)));
    }

    @Operation(summary = "重置负数下单测试数据")
    @PostMapping("/reset")
    public Result reset(HttpServletRequest request) {
        return execute(() -> negativeOrderService.reset(currentUserId(request)));
    }

    /**
     * 当前靶场统一认证仍由 Admin 表承载；订单域将该身份抽象为 userId。
     */
    private Integer currentUserId(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        return Integer.valueOf(JwtUtils.parseJwt(token).get("id").toString());
    }

    private Integer quantity(Map<String, Object> body) {
        if (body == null || body.get("quantity") == null) {
            return null;
        }
        Object value = body.get("quantity");
        try {
            return Integer.valueOf(String.valueOf(value).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("购买数量必须是整数");
        }
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
