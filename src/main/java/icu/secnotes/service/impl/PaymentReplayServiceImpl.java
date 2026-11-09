package icu.secnotes.service.impl;

import icu.secnotes.mapper.RechargeOrderMapper;
import icu.secnotes.pojo.RechargeOrder;
import icu.secnotes.service.PaymentReplayService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class PaymentReplayServiceImpl implements PaymentReplayService {

    private static final BigDecimal RECHARGE_AMOUNT = new BigDecimal("100.00");
    private static final BigDecimal INITIAL_BALANCE = new BigDecimal("1000.00");

    @Autowired
    private RechargeOrderMapper rechargeOrderMapper;

    @Override
    @Transactional
    public Map<String, Object> createOrder(Integer userId) {
        requireBalance(userId);
        RechargeOrder order = new RechargeOrder();
        order.setUserId(userId);
        order.setRechargeNo("RCH" + uuidPart());
        order.setAmount(RECHARGE_AMOUNT);
        rechargeOrderMapper.insert(order);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("rechargeNo", order.getRechargeNo());
        result.put("gatewayTransactionNo", "TXN" + uuidPart());
        result.put("amount", RECHARGE_AMOUNT);
        result.put("message", "充值订单已创建，等待支付平台回调");
        return result;
    }

    @Override
    @Transactional
    public Map<String, Object> notifyVuln(Integer userId, String rechargeNo, String transactionNo) {
        RechargeOrder order = requireOrder(userId, rechargeNo);
        requireTransaction(order, transactionNo);
        rechargeOrderMapper.markPaid(userId, rechargeNo, transactionNo);
        rechargeOrderMapper.creditBalance(userId, order.getAmount());
        return callbackResult(true, false, "支付回调处理成功，充值到账", order.getAmount(), balanceAfterCredit(userId));
    }

    @Override
    @Transactional
    public Map<String, Object> notifySecure(Integer userId, String rechargeNo, String transactionNo) {
        RechargeOrder order = requireOrder(userId, rechargeNo);
        requireTransaction(order, transactionNo);
        int changed = rechargeOrderMapper.markPaidIfPending(userId, rechargeNo, transactionNo, order.getAmount());
        if (changed == 1) {
            rechargeOrderMapper.creditBalance(userId, order.getAmount());
            return callbackResult(true, false, "首次支付回调处理成功，充值到账", order.getAmount(), balanceAfterCredit(userId));
        }

        RechargeOrder paidOrder = requireOrder(userId, rechargeNo);
        if ("PAID".equals(paidOrder.getStatus()) && transactionNo.equals(paidOrder.getGatewayTransactionNo())) {
            return callbackResult(true, true, "重复回调已确认，不重复入账", BigDecimal.ZERO, requireBalance(userId));
        }
        throw new IllegalArgumentException("支付状态或交易号异常");
    }

    @Override
    public Map<String, Object> status(Integer userId) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<RechargeOrder> orders = rechargeOrderMapper.selectByUser(userId);
        result.put("balance", requireBalance(userId));
        result.put("orderCount", orders.size());
        result.put("orders", orders);
        return result;
    }

    @Override
    @Transactional
    public Map<String, Object> reset(Integer userId) {
        rechargeOrderMapper.deleteByUser(userId);
        rechargeOrderMapper.resetBalance(userId, INITIAL_BALANCE);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("message", "当前测试账户的充值订单已清空，余额已恢复为 1000.00 元");
        result.put("balance", INITIAL_BALANCE);
        return result;
    }

    private RechargeOrder requireOrder(Integer userId, String rechargeNo) {
        if (rechargeNo == null || rechargeNo.trim().isEmpty()) {
            throw new IllegalArgumentException("充值订单号不能为空");
        }
        RechargeOrder order = rechargeOrderMapper.selectByRechargeNo(userId, rechargeNo);
        if (order == null) {
            throw new IllegalArgumentException("充值订单不存在或不属于当前账户");
        }
        return order;
    }

    private void requireTransaction(RechargeOrder order, String transactionNo) {
        if (transactionNo == null || transactionNo.trim().isEmpty()) {
            throw new IllegalArgumentException("支付交易号不能为空");
        }
        if (order.getGatewayTransactionNo() != null && !transactionNo.equals(order.getGatewayTransactionNo())) {
            throw new IllegalArgumentException("支付交易号与已处理订单不匹配");
        }
    }

    private BigDecimal requireBalance(Integer userId) {
        BigDecimal balance = rechargeOrderMapper.selectBalance(userId);
        if (balance == null) {
            throw new IllegalArgumentException("当前测试账户不存在");
        }
        return balance;
    }

    private BigDecimal balanceAfterCredit(Integer userId) {
        return requireBalance(userId);
    }

    private Map<String, Object> callbackResult(boolean accepted, boolean duplicateIgnored, String message,
                                               BigDecimal creditedAmount, BigDecimal balance) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("accepted", accepted);
        result.put("duplicateIgnored", duplicateIgnored);
        result.put("message", message);
        result.put("creditedAmount", creditedAmount);
        result.put("balance", balance);
        return result;
    }

    private String uuidPart() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 20).toUpperCase();
    }
}
