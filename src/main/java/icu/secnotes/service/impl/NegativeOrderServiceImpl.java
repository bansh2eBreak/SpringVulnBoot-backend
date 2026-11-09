package icu.secnotes.service.impl;

import icu.secnotes.mapper.NegativeOrderMapper;
import icu.secnotes.pojo.NegativeOrder;
import icu.secnotes.service.NegativeOrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class NegativeOrderServiceImpl implements NegativeOrderService {

    private static final String PRODUCT_CODE = "DEMO-HEADPHONE";
    private static final String PRODUCT_NAME = "演示蓝牙耳机";
    private static final BigDecimal UNIT_PRICE = new BigDecimal("199.00");
    private static final BigDecimal INITIAL_BALANCE = new BigDecimal("1000.00");

    @Autowired
    private NegativeOrderMapper negativeOrderMapper;

    @Override
    @Transactional
    public Map<String, Object> orderNormal(Integer userId, Integer quantity) {
        return orderSecure(userId, quantity);
    }

    /**
     * 漏洞版：仅校验数量上限，遗漏数量必须大于 0 的下限校验。
     */
    @Override
    @Transactional
    public Map<String, Object> orderVuln(Integer userId, Integer quantity) {
        return placeVulnOrder(userId, quantity);
    }

    /**
     * 安全版：数量必须为 1 至 99 的正整数，余额扣减使用条件更新。
     */
    @Override
    @Transactional
    public Map<String, Object> orderSecure(Integer userId, Integer quantity) {
        requireSecureQuantity(quantity);
        BigDecimal totalAmount = UNIT_PRICE.multiply(BigDecimal.valueOf(quantity));
        BigDecimal balanceBefore = requireBalance(userId);

        if (negativeOrderMapper.deductBalanceIfEnough(userId, totalAmount) != 1) {
            return result(false, "余额不足，无法完成下单", null, balanceBefore);
        }

        BigDecimal balanceAfter = balanceBefore.subtract(totalAmount);
        NegativeOrder order = buildOrder(userId, quantity, totalAmount);
        negativeOrderMapper.insert(order);
        return result(true, "下单成功，余额已扣减", order, balanceAfter);
    }

    @Override
    public Map<String, Object> status(Integer userId) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<NegativeOrder> orders = negativeOrderMapper.selectByUser(userId);
        result.put("balance", requireBalance(userId));
        result.put("productCode", PRODUCT_CODE);
        result.put("productName", PRODUCT_NAME);
        result.put("unitPrice", UNIT_PRICE);
        result.put("orderCount", orders.size());
        result.put("orders", orders);
        return result;
    }

    @Override
    @Transactional
    public Map<String, Object> reset(Integer userId) {
        negativeOrderMapper.deleteByUser(userId);
        negativeOrderMapper.resetBalance(userId, INITIAL_BALANCE);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("message", "当前测试账户的订单记录已清空，余额已恢复为 1000.00 元");
        result.put("balance", INITIAL_BALANCE);
        return result;
    }

    private Map<String, Object> placeVulnOrder(Integer userId, Integer quantity) {
        requireVulnQuantity(quantity);
        BigDecimal totalAmount = UNIT_PRICE.multiply(BigDecimal.valueOf(quantity));
        BigDecimal balanceBefore = requireBalance(userId);

        // ❌ 当 quantity 为负数时，余额充足判断仍会通过，balance - (-totalAmount) 会使余额增加。
        if (negativeOrderMapper.deductBalanceIfEnough(userId, totalAmount) != 1) {
            return result(false, "余额不足，无法完成下单", null, balanceBefore);
        }
        BigDecimal balanceAfter = balanceBefore.subtract(totalAmount);
        NegativeOrder order = buildOrder(userId, quantity, totalAmount);
        negativeOrderMapper.insert(order);

        String message = quantity < 0
                ? "漏洞触发：负数数量生成负订单金额，余额被反向增加"
                : "下单成功，余额已扣减";
        return result(true, message, order, balanceAfter);
    }

    private NegativeOrder buildOrder(Integer userId, Integer quantity, BigDecimal totalAmount) {
        NegativeOrder order = new NegativeOrder();
        order.setUserId(userId);
        order.setOrderNo("NEG" + UUID.randomUUID().toString().replace("-", "").substring(0, 20).toUpperCase());
        order.setProductCode(PRODUCT_CODE);
        order.setProductName(PRODUCT_NAME);
        order.setUnitPrice(UNIT_PRICE);
        order.setQuantity(quantity);
        order.setTotalAmount(totalAmount);
        return order;
    }

    private Map<String, Object> result(boolean ordered, String message, NegativeOrder order, BigDecimal balance) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ordered", ordered);
        result.put("message", message);
        result.put("balance", balance);
        result.put("order", order);
        return result;
    }

    private BigDecimal requireBalance(Integer userId) {
        BigDecimal balance = negativeOrderMapper.selectBalance(userId);
        if (balance == null) {
            throw new IllegalArgumentException("当前测试账户不存在");
        }
        return balance;
    }

    private void requireVulnQuantity(Integer quantity) {
        if (quantity == null || quantity > 99 || quantity < -99) {
            throw new IllegalArgumentException("数量必须是 -99 至 99 之间的整数");
        }
    }

    private void requireSecureQuantity(Integer quantity) {
        if (quantity == null || quantity < 1 || quantity > 99) {
            throw new IllegalArgumentException("购买数量必须是 1 至 99 之间的整数");
        }
    }

}
