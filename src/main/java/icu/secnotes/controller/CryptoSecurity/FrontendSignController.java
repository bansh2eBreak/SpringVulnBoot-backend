package icu.secnotes.controller.CryptoSecurity;

import icu.secnotes.pojo.Result;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 加密安全 - 前端加签被逆向漏洞演示控制器（电商下单改价场景）
 *
 * 背景：很多系统为了"防篡改/防重放/过 WAF"，让前端用 crypto-js 对下单参数计算一个
 *      sign = md5(参数按 key 升序拼接 + secret)，后端用同样的 secret 重算 sign 比对。
 *      致命缺陷在于：前端要算 sign 就必须持有 secret，而前端 JS 下发到用户设备，
 *      secret 100% 可被 F12 / 逆向获取。攻击者拿到 secret 和拼接规则后，就能像正常前端一样
 *      伪造任意合法签名，把 price=8999 改成 price=1 并重算出合法 sign，实现 1 元下单。
 *
 * 漏洞版 /vuln/order：验签通过后，直接信任前端传来的 price 计算订单金额。
 * 安全版 /sec/order ：同样验签，但忽略前端 price，用 goodsId 查服务端真实价格计费，
 *                     篡改前端 price 无效。
 *
 * 注意：漏洞版与安全版共用同一套验签逻辑，差别只在"验签之后信不信前端数据"，
 *      以此凸显——签名本身不是问题，无条件信任前端数据才是问题。
 */
@RestController
@RequestMapping("/cryptoSecurity/frontendSign")
@Slf4j
@Tag(name = "前端加签被逆向漏洞", description = "前端加签 secret 硬编码在 JS，逆向后可伪造合法签名篡改下单价格")
public class FrontendSignController {

    /**
     * 加签密钥。
     * ❌ 漏洞根源：这个 secret 与前端 src/utils/frontendSign.js 中硬编码的 SIGN_SECRET 完全一致，
     *            前端持有同一份 secret 才能加签，意味着它必然暴露在客户端，可被逆向获取。
     */
    private static final String SIGN_SECRET = "x9f2Kd8sLp3qW7mE";

    /**
     * 商品目录（内存，演示用）。安全版以此作为"服务端真实价格"的唯一来源。
     */
    private static final Map<Long, Goods> GOODS_CATALOG = new LinkedHashMap<>();

    static {
        GOODS_CATALOG.put(2001L, new Goods(2001L, "iPhone 16 Pro Max 256G", 8999));
        GOODS_CATALOG.put(2002L, new Goods(2002L, "AirPods Pro 2", 1899));
        GOODS_CATALOG.put(2003L, new Goods(2003L, "原装快充线", 59));
    }

    /**
     * 订单列表（内存，演示用，进程重启即清空）
     */
    private static final List<Map<String, Object>> ORDERS = Collections.synchronizedList(new ArrayList<>());

    private static final AtomicLong ORDER_SEQ = new AtomicLong(100000);

    /**
     * 查询商品目录（前后端共用，供页面展示和前端加签取真实价格）
     */
    @GetMapping("/goods")
    @Operation(summary = "商品目录", description = "返回商品 id/名称/价格")
    public Result goods() {
        return Result.success(new ArrayList<>(GOODS_CATALOG.values()));
    }

    /**
     * 漏洞版下单：验签通过后，直接信任前端传来的 price 计算金额
     */
    @PostMapping("/vuln/order")
    @Operation(summary = "下单-漏洞版", description = "验签通过后直接信任前端 price，可被篡改为任意低价")
    public Result orderVuln(@RequestBody Map<String, Object> body) {
        long goodsId = toLong(body.get("goodsId"));
        long price = toLong(body.get("price"));
        int count = (int) toLong(body.get("count"));
        String sign = body.get("sign") == null ? "" : String.valueOf(body.get("sign"));

        Goods goods = GOODS_CATALOG.get(goodsId);
        if (goods == null) {
            return Result.error("商品不存在：" + goodsId);
        }

        // 1. 验签（漏洞版同样会验签 —— 签名能挡住只改包不会逆向的人）
        if (!verifySign(goodsId, price, count, sign)) {
            log.warn("【FrontendSign-VULN】验签失败，参数被篡改或签名无效：goodsId={}, price={}, count={}, sign={}",
                    goodsId, price, count, sign);
            return Result.error("签名校验失败：参数被篡改或签名无效");
        }

        // 2. ❌ 漏洞点：验签通过后，无条件信任前端传来的 price
        long total = price * count;
        Map<String, Object> order = buildOrder(goods, price, count, total, "按【前端传入】价格计费");

        log.warn("【FrontendSign-VULN】下单成功：商品={}, 真实单价={}, 前端传入单价={}, 数量={}, 实付={}",
                goods.getName(), goods.getPrice(), price, count, total);

        Map<String, Object> data = new HashMap<>();
        data.put("order", order);
        data.put("realPrice", goods.getPrice());
        data.put("message", price < goods.getPrice()
                ? "⚠️ 下单成功！前端传入单价 " + price + " 元（真实价 " + goods.getPrice() + " 元），服务端按前端价格计费，被薅羊毛！"
                : "下单成功，实付 " + total + " 元");
        return Result.success(data);
    }

    /**
     * 安全版下单：同样验签，但忽略前端 price，用 goodsId 查服务端真实价格计费
     */
    @PostMapping("/sec/order")
    @Operation(summary = "下单-安全版", description = "验签通过后忽略前端 price，按服务端真实价格计费，篡改无效")
    public Result orderSec(@RequestBody Map<String, Object> body) {
        long goodsId = toLong(body.get("goodsId"));
        long price = toLong(body.get("price"));
        int count = (int) toLong(body.get("count"));
        String sign = body.get("sign") == null ? "" : String.valueOf(body.get("sign"));

        Goods goods = GOODS_CATALOG.get(goodsId);
        if (goods == null) {
            return Result.error("商品不存在：" + goodsId);
        }

        // 1. 验签（与漏洞版同一套逻辑）
        if (!verifySign(goodsId, price, count, sign)) {
            log.warn("【FrontendSign-SEC】验签失败：goodsId={}, price={}, count={}, sign={}",
                    goodsId, price, count, sign);
            return Result.error("签名校验失败：参数被篡改或签名无效");
        }

        // 2. ✅ 安全点：不信任前端 price，用 goodsId 查服务端真实价格计费
        int realPrice = goods.getPrice();
        long total = (long) realPrice * count;
        Map<String, Object> order = buildOrder(goods, realPrice, count, total, "按【服务端真实】价格计费");

        boolean tampered = price != realPrice;
        log.info("【FrontendSign-SEC】下单成功：商品={}, 真实单价={}, 前端传入单价={}, 以真实价计费, 实付={}",
                goods.getName(), realPrice, price, total);

        Map<String, Object> data = new HashMap<>();
        data.put("order", order);
        data.put("realPrice", realPrice);
        data.put("message", tampered
                ? "✅ 验签虽通过，但服务端忽略前端价格 " + price + " 元，按真实价 " + realPrice + " 元计费，实付 " + total + " 元，篡改无效！"
                : "下单成功，实付 " + total + " 元");
        return Result.success(data);
    }

    /**
     * 验签：sign = md5(参数按 key 升序拼接 "k=v&..." + SIGN_SECRET)
     * 参与签名的参数：count、goodsId、price（升序）
     */
    private boolean verifySign(long goodsId, long price, int count, String sign) {
        String raw = "count=" + count + "&goodsId=" + goodsId + "&price=" + price + SIGN_SECRET;
        String expect = md5Hex(raw);
        return expect.equalsIgnoreCase(sign);
    }

    private Map<String, Object> buildOrder(Goods goods, long unitPrice, int count, long total, String note) {
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("orderId", "ORD" + ORDER_SEQ.incrementAndGet());
        order.put("goodsId", goods.getId());
        order.put("goodsName", goods.getName());
        order.put("unitPrice", unitPrice);
        order.put("count", count);
        order.put("totalAmount", total);
        order.put("note", note);
        ORDERS.add(order);
        return order;
    }

    private static long toLong(Object o) {
        if (o == null) {
            return 0L;
        }
        try {
            return Long.parseLong(String.valueOf(o).trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static String md5Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("MD5 计算失败", e);
        }
    }

    /**
     * 商品（内存模型）
     */
    public static class Goods {
        private Long id;
        private String name;
        private int price;

        public Goods() {
        }

        public Goods(Long id, String name, int price) {
            this.id = id;
            this.name = name;
            this.price = price;
        }

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getPrice() {
            return price;
        }

        public void setPrice(int price) {
            this.price = price;
        }
    }
}
