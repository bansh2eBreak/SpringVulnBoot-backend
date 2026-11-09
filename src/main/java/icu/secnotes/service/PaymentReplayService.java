package icu.secnotes.service;

import java.util.Map;

public interface PaymentReplayService {
    Map<String, Object> createOrder(Integer userId);

    Map<String, Object> notifyVuln(Integer userId, String rechargeNo, String transactionNo);

    Map<String, Object> notifySecure(Integer userId, String rechargeNo, String transactionNo);

    Map<String, Object> status(Integer userId);

    Map<String, Object> reset(Integer userId);
}
