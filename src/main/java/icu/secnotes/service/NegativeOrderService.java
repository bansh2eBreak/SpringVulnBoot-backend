package icu.secnotes.service;

import java.util.Map;

public interface NegativeOrderService {
    Map<String, Object> orderNormal(Integer userId, Integer quantity);

    Map<String, Object> orderVuln(Integer userId, Integer quantity);

    Map<String, Object> orderSecure(Integer userId, Integer quantity);

    Map<String, Object> status(Integer userId);

    Map<String, Object> reset(Integer userId);
}
