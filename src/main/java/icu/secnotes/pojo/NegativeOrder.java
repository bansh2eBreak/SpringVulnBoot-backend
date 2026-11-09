package icu.secnotes.pojo;

import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
public class NegativeOrder {
    private Long id;
    private Integer userId;
    private String orderNo;
    private String productCode;
    private String productName;
    private BigDecimal unitPrice;
    private Integer quantity;
    private BigDecimal totalAmount;
    private LocalDateTime createdAt;
}
