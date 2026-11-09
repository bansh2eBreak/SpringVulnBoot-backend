package icu.secnotes.pojo;

import lombok.Data;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
public class RechargeOrder {
    private Long id;
    private Integer userId;
    private String rechargeNo;
    private BigDecimal amount;
    private String status;
    private String gatewayTransactionNo;
    private LocalDateTime paidAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
