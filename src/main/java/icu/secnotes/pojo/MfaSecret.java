package icu.secnotes.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MfaSecret {
    private Integer id;
    private Integer userId;
    private String secret;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

    public MfaSecret(Integer userId, String secret) {
        this.userId = userId;
        this.secret = secret;
    }
}
