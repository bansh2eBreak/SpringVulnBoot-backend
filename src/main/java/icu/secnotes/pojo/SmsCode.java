package icu.secnotes.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SmsCode {

    private Long id;
    private String phone;
    private String code;
    private LocalDateTime createTime;
    private LocalDateTime expireTime;
    private Integer used;
    private Integer retryCount;

}
