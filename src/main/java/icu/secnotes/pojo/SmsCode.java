package icu.secnotes.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SmsCode {

    private Long id;
    @NotBlank(message = "手机号不能为空")
    @Pattern(regexp = "^1(3[0-9]|4[5-9]|5[0-3,5-9]|6[6]|7[0-8]|8[0-9]|9[1,8,9])\\d{8}$", message = "手机号格式错误")
    private String phone;
    private String code;
    private LocalDateTime createTime;
    private LocalDateTime expireTime;
    private Integer used;
    private Integer retryCount;

}
