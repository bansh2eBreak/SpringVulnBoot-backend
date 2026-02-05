package icu.secnotes.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Admin {
    private Integer id;
    private String name;
    private String username;
    private String password;
    private String token;
    private String avatar;
    private LocalDateTime createTime;
    private String role;  // 用户角色：admin-管理员, guest-访客
}
