package icu.secnotes.service;

import icu.secnotes.pojo.MfaSecret;

public interface MfaSecretService {

    // 创建MFA密钥
    Integer createMfaSecret(MfaSecret mfaSecret);

    // 删除MFA密钥
    Integer deleteMfaSecret(MfaSecret mfaSecret);

    // 根据用户ID查询密钥
    MfaSecret getSecretByUserId(Integer userId);

    // 更新密钥
    int updateSecret(MfaSecret mfaSecret);

}
