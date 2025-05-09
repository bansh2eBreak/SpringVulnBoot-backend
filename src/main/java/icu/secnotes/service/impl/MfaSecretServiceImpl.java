package icu.secnotes.service.impl;

import icu.secnotes.mapper.MfaSecretMapper;
import icu.secnotes.pojo.MfaSecret;
import icu.secnotes.service.MfaSecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MfaSecretServiceImpl implements MfaSecretService {

    @Autowired
    private MfaSecretMapper mfaSecretMapper;

    @Override
    public Integer createMfaSecret(MfaSecret mfaSecret) {
        return mfaSecretMapper.insert(mfaSecret);
    }

    @Override
    public Integer deleteMfaSecret(MfaSecret mfaSecret) {
        return mfaSecretMapper.delete(mfaSecret);
    }

    @Override
    public MfaSecret getSecretByUserId(Integer userId) {
        return mfaSecretMapper.selectByUserId(userId);
    }

    @Override
    public int updateSecret(MfaSecret mfaSecret) {
        return mfaSecretMapper.update(mfaSecret);
    }
}
