package icu.secnotes.service.impl;

import icu.secnotes.mapper.BooleanBlindMapper;
import icu.secnotes.service.BooleanBlindService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 布尔盲注 Service 实现类
 */
@Service
public class BooleanBlindServiceImpl implements BooleanBlindService {
    
    @Autowired
    private BooleanBlindMapper booleanBlindMapper;
    
    @Override
    public int checkUserExistsByDollar(String username) {
        return booleanBlindMapper.checkUserExistsByDollar(username);
    }
    
    @Override
    public int checkUserExistsBySharp(String username) {
        return booleanBlindMapper.checkUserExistsBySharp(username);
    }
}
