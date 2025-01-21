package icu.secnotes.service.impl;

import icu.secnotes.mapper.LoginMapper;
import icu.secnotes.pojo.Admin;
import icu.secnotes.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private LoginMapper loginMapper;

    @Override
    public Admin login(Admin admin) {
        return loginMapper.login(admin);
    }

    @Override
    public Admin getAdminById(String id) {
        return loginMapper.getAdminById(id);
    }

}
