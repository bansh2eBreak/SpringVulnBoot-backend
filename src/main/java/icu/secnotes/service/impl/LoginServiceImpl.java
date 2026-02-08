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
    
    @Override
    public int changePassword(String username, String newPassword) {
        return loginMapper.changePassword(username, newPassword);
    }
    
    @Override
    public boolean changePasswordByUserId(String userId, String newPassword) {
        try {
            int result = loginMapper.changePasswordByUserId(userId, newPassword);
            return result > 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public boolean changePasswordSecure(String userId, String oldPassword, String newPassword) {
        try {
            int result = loginMapper.changePasswordSecure(userId, oldPassword, newPassword);
            return result > 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public boolean verifyOldPassword(String userId, String oldPassword) {
        try {
            Admin admin = loginMapper.verifyOldPassword(userId, oldPassword);
            return admin != null;
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public boolean updateAdmin(Admin admin) {
        try {
            int result = loginMapper.updateAdmin(admin);
            return result > 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public boolean checkUsernameExists(String username) {
        try {
            int count = loginMapper.checkUsernameExists(username);
            return count > 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    @Override
    public boolean register(Admin admin) {
        try {
            int result = loginMapper.register(admin);
            return result > 0;
        } catch (Exception e) {
            return false;
        }
    }

}
