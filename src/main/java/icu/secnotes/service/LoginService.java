package icu.secnotes.service;

import icu.secnotes.pojo.Admin;

public interface LoginService {
    Admin login(Admin admin);

    Admin getUserByToken(String token);
}
