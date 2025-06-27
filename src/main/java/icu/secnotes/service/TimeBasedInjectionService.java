package icu.secnotes.service;

import java.util.List;
import icu.secnotes.pojo.User;

public interface TimeBasedInjectionService {

    List<User> getUserByUsernameTime(String username);
    List<User> getUserByUsernameTimeSafe(String username);

} 