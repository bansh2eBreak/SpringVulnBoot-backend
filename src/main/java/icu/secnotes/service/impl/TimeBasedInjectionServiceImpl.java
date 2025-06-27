package icu.secnotes.service.impl;

import icu.secnotes.mapper.TimeBasedInjectionMapper;
import icu.secnotes.pojo.User;
import icu.secnotes.service.TimeBasedInjectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;
import java.util.List;

@Slf4j
@Service
public class TimeBasedInjectionServiceImpl implements TimeBasedInjectionService {

    @Autowired
    private TimeBasedInjectionMapper timeBasedInjectionMapper;

    @Override
    public List<User> getUserByUsernameTime(String username) {
        return timeBasedInjectionMapper.selectUserByUsernameTime(username);
    }

    @Override
    public List<User> getUserByUsernameTimeSafe(String username) {
        return timeBasedInjectionMapper.selectUserByUsernameTimeSafe(username);
    }

} 