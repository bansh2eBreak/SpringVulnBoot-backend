package icu.secnotes.controller.SQLI;

import icu.secnotes.pojo.Result;
import icu.secnotes.service.TimeBasedInjectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sqli/time")
public class TimeBasedInjectionController {

    @Autowired
    private TimeBasedInjectionService timeBasedInjectionService;

    @GetMapping("/getUserByUsernameTime")
    public Result getUserByUsernameTime(@RequestParam String username) {
        return Result.success(timeBasedInjectionService.getUserByUsernameTime(username));
    }

    @GetMapping("/getUserByUsernameTimeSafe")
    public Result getUserByUsernameTimeSafe(@RequestParam String username) {
        return Result.success(timeBasedInjectionService.getUserByUsernameTimeSafe(username));
    }
    
} 