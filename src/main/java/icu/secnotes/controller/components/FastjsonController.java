package icu.secnotes.controller.components;

import com.alibaba.fastjson.JSON;
import icu.secnotes.pojo.Result;
import icu.secnotes.pojo.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("/components")
public class FastjsonController {

    @PostMapping("/fastjsonVuln1")
    public Result fastjsonVuln1(@RequestBody String json) {
        log.info("请求参数: {}", json);
        // 进行fastjson反序列化，需要对下面的代码进行try catch异常处理
        try {
            Object object = JSON.parse(json);
            return Result.success(object.toString());
        } catch (Exception e) {
            return Result.error(e.toString());
        }
    }

        @PostMapping("/fastjsonSec1")
        public Result fastjsonSec1(@RequestBody String json) {
            log.info("请求参数: {}", json);
            // 进行fastjson反序列化，需要对下面的代码进行try catch异常处理
            try {
                Object object = JSON.parseObject(json, User.class);
                return Result.success(object.toString());
            } catch (Exception e) {
                return Result.error(e.toString());
            }
        }

}
