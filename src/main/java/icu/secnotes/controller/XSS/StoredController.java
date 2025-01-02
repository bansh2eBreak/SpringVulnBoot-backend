package icu.secnotes.controller.XSS;

import icu.secnotes.mapper.MessageBoardMapper;
import icu.secnotes.pojo.MessageBoard;
import icu.secnotes.pojo.Result;
import icu.secnotes.service.MessageBoardService;
import lombok.extern.slf4j.Slf4j;
import org.owasp.esapi.ESAPI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@Slf4j
@RequestMapping("/xss/stored")
public class StoredController {

    @Autowired
    private MessageBoardService messageBoardService;

    /**
     * 添加留言
     */
    @PostMapping("/addMessage")
    public Result addMessage(@RequestBody MessageBoard messageBoard) {
        if (messageBoard.getMessage() == null || "".equals(messageBoard.getMessage())) {
            log.error("留言内容不能为空");
            return Result.error("留言内容不能为空");
        }
        messageBoardService.insertMessage(messageBoard);
        return Result.success();
    }

    /**
     * 查询留言
     */
    @GetMapping("/queryMessage")
    public Result queryMessage() {
        List<MessageBoard> messageBoards = messageBoardService.selectMessage();
        return Result.success(messageBoards);
    }

    /**
     * ESAPI安全工具包防御xss
     */
    @GetMapping("/addMessageSec")
    public Result addMessageSec(@RequestBody MessageBoard messageBoard) {
        if (messageBoard.getMessage() == null || "".equals(messageBoard.getMessage())) {
            log.error("留言内容不能为空");
            return Result.error("留言内容不能为空");
        }

        // ESAPI安全工具包防御xss
        messageBoard.setMessage(ESAPI.encoder().encodeForHTML(messageBoard.getMessage()));
        messageBoardService.insertMessage(messageBoard);
        return Result.success();
    }

}
