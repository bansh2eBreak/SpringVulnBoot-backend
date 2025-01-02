package icu.secnotes.service;

import icu.secnotes.pojo.MessageBoard;
import java.util.List;

public interface MessageBoardService {
    /**
     * 添加留言
     */
    void insertMessage(MessageBoard messageBoard);

    /**
     * 查询留言
     */
    List<MessageBoard> selectMessage();
}
