package icu.secnotes.service.impl;

import icu.secnotes.mapper.MessageBoardMapper;
import icu.secnotes.pojo.MessageBoard;
import icu.secnotes.service.MessageBoardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MessageBoardServiceImpl implements MessageBoardService {
    @Autowired
    private MessageBoardMapper messageBoardMapper;

    @Override
    public void insertMessage(MessageBoard messageBoard) {
        messageBoardMapper.insertMessage(messageBoard);
    }

    @Override
    public List<MessageBoard> selectMessage() {
        return messageBoardMapper.selectMessage();
    }
}
