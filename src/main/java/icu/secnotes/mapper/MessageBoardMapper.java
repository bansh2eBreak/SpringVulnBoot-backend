package icu.secnotes.mapper;

import icu.secnotes.pojo.MessageBoard;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import java.util.List;

@Mapper
public interface MessageBoardMapper {

    /**
     * 添加留言
     */
    @Insert("insert into MessageBoard(message) values(#{message})")
    void insertMessage(MessageBoard messageBoard);

    /**
     * 查询留言
     */
    @Select("select * from MessageBoard")
    List<MessageBoard> selectMessage();
}
