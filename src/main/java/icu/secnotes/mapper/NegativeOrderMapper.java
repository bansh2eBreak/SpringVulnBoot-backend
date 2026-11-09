package icu.secnotes.mapper;

import icu.secnotes.pojo.NegativeOrder;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import java.math.BigDecimal;
import java.util.List;

@Mapper
public interface NegativeOrderMapper {

    @Select("select balance from Admin where id = #{userId}")
    BigDecimal selectBalance(@Param("userId") Integer userId);

    @Update("update Admin set balance = balance - #{amount} where id = #{userId} and balance >= #{amount}")
    int deductBalanceIfEnough(@Param("userId") Integer userId, @Param("amount") BigDecimal amount);

    @Update("update Admin set balance = #{balance} where id = #{userId}")
    int resetBalance(@Param("userId") Integer userId, @Param("balance") BigDecimal balance);

    @Insert("insert into logic_negative_order(user_id, order_no, product_code, product_name, unit_price, quantity, total_amount) "
            + "values(#{order.userId}, #{order.orderNo}, #{order.productCode}, #{order.productName}, #{order.unitPrice}, #{order.quantity}, #{order.totalAmount})")
    int insert(@Param("order") NegativeOrder order);

    @Select("select id, user_id as userId, order_no as orderNo, product_code as productCode, "
            + "product_name as productName, unit_price as unitPrice, quantity, total_amount as totalAmount, "
            + "created_at as createdAt from logic_negative_order where user_id = #{userId} order by id desc")
    List<NegativeOrder> selectByUser(@Param("userId") Integer userId);

    @Delete("delete from logic_negative_order where user_id = #{userId}")
    int deleteByUser(@Param("userId") Integer userId);
}
