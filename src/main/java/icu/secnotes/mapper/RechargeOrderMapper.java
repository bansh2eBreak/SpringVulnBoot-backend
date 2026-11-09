package icu.secnotes.mapper;

import icu.secnotes.pojo.RechargeOrder;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import java.math.BigDecimal;
import java.util.List;

@Mapper
public interface RechargeOrderMapper {

    @Select("select balance from Admin where id = #{userId}")
    BigDecimal selectBalance(@Param("userId") Integer userId);

    @Update("update Admin set balance = balance + #{amount} where id = #{userId}")
    int creditBalance(@Param("userId") Integer userId, @Param("amount") BigDecimal amount);

    @Update("update Admin set balance = #{balance} where id = #{userId}")
    int resetBalance(@Param("userId") Integer userId, @Param("balance") BigDecimal balance);

    @Insert("insert into logic_recharge_order(user_id, recharge_no, amount, status) "
            + "values(#{order.userId}, #{order.rechargeNo}, #{order.amount}, 'PENDING')")
    int insert(@Param("order") RechargeOrder order);

    @Update("update logic_recharge_order set status = 'PAID', gateway_transaction_no = #{transactionNo}, paid_at = now() "
            + "where recharge_no = #{rechargeNo} and user_id = #{userId}")
    int markPaid(@Param("userId") Integer userId, @Param("rechargeNo") String rechargeNo,
                 @Param("transactionNo") String transactionNo);

    @Update("update logic_recharge_order set status = 'PAID', gateway_transaction_no = #{transactionNo}, paid_at = now() "
            + "where recharge_no = #{rechargeNo} and user_id = #{userId} and status = 'PENDING' and amount = #{amount}")
    int markPaidIfPending(@Param("userId") Integer userId, @Param("rechargeNo") String rechargeNo,
                          @Param("transactionNo") String transactionNo, @Param("amount") BigDecimal amount);

    @Select("select id, user_id as userId, recharge_no as rechargeNo, amount, status, "
            + "gateway_transaction_no as gatewayTransactionNo, paid_at as paidAt, created_at as createdAt, updated_at as updatedAt "
            + "from logic_recharge_order where recharge_no = #{rechargeNo} and user_id = #{userId}")
    RechargeOrder selectByRechargeNo(@Param("userId") Integer userId, @Param("rechargeNo") String rechargeNo);

    @Select("select id, user_id as userId, recharge_no as rechargeNo, amount, status, "
            + "gateway_transaction_no as gatewayTransactionNo, paid_at as paidAt, created_at as createdAt, updated_at as updatedAt "
            + "from logic_recharge_order where user_id = #{userId} order by id desc")
    List<RechargeOrder> selectByUser(@Param("userId") Integer userId);

    @Delete("delete from logic_recharge_order where user_id = #{userId}")
    int deleteByUser(@Param("userId") Integer userId);
}
