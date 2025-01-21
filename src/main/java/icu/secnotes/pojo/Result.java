package icu.secnotes.pojo;

/**
 * 统一响应结果封装类
 */
public class Result {
    private Integer code;   //0 成功  1失败
    private String msg;     //提示信息
    private Object data;    //数据 data

    public Result() {
    }

    public Result(Integer code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    // 用于返回增删改操作成功的结果
    public static Result success(Object data){
        return new Result(0,"success", data);
    }

    // 用于返回查询操作成功的结果
    public static Result success(){
        return new Result(0,"success", null);
    }

    // 用于返回操作失败的结果
    public static Result error(Object data){
        return new Result(1,"error", data);
    }

    @Override
    public String toString() {
        return "Result{" +
                "code=" + code +
                ", msg='" + msg + '\'' +
                ", data=" + data +
                '}';
    }
}