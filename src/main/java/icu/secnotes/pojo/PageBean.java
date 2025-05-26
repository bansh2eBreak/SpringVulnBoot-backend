package icu.secnotes.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PageBean<T> {
    /** 总记录数 */
    private Integer total;
    
    /** 数据列表 */
    private List<T> rows;
}
