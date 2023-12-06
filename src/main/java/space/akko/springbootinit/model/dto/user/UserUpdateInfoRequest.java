package space.akko.springbootinit.model.dto.user;

import java.io.Serializable;
import lombok.Data;

/**
 * 用户更新个人信息请求
 */
@Data
public class UserUpdateInfoRequest implements Serializable {

    /**
     * 用户昵称
     */
    private String userName;

    /**
     * 简介
     */
    private String userProfile;

    private static final long serialVersionUID = 1L;
}
