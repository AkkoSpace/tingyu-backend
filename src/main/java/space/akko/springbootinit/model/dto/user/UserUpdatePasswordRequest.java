package space.akko.springbootinit.model.dto.user;

import lombok.Data;

import java.io.Serializable;

/**
 * 用户更新个人信息请求
 */
@Data
public class UserUpdatePasswordRequest implements Serializable {

    /**
     * 用户旧密码
     */
    private String oldPassword;

    /**
     * 用户新密码
     */
    private String newPassword;

    private static final long serialVersionUID = 1L;
}
