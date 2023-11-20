package space.akko.springbootinit.model.entity;

import lombok.Data;

/**
 * 封装用户和 Token
 *
 * @author Akko
 */
@Data
public class TokenUser {
    private User user;
    private String token;

    public TokenUser(User user, String token) {
        this.user = user;
        this.token = token;
    }

    public TokenUser() {

    }

    public User getUser() {
        return user;
    }

    public String getToken() {
        return token;
    }
}
