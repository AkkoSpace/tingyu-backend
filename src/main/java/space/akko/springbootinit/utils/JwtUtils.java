package space.akko.springbootinit.utils;

import cn.hutool.core.date.DateField;
import cn.hutool.core.date.DateTime;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.RegisteredPayload;

import java.util.Map;

/**
 * JWT 工具类
 *
 * @author Akko
 */
public class JwtUtils {
    private static final String SALT = "tingyu";

    public static String generateToken(Map<String, Object> map) {
        DateTime now = DateTime.now();
        DateTime newTime = now.offsetNew(DateField.MINUTE, 10);
        // 签发时间
        map.put(RegisteredPayload.ISSUED_AT, now);
        // 过期时间
        map.put(RegisteredPayload.EXPIRES_AT, newTime);
        // 生效时间
        map.put(RegisteredPayload.NOT_BEFORE, now);
        return JWTUtil.createToken(map, SALT.getBytes());
    }
}
