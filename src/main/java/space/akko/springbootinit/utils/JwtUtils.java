package space.akko.springbootinit.utils;

import cn.hutool.core.date.DateField;
import cn.hutool.core.date.DateTime;
import cn.hutool.jwt.JWT;
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

    /**
     * 生成 JWT
     *
     * @param map 自定义信息
     * @return token
     */

    public static String generateToken(Map<String, Object> payload) {
        DateTime now = DateTime.now();
        DateTime newTime = now.offsetNew(DateField.MINUTE, 10);
        // 签发时间
        payload.put(RegisteredPayload.ISSUED_AT, now);
        // 过期时间
        payload.put(RegisteredPayload.EXPIRES_AT, newTime);
        // 生效时间
        payload.put(RegisteredPayload.NOT_BEFORE, now);
        return JWTUtil.createToken(payload, SALT.getBytes());
    }

    /**
     * 校验 JWT
     *
     * @param token token
     * @return 是否有效
     */
    public static boolean verifyToken(String token) {
        return JWTUtil.verify(token, SALT.getBytes());
    }

    /**
     * 解析 JWT
     *
     * @param token token
     * @return 载荷
     */
    public static JWT parseToken(String token) {
        return JWTUtil.parseToken(token);
    }
}
