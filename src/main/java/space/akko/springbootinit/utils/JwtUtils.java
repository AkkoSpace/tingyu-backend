package space.akko.springbootinit.utils;

import cn.hutool.core.date.DateField;
import cn.hutool.core.date.DateTime;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.RegisteredPayload;
import org.apache.commons.lang3.StringUtils;
import space.akko.springbootinit.common.ErrorCode;
import space.akko.springbootinit.exception.BusinessException;

import javax.servlet.http.HttpServletRequest;
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
     * @param payload 载荷
     * @return token
     */

    public static String generateToken(String type, Map<String, Object> payload) {
        DateTime now = DateTime.now();
        DateTime newTime = DateTime.now();
        if ("access".equals(type)) {
            newTime = now.offsetNew(DateField.MINUTE, 10);
        } else if ("refresh".equals(type)) {
            newTime = now.offsetNew(DateField.HOUR, 24 * 7);
        }
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

    /**
     * 格式化 Header
     *
     * @param request 请求
     * @return token
     */
    public static String formatHeaderToToken(HttpServletRequest request) {
        // 获取返回的 token
        String token = request.getHeader("Authorization");
        // 去掉 Bearer
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        // 判断 token 是否为空
        if (StringUtils.isBlank(token)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "未登录");
        }
        // 校验 token
        if (!JwtUtils.verifyToken(token)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR, "Token 异常");
        }
        return token;
    }
}
