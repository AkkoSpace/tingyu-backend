package space.akko.springbootinit.controller;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import lombok.extern.slf4j.Slf4j;
import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;
import me.chanjar.weixin.mp.api.WxMpService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;
import space.akko.springbootinit.annotation.AuthCheck;
import space.akko.springbootinit.common.BaseResponse;
import space.akko.springbootinit.common.DeleteRequest;
import space.akko.springbootinit.common.ErrorCode;
import space.akko.springbootinit.common.ResultUtils;
import space.akko.springbootinit.config.WxOpenConfig;
import space.akko.springbootinit.constant.UserConstant;
import space.akko.springbootinit.exception.BusinessException;
import space.akko.springbootinit.exception.ThrowUtils;
import space.akko.springbootinit.model.dto.user.*;
import space.akko.springbootinit.model.entity.User;
import space.akko.springbootinit.model.vo.LoginUserVO;
import space.akko.springbootinit.model.vo.UserVO;
import space.akko.springbootinit.service.UserService;
import space.akko.springbootinit.utils.JwtUtils;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

import static space.akko.springbootinit.constant.CommonConstant.SALT;
import static space.akko.springbootinit.constant.Key.PRIVATE_KEY;

/**
 * 用户接口
 *
 * @author Akko
 */
@RestController
@RequestMapping("/user")
@Slf4j
public class UserController {

    @Resource
    private UserService userService;

    @Resource
    private WxOpenConfig wxOpenConfig;

    // region 登录相关

    /**
     * 用户注册
     *
     * @param userRegisterRequest 用户注册请求
     * @return 用户 id
     */
    @PostMapping("/register")
    public BaseResponse<Long> userRegister(@RequestBody UserRegisterRequest userRegisterRequest) {
        if (userRegisterRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String userAccount = userRegisterRequest.getUserAccount();
        String userPassword = userRegisterRequest.getUserPassword();
        String checkPassword = userRegisterRequest.getCheckPassword();
        if (StringUtils.isAnyBlank(userAccount, userPassword, checkPassword)) {
            return null;
        }
        RSA rsa = new RSA(PRIVATE_KEY, null);
        String decryptUserPassword = rsa.decryptStr(userPassword, KeyType.PrivateKey);
        String decryptCheckPassword = rsa.decryptStr(checkPassword, KeyType.PrivateKey);
        long result = userService.userRegister(userAccount, decryptUserPassword, decryptCheckPassword);
        return ResultUtils.success(result);
    }

    /**
     * 用户登录
     *
     * @param userLoginRequest 用户登录请求
     * @param request          请求
     * @return token
     */
    @PostMapping("/login")
    public BaseResponse<String> userLogin(@RequestBody UserLoginRequest userLoginRequest, HttpServletRequest request) {
        if (userLoginRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String userAccount = userLoginRequest.getUserAccount();
        String userPassword = userLoginRequest.getUserPassword();
        if (StringUtils.isAnyBlank(userAccount, userPassword)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        RSA rsa = new RSA(PRIVATE_KEY, null);
        String decryptUserPassword = rsa.decryptStr(userPassword, KeyType.PrivateKey);
        String token = userService.userLogin(userAccount, decryptUserPassword, request);
        return ResultUtils.success(token);
    }

    /**
     * 验证用户
     *
     * @param request 请求
     * @return token
     */
    @PostMapping("/auth")
    public BaseResponse<String> userAuth(HttpServletRequest request) {
        String token = userService.userAuth(request);
        return ResultUtils.success(token);
    }

    /**
     * 用户登录（微信开放平台）
     *
     * @param request  请求
     * @param response 响应
     */
    @GetMapping("/login/wx_open")
    public BaseResponse<LoginUserVO> userLoginByWxOpen(HttpServletRequest request, HttpServletResponse response, @RequestParam("code") String code) {
        WxOAuth2AccessToken accessToken;
        try {
            WxMpService wxService = wxOpenConfig.getWxMpService();
            accessToken = wxService.getOAuth2Service().getAccessToken(code);
            WxOAuth2UserInfo userInfo = wxService.getOAuth2Service().getUserInfo(accessToken, code);
            String unionId = userInfo.getUnionId();
            String mpOpenId = userInfo.getOpenid();
            if (StringUtils.isAnyBlank(unionId, mpOpenId)) {
                throw new BusinessException(ErrorCode.SYSTEM_ERROR, "登录失败，系统错误");
            }
            return ResultUtils.success(userService.userLoginByMpOpen(userInfo, request));
        } catch (Exception e) {
            log.error("userLoginByWxOpen error", e);
            throw new BusinessException(ErrorCode.SYSTEM_ERROR, "登录失败，系统错误");
        }
    }

    /**
     * 用户注销
     *
     * @param request 请求
     * @return 是否成功
     */
    @PostMapping("/logout")
    public BaseResponse<Boolean> userLogout(HttpServletRequest request) {
        if (request == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        boolean result = userService.userLogout(request);
        return ResultUtils.success(result);
    }

    /**
     * 获取当前登录用户信息
     *
     * @param request 请求
     * @return 当前登录用户信息
     */
    @GetMapping("/info")
    public BaseResponse<LoginUserVO> getLoginUser(HttpServletRequest request) {
        User user = userService.getLoginUser(request);
        return ResultUtils.success(userService.getLoginUserVO(user));
    }

    // endregion

    // region 增删改查

    /**
     * 创建用户
     *
     * @param userAddRequest 用户创建请求
     * @param request        请求
     * @return 用户 id
     */
    @PostMapping("/add")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Long> addUser(@RequestBody UserAddRequest userAddRequest, HttpServletRequest request) {
        if (userAddRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        User user = new User();
        BeanUtils.copyProperties(userAddRequest, user);
        boolean result = userService.save(user);
        ThrowUtils.throwIf(!result, ErrorCode.OPERATION_ERROR);
        return ResultUtils.success(user.getId());
    }

    /**
     * 删除用户
     *
     * @param deleteRequest 用户删除请求
     * @param request       请求
     * @return 是否成功
     */
    @PostMapping("/delete")
    public BaseResponse<Boolean> deleteUser(@RequestBody DeleteRequest deleteRequest, HttpServletRequest request) {
        if (deleteRequest == null || deleteRequest.getId() <= 0) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        if (deleteRequest.getId().equals(JwtUtils.parseToken(JwtUtils.formatHeaderToToken(request)).getPayload("id"))) {
            boolean b = userService.removeById(deleteRequest.getId());
            return ResultUtils.success(b);
        } else {
            throw new BusinessException(ErrorCode.FORBIDDEN_ERROR);
        }
    }

    /**
     * 更新用户
     *
     * @param userUpdateRequest 用户更新请求
     * @param request           请求
     * @return 是否成功
     */
    @PostMapping("/update")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Boolean> updateUser(@RequestBody UserUpdateRequest userUpdateRequest, HttpServletRequest request) {
        if (userUpdateRequest == null || userUpdateRequest.getId() == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        User user = new User();
        BeanUtils.copyProperties(userUpdateRequest, user);
        boolean result = userService.updateById(user);
        ThrowUtils.throwIf(!result, ErrorCode.OPERATION_ERROR);
        return ResultUtils.success(true);
    }

    /**
     * 根据 id 获取用户（仅管理员）
     *
     * @param id      用户 id
     * @param request 请求
     * @return 用户
     */
    @GetMapping("/get")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<User> getUserById(long id, HttpServletRequest request) {
        if (id <= 0) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        User user = userService.getById(id);
        ThrowUtils.throwIf(user == null, ErrorCode.NOT_FOUND_ERROR);
        return ResultUtils.success(user);
    }

    /**
     * 根据 id 获取包装类
     *
     * @param id      用户 id
     * @param request 请求
     * @return 用户
     */
    @GetMapping("/get/vo")
    public BaseResponse<UserVO> getUserVOById(long id, HttpServletRequest request) {
        BaseResponse<User> response = getUserById(id, request);
        User user = response.getData();
        return ResultUtils.success(userService.getUserVO(user));
    }

    /**
     * 分页获取用户列表（仅管理员）
     *
     * @param userQueryRequest 用户查询请求
     * @param request          请求
     * @return 用户列表
     */
    @PostMapping("/list/page")
    @AuthCheck(mustRole = UserConstant.ADMIN_ROLE)
    public BaseResponse<Page<User>> listUserByPage(@RequestBody UserQueryRequest userQueryRequest, HttpServletRequest request) {
        long current = userQueryRequest.getCurrent();
        long size = userQueryRequest.getPageSize();
        Page<User> userPage = userService.page(new Page<>(current, size), userService.getQueryWrapper(userQueryRequest));
        return ResultUtils.success(userPage);
    }

    /**
     * 分页获取用户封装列表
     *
     * @param userQueryRequest 用户查询请求
     * @param request          请求
     * @return 用户列表
     */
    @PostMapping("/list/page/vo")
    public BaseResponse<Page<UserVO>> listUserVOByPage(@RequestBody UserQueryRequest userQueryRequest, HttpServletRequest request) {
        if (userQueryRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        long current = userQueryRequest.getCurrent();
        long size = userQueryRequest.getPageSize();
        // 限制爬虫
        ThrowUtils.throwIf(size > 20, ErrorCode.PARAMS_ERROR);
        Page<User> userPage = userService.page(new Page<>(current, size), userService.getQueryWrapper(userQueryRequest));
        Page<UserVO> userVOPage = new Page<>(current, size, userPage.getTotal());
        List<UserVO> userVO = userService.getUserVO(userPage.getRecords());
        userVOPage.setRecords(userVO);
        return ResultUtils.success(userVOPage);
    }

    // endregion

    /**
     * 更新个人信息
     *
     * @param userUpdateInfoRequest 用户更新请求
     * @param request               请求
     * @return 是否成功
     */
    @PostMapping("/update/info")
    public BaseResponse<LoginUserVO> updateMyUser(@RequestBody UserUpdateInfoRequest userUpdateInfoRequest, HttpServletRequest request) {
        if (userUpdateInfoRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        User loginUser = userService.getLoginUser(request);
        User user = new User();
        BeanUtils.copyProperties(userUpdateInfoRequest, user);
        user.setId(loginUser.getId());
        boolean result = userService.updateById(user);
        ThrowUtils.throwIf(!result, ErrorCode.OPERATION_ERROR);
        return ResultUtils.success(userService.getLoginUserVO(user));
    }

    /**
     * 更新个人密码
     *
     * @param userUpdatePasswordRequest 用户更新密码请求
     * @param request                   请求
     * @return 是否成功
     */
    @PostMapping("/update/password")
    public BaseResponse<Boolean> updateMyPassword(@RequestBody UserUpdatePasswordRequest userUpdatePasswordRequest, HttpServletRequest request) {
        if (userUpdatePasswordRequest == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String oldPassword = userUpdatePasswordRequest.getOldPassword();
        RSA rsa = new RSA(PRIVATE_KEY, null);
        String decryptOldPassword = rsa.decryptStr(oldPassword, KeyType.PrivateKey);
        String encryptOldPassword = DigestUtils.md5DigestAsHex((SALT + decryptOldPassword).getBytes());
        User loginUser = userService.getLoginUser(request);
        if (!loginUser.getUserPassword().equals(encryptOldPassword)) {
            throw new BusinessException(ErrorCode.PASSWORD_ERROR);
        } else {
            String newPassword = userUpdatePasswordRequest.getNewPassword();
            String decryptNewPassword = rsa.decryptStr(newPassword, KeyType.PrivateKey);
            String encryptNewPassword = DigestUtils.md5DigestAsHex((SALT + decryptNewPassword).getBytes());
            if (loginUser.getUserPassword().equals(encryptNewPassword)) {
                throw new BusinessException(ErrorCode.PARAMS_ERROR);
            }
            loginUser.setUserPassword(encryptNewPassword);
            boolean result = userService.updateById(loginUser);
            ThrowUtils.throwIf(!result, ErrorCode.OPERATION_ERROR);
            return ResultUtils.success(true);
        }
    }
}
