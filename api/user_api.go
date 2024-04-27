/*
 * Copyright (c) 2023 ivfzhou
 * backend is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/consts"
	"backend/protocol"
	"backend/service"
)

// UserApi 用户管理模块
type UserApi struct{}

// Register 注册
func (*UserApi) Register(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析请求参数
	form, err := c.MultipartForm()
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	defer func() { log.ErrorIf(ctx, form.RemoveAll()) }()
	nameEns := form.Value["nameEn"]
	if len(nameEns) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无英文名")
		return
	}
	nameZhs := form.Value["nameZh"]
	if len(nameZhs) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无中文名")
		return
	}
	passwds := form.Value["password"]
	if len(passwds) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无密码")
		return
	}
	files := form.File["avatar"]
	if len(files) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无头像")
		return
	}
	req := &protocol.User_RegisterReq{
		NameZh:    nameZhs[0],
		NameEn:    nameEns[0],
		Avatar:    files[0],
		Password:  passwds[0],
		UserAgent: c.Request.UserAgent(),
	}

	// 调用下游
	session, err := service.User_Register(ctx, req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	c.SetCookie(consts.SessionKey, session, 0, "", "", false, true)
	c.SetCookie(consts.SessionUser, req.NameEn, 0, "", "", false, true)
	util.SuccessMsg(c, "注册成功")
}

// Login 登录
func (*UserApi) Login(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取请求参数
	var req protocol.User_LoginReq
	err := c.ShouldBind(&req)
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}

	// 调用下游
	req.UserAgent = c.Request.UserAgent()
	session, err := service.User_Login(ctx, &req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	c.SetCookie(consts.SessionKey, session, 0, "", "", false, true)
	c.SetCookie(consts.SessionUser, req.Name, 0, "", "", false, true)
	util.SuccessMsg(c, "登陆成功")
}

// Logout 登出
func (*UserApi) Logout(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取会话
	session, _ := c.Cookie(consts.SessionKey)
	user, _ := c.Cookie(consts.SessionUser)

	// 调用下游
	if err := service.User_Logout(ctx, user, session); err != nil {
		util.FailByErr(c, err)
		return
	}

	c.SetCookie(consts.SessionKey, session, -1, "", "", false, true)
	c.SetCookie(consts.SessionUser, user, -1, "", "", false, true)
	util.SuccessMsg(c, "登出成功")
}

// Info 获取个人信息
func (*UserApi) Info(c *gin.Context) {
	ctx := c.Request.Context()

	// 调用下游
	rsp, err := service.User_GetInfo(ctx)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.Success(c, rsp)
}

// UpdateInfo 更新个人信息
func (*UserApi) UpdateInfo(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析请求参数
	var req protocol.User_UpdateInfoReq
	err := c.ShouldBind(&req)
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}

	// 调用下游
	if err = service.User_UpdateInfo(ctx, &req); err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "修改成功")
}

// ChangePassword 修改密码
func (*UserApi) ChangePassword(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析请求参数
	var req protocol.User_ChangePasswordReq
	err := c.ShouldBind(&req)
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}

	// 调用下游
	if err = service.User_ChangePassword(ctx, &req); err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "修改成功")
}

// ChangeAvatar 修改头像
func (*UserApi) ChangeAvatar(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析参数
	multipartForm, err := c.MultipartForm()
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}
	files := multipartForm.File["file"]
	if len(files) != 1 {
		util.FailByErr(c, errs.NewParamsErr(nil))
		return
	}
	file := files[0]

	// 调用下游
	err = service.User_ChangeAvatar(ctx, &protocol.User_ChangeAvatarReq{
		Avatar: file,
	})
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "修改成功")
}
