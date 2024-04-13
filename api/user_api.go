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
		log.Error(ctx, err)
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
	files := form.File["file"]
	if len(files) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无头像")
		return
	}
	req := &protocol.RegisterReq{
		NameZh:   nameZhs[0],
		NameEn:   nameEns[0],
		Avatar:   files[0],
		Password: passwds[0],
	}

	// 调用下游
	session, err := service.Register(ctx, req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	c.SetCookie("csms_session", session, 0, "", "", false, true)
	util.SuccessMsg(c, "注册成功")
}

// Login 登录
func (*UserApi) Login(c *gin.Context) {

}

// Logout 登出
func (*UserApi) Logout(c *gin.Context) {

}

// UpdateInfo 更新个人信息
func (*UserApi) UpdateInfo(c *gin.Context) {

}

// ChangePasswd 修改密码
func (*UserApi) ChangePasswd(c *gin.Context) {

}

// Info 获取个人信息
func (*UserApi) Info(c *gin.Context) {

}
