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
	"mime/multipart"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/protocol"
	"backend/service"
)

// AppApi 应用管理模块
type AppApi struct{}

// Create 注册应用
func (*AppApi) Create(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析请求参数
	form, err := c.MultipartForm()
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	defer func() { log.ErrorIf(ctx, form.RemoveAll()) }()
	names := form.Value["name"]
	if len(names) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无应用名")
		return
	}
	platforms := form.Value["platform"]
	if len(platforms) != 1 {
		util.Fail(c, http.StatusExpectationFailed, "无应用平台")
		return
	}
	platform, _ := strconv.Atoi(platforms[0])
	admins := form.Value["admins"]
	members := form.Value["members"]

	files := form.File["logo"]
	var file *multipart.FileHeader
	if len(files) > 1 {
		util.Fail(c, http.StatusExpectationFailed, "未知 Logo")
		return
	}
	if len(files) == 1 {
		file = files[0]
	}
	req := &protocol.CreateReq{
		Name:     names[0],
		Platform: platform,
		Logo:     file,
		Admins:   admins,
		Members:  members,
	}

	// 调用下游
	if err = service.Create(ctx, req); err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "创建成功")
}

// Update 更新应用
func (*AppApi) Update(c *gin.Context) {
	ctx := c.Request.Context()
	// 解析请求参数
	var req protocol.UpdateReq
	err := c.ShouldBind(&req)
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}

	// 调用下游
	if err = service.Update(ctx, &req); err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "修改成功")
}

// Delete 注销应用
func (*AppApi) Delete(c *gin.Context) {
	ctx := c.Request.Context()

	// 调用下游
	err := service.Delete(ctx)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "注销成功")
}

// ChangeLogo 修改应用图标
func (*AppApi) ChangeLogo(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析数据
	var req protocol.ChangeLogoReq
	err := c.ShouldBind(&req)
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}

	// 调用下游
	if err = service.ChangeLogo(ctx, &req); err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "修改成功")
}
