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
	"backend/service"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/protocol"
)

// OpenApi 凭证管理模块
type OpenApi struct{}

// Create 创建凭证
func (*OpenApi) Create(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析请求参数
	var req protocol.Open_CreateReq
	err := c.ShouldBind(&req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	// 调用下游
	rsp, err := service.Open_Create(ctx, &req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.Success(c, rsp)
}

// Update 更新凭证
func (*OpenApi) Update(c *gin.Context) {
	ctx := c.Request.Context()

	// 解析请求参数
	var req protocol.Open_UpdateReq
	err := c.ShouldBind(&req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	// 调用下游
	err = service.Open_Update(ctx, &req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "更新成功")
}
