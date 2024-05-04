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
	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/backend/protocol"
	"gitee.com/CertificateAndSigningManageSystem/backend/service"
	"gitee.com/CertificateAndSigningManageSystem/common/util"
)

// HLKApi 供 hlk_manager 使用的相关接口
type HLKApi struct{}

// QueryJobInfo 获取任务信息
func (api *HLKApi) QueryJobInfo(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取请求参数
	req := protocol.HLK_QueryJobInfoReq{}
	err := c.ShouldBindQuery(&req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	// 调用下游
	rsp, err := service.HLK_QueryJobInfo(ctx, &req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.Success(c, rsp)
}
