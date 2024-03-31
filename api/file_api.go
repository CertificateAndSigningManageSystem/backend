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
	"strconv"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/protocol"
	"backend/service"
)

// UploadAPI 文件分片上传接口
type UploadAPI struct{}

// InitialUpload godoc
//
//	@Summary	初始化分片上传
//	@Tags		file-api
//	@Accept		json
//	@Produce	json
//	@Param		Authorization	header		string						true	"jwt凭证"
//	@Param		reqBody			body		protocol.InitialUploadReq	true	"reqBody"
//	@Success	200				{object}	protocol.InitialUploadRsp
//	@Router		/api/upload/initialUpload [post]
func (*UploadAPI) InitialUpload(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取请求参数
	var req protocol.InitialUploadReq
	err := c.ShouldBind(&req)
	if err != nil {
		log.Warn(ctx, err)
		util.FailByErr(c, errs.NewParamsErr(err))
		return
	}

	// 调用下游
	rsp, err := service.InitialUpload(ctx, &req)
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.Success(c, rsp)
}

// UploadPart godoc
//
//	@Summary	上传分片
//	@Tags		file-api
//	@Accept		mpfd
//	@Param		Authorization	header		string	true	"jwt凭证"
//	@Param		file			formData	file	true	"文件"
//	@Param		fileId			formData	string	true	"分片序号"
//	@Param		chunkNum		formData	integer	true	"文件Id"
//	@Success	200				{object}	nil
//	@Router		/api/upload/uploadPart [patch]
func (*UploadAPI) UploadPart(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取请求参数
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
	fileObj, err := file.Open()
	if err != nil {
		log.Error(ctx, err)
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	defer util.CloseIO(ctx, fileObj)
	fileIds := multipartForm.Value["fileId"]
	if len(fileIds) != 1 {
		util.FailByErr(c, errs.NewParamsErr(nil))
		return
	}
	fileId := fileIds[0]
	chunkNums := multipartForm.Value["chunkNum"]
	if len(chunkNums) != 1 {
		util.FailByErr(c, errs.NewParamsErr(nil))
		return
	}
	chunkNum, _ := strconv.Atoi(chunkNums[0])

	// 调用下游
	err = service.UploadPart(ctx, &protocol.UploadPartReq{
		FileId:    fileId,
		ChunkNum:  chunkNum,
		ChunkSize: int(file.Size),
		Chunk:     fileObj,
	})
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.Success(c, "")
}

// MergePart godoc
//
//	@Summary	合并分片
//	@Tags		file-api
//	@Accept		x-www-form-urlencoded
//	@Param		Authorization	header		string	true	"jwt凭证"
//	@Param		fileId			body		string	true	"文件Id"
//	@Success	200				{object}	nil
//	@Router		/api/upload/mergePart [post]
func (*UploadAPI) MergePart(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取参数
	fileId := c.PostForm("fileId")

	// 调用下游
	err := service.MergePart(ctx, &protocol.MergePartReq{FileId: fileId})
	if err != nil {
		util.FailByErr(c, err)
		return
	}

	util.SuccessMsg(c, "上传成功")
}
