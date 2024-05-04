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

package service

import (
	"context"

	"gitee.com/CertificateAndSigningManageSystem/backend/protocol"
	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

// HLK_QueryJobInfo 查询 hlk 任务信息
func HLK_QueryJobInfo(ctx context.Context, req *protocol.HLK_QueryJobInfoReq) (*protocol.HLK_QueryJobInfoRsp, error) {
	// 校验
	if req.Id <= 0 {
		return nil, errs.NewParamsErrMsg("id is invalid")
	}

	// 查库
	var twinSignJob model.TWinSignJob
	err := conn.GetMySQLClient(ctx).Where("id = ?", req.Id).Find(&twinSignJob).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}

	// 组装数据
	res := &protocol.HLK_QueryJobInfoRsp{
		Id:            twinSignJob.Id,
		UserId:        twinSignJob.UserId,
		AppId:         twinSignJob.AppId,
		FileId:        twinSignJob.FileId,
		HLKTestSystem: twinSignJob.HLKTestSystem,
		CreateTime:    twinSignJob.CreateTime,
		FinishTime:    twinSignJob.FinishTime,
		Status:        twinSignJob.Status,
		TmpFileId:     twinSignJob.TmpFileId,
		SignedFileId:  twinSignJob.SignedFileId,
	}

	return res, nil
}
