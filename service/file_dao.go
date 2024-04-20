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

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

// CreateDBFile 数据库新增文件信息实体
func CreateDBFile(ctx context.Context, f *model.TFile) error {
	err := conn.GetMySQLClient(ctx).Create(f).Error
	if err != nil {
		log.ErrorIf(ctx, conn.GetMySQLClient(ctxs.CloneCtx(ctx)).Table(f.TableName()).AutoMigrate(&model.TFile{}))
		err = conn.GetMySQLClient(ctx).Create(f).Error
		if err != nil {
			return errs.NewSystemBusyErr(err)
		}
	}
	return nil
}

// QueryDBFileById 检索文件
func QueryDBFileById(ctx context.Context, fileId string) (*model.TFile, error) {
	f := &model.TFile{FileId: fileId}
	err := conn.GetMySQLClient(ctx).Where("file_id = ?", fileId).Find(f).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	return f, nil
}

// DeleteDBFile 删除文件
func DeleteDBFile(ctx context.Context, fileId string) error {
	f := &model.TFile{FileId: fileId}
	err := conn.GetMySQLClient(ctx).Table(f.TableName()).Where("file_id = ?", fileId).Delete(&model.TFile{}).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	return nil
}
