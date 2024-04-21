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

// CreateEvent 数据库新增事件
func CreateEvent(ctx context.Context, e *model.TEvent) error {
	err := conn.GetMySQLClient(ctx).Create(e).Error
	if err != nil {
		log.ErrorIf(ctx, conn.GetMySQLClient(ctxs.CloneCtx(ctx)).Table(e.TableName()).AutoMigrate(&model.TEvent{}))
		if err = conn.GetMySQLClient(ctx).Create(e).Error; err != nil {
			return errs.NewSystemBusyErr(err)
		}
	}
	return nil
}
