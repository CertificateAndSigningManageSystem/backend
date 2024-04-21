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
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

// HasUserAnyAuthorities 判断userId是否具有authorities中任何一个角色
func HasUserAnyAuthorities(ctx context.Context, userId, appId uint, authorities ...uint) (bool, error) {
	if len(authorities) <= 0 {
		return true, nil
	}
	var b bool
	err := conn.GetMySQLClient(ctx).Model(&model.TUserRole{}).Select("count(id)").
		Where("user_id = ? and app_id = ? and role in ?", userId, appId, authorities).Find(&b).Error
	if err != nil {
		log.Error(ctx, err, userId, authorities)
		return false, errs.NewSystemBusyErr(err)
	}
	return b, nil
}
