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

// GetAuthInfoById 根据id获取凭证信息
func GetAuthInfoById(ctx context.Context, id uint) (*model.TAuthorization, error) {
	var info model.TAuthorization
	err := conn.GetMySQLClient(ctx).Where("id = ?", id).Find(&info).Error
	if err != nil {
		log.Error(ctx, "query t_authorization error", err, id)
		return &info, errs.NewSystemBusyErr(err)
	}
	return &info, nil
}

// GetAuthInfo 获取凭证信息
func GetAuthInfo(ctx context.Context, appId, authId string) (*model.TAuthorization, error) {
	var info model.TAuthorization
	err := conn.GetMySQLClient(ctx).Where("app_id = ? and auth_id = ?", appId, authId).Find(&info).Error
	if err != nil {
		log.Error(ctx, "query t_authorization error", err, appId, authId)
		return &info, errs.NewSystemBusyErr(err)
	}
	return &info, nil
}

// HasAuthAnyAuthorities 凭证是否有任何一个授权项
func HasAuthAnyAuthorities(ctx context.Context, authId uint, authorities ...uint) (bool, error) {
	if len(authorities) <= 0 {
		return true, nil
	}
	var b bool
	err := conn.GetMySQLClient(ctx).Model(&model.TAuthorizationActionRelation{}).Select("count(id)").
		Where("auth_id = ? and action_id in ?", authId, authorities).Find(&b).Error
	if err != nil {
		log.Error(ctx, "query t_authorization_action_relation error", err, authId, authorities)
		return b, errs.NewSystemBusyErr(err)
	}
	return b, nil
}
