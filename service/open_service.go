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
	"fmt"
	"strings"
	"time"
	"unicode"

	"gitee.com/ivfzhou/gotools/v4"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"

	"backend/protocol"
)

// Open_Create 创建凭证
func Open_Create(ctx context.Context, req *protocol.Open_CreateReq) (*protocol.Open_CreateRsp, error) {
	// 校验
	b, ip := IsValidAuthIP(ctx, req.IP)
	if !IsValidAuthId(ctx, req.Id) || !b || !IsValidFrequency(ctx, req.Frequency) || len(req.ActionIds) <= 0 {
		return nil, errs.ErrIllegalRequest
	}
	appId := ctxs.AppId(ctx)
	// 获取应用平台，校验授权项
	var platform int
	err := conn.GetMySQLClient(ctx).Model(&model.TApp{}).Select("platform").Where("id = ?", appId).Find(&platform).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	var count int
	err = conn.GetMySQLClient(ctx).Model(&model.TAuthorizationAction{}).Select("count(id)").
		Where("id in ? and (platform = ? or platform = ?)", req.ActionIds, platform, model.TApp_Platform_All).
		Find(&count).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	if count != len(req.ActionIds) {
		return nil, errs.NewParamsErrMsg("选择的授权项非法")
	}
	// 校验应用状态
	var appStatus uint8
	err = conn.GetMySQLClient(ctx).Model(&model.TApp{}).Select("status").Where("id = ?", appId).Find(&appStatus).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	if appStatus != model.TApp_Status_OK {
		return nil, errs.NewParamsErrMsg("应用信息不可更改")
	}

	// 加锁，避免同名凭证
	lockKey := fmt.Sprintf(conn.LockKey_OpenApiCreateFmt, appId, req.Id)
	if !conn.Lock(ctx, lockKey, 0) {
		return nil, errs.ErrTooManyRequest
	}
	defer conn.Unlock(ctx, lockKey)

	// 校验凭证是否存在
	var exist bool
	err = conn.GetMySQLClient(ctx).Model(&model.TAuthorization{}).Select("count(id)>0").
		Where("app_id = ? and auth_id = ?", appId, req.Id).Find(&exist).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	if exist {
		return nil, errs.NewParamsErrMsg("凭证Id已存在")
	}

	// 新增数据库记录
	userId := ctxs.UserId(ctx)
	now := time.Now()
	secret := gotools.RandomCharsCaseInsensitive(128)
	auth := &model.TAuthorization{
		AppId:      appId,
		AuthId:     req.Id,
		UserId:     userId,
		IP:         ip,
		Frequency:  uint(req.Frequency),
		Secret:     secret,
		CreateTime: now,
		ExpireTime: now.AddDate(0, 6, 0),
	}
	if err = conn.GetMySQLClient(ctx).Create(auth).Error; err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	aar := gotools.ConvertSlice(req.ActionIds, func(e int) *model.TAuthorizationActionRelation {
		return &model.TAuthorizationActionRelation{
			AuthId:   auth.Id,
			ActionId: uint(e),
		}
	})
	if err = conn.GetMySQLClient(ctx).CreateInBatches(aar, len(aar)).Error; err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	err = CreateEvent(ctx, &model.TEvent{
		Type:      model.TEvent_Type_ApplyOpenAPIToken,
		OccurTime: now,
		UserId:    userId,
		AppId:     appId,
		Content:   fmt.Sprintf("用户%d应用%d新建openapi %s", userId, appId, req.Id),
	})
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}

	return &protocol.Open_CreateRsp{Secret: secret}, nil
}

func IsValidAuthIP(_ context.Context, ip string) (bool, string) {
	ip = string(gotools.FilterSlice([]byte(ip), func(e byte) bool { return e != ' ' }))
	if len(ip) <= 0 {
		return false, ""
	}
	arr := strings.Split(ip, ",")
	ipClean := make([]string, 0, len(arr))
	hasWildcard := false
	for _, v := range arr {
		if len(v) <= 0 {
			continue
		}
		if v == "*" {
			ipClean = append(ipClean, v)
			hasWildcard = true
			continue
		}
		if strings.Contains(v, "-") {
			ipArr := strings.Split(v, "-")
			if len(ipArr) != 2 {
				return false, ""
			}
			if !gotools.IsIPv4(ipArr[0]) || gotools.IsIntranet(ipArr[0]) ||
				!gotools.IsIPv4(ipArr[1]) || gotools.IsIntranet(ipArr[1]) {
				return false, ""
			}
			if gotools.IPv4ToNum(ipArr[0]) > gotools.IPv4ToNum(ipArr[1]) {
				return false, ""
			}
		} else {
			if !gotools.IsIPv4(v) || gotools.IsIntranet(v) {
				return false, ""
			}
		}
		ipClean = append(ipClean, v)
	}
	if len(ipClean) <= 0 {
		return false, ""
	}
	if hasWildcard {
		return true, "*"
	}
	return true, strings.Join(ipClean, ",")
}

func IsValidAuthId(_ context.Context, authId string) bool {
	if len(authId) <= 0 || len(authId) > 60 {
		return false
	}
	for _, v := range []rune(authId) {
		if !unicode.IsDigit(v) && !unicode.IsLetter(v) && v != '_' {
			return false
		}
	}
	return true
}

func IsValidFrequency(_ context.Context, frequency int) bool {
	if frequency <= 0 || frequency > 600 {
		return false
	}
	return true
}
