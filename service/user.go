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
	"encoding/json"
	"fmt"
	"net/http"

	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

// ErrUnknownUser 登录时未知用户
var ErrUnknownUser error = &errs.Error{
	HTTPStatus: http.StatusUnauthorized,
	Msg:        "unknown user 未知用户",
	WrappedErr: fmt.Errorf("unknown user 未知用户"),
}

// SessionInfo 会话信息
type SessionInfo struct {
	LoginIP string
	*model.TUser
}

// GetSessionInfo 获取会话信息
func GetSessionInfo(ctx context.Context, session string) (*SessionInfo, error) {
	// 反序列数据
	var data struct {
		UserId  uint   `json:"userId"`
		LoginIP string `json:"loginIP"`
	}
	err := json.Unmarshal([]byte(session), &data)
	if err != nil {
		log.Error(ctx, "json unmarshal error JSON反序列化错误", err, session)
		return &SessionInfo{}, errs.NewSystemBusyErr(err)
	}

	// 查库
	userInfo, err := GetUserInfoById(ctx, data.UserId)
	if err != nil {
		return &SessionInfo{}, err
	}
	if userInfo.Id <= 0 {
		log.Warn(ctx, "unknown user 未知用户", session)
		return &SessionInfo{}, ErrUnknownUser
	}

	return &SessionInfo{
		LoginIP: data.LoginIP,
		TUser:   userInfo,
	}, nil
}
