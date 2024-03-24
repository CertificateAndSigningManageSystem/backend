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

	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

// SessionInfo 会话信息
type SessionInfo struct {
	LoginIP string
	model.TUser
}

// GetSessionInfo 获取会话信息
func GetSessionInfo(ctx context.Context, session string) (*SessionInfo, error) {
	var data struct {
		UserId  uint   `json:"userId"`
		LoginIP string `json:"loginIP"`
	}
	err := json.Unmarshal([]byte(session), &data)
	if err != nil {
		log.Error(ctx, "json unmarshal error JSON反序列化错误", err, session)
		return &SessionInfo{}, errs.NewSystemBusyErr(err)
	}

	return nil, nil
}
