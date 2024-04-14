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

	"github.com/google/uuid"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
)

const (
	IdScope_File = "file"
)

// GenerateId 生成唯一id
func GenerateId(ctx context.Context, scope string) (string, error) {
	for {
		id := strings.ReplaceAll(time.Now().Format("200601")+uuid.NewString(), "-", "")
		result, err := conn.GetRedisClient(ctx).SAdd(ctx, fmt.Sprintf(conn.CacheKey_GenIdFmt, scope), id).Result()
		if err != nil {
			log.Error(ctx, err)
			return "", errs.NewSystemBusyErr(err)
		}
		if result > 0 {
			return id, nil
		}
		time.Sleep(time.Second)
	}
}

// ReclaimId 回收id
func ReclaimId(ctx context.Context, scope, id string) error {
	err := conn.GetRedisClient(ctx).SRem(ctx, fmt.Sprintf(conn.CacheKey_GenIdFmt, scope), id).Err()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewParamsErr(err)
	}
	return nil
}
