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

package cron

import (
	"context"
	"fmt"
	"time"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
)

var _ = MultipartUploadCleaner

// MultipartUploadCleaner 定时清理分片文件上传异常数据
func MultipartUploadCleaner(ctx context.Context, cronName string, runTime time.Time) {
	redisClient := conn.GetRedisClient(ctx)
	// 尝试设置运行标记
	b, err := redisClient.SetNX(ctx,
		fmt.Sprintf("%s:%s", cronName, runTime.Format("20060102150405")),
		"1",
		5*time.Minute).Result()
	log.ErrorIf(ctx, err)
	if !b {
		// 有其他实例运行了
		return
	}
}
