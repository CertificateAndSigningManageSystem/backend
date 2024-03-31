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

	"github.com/ivfzhou/cron/v3"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"

	"backend/service"
)

// InitialCron 初始化定时任务
func InitialCron(ctx context.Context) {
	c := cron.New(cron.WithSeconds())
	cronEntries := make(map[string]cron.EntryID)
	entryId, err := c.AddFunc("0 0 2 * * *", cronWrapper("MultipartUploadCleaner", MultipartUploadCleaner))
	if err != nil {
		log.Fatal(ctx, err)
	}
	cronEntries["MultipartUploadCleaner"] = entryId
	c.Run()
	log.Info(ctx, "init cron success")
}

// MultipartUploadCleaner 定时清理分片文件上传异常数据
func MultipartUploadCleaner(ctx context.Context, cronName string, runTime time.Time) {
	redisClient := conn.GetRedisClient(ctx)
	// 尝试设置运行标记
	b, err := redisClient.SetNX(ctx,
		fmt.Sprintf(conn.CacheKey_CronRecordFmt, cronName, runTime.Format("20060102150405")),
		"1", 5*time.Minute).Result()
	log.ErrorIf(ctx, err)
	if !b {
		// 有其他实例运行了
		return
	}

	if err = service.CleanMultipartUpload(ctx); err != nil {
		log.Error(ctx, err)
	}
}

func cronWrapper(cronName string, fn func(ctx context.Context, cronName string, runTime time.Time)) func(time.Time) {
	return func(t time.Time) {
		ctx := ctxs.NewCtx(cronName)
		defer func() {
			if p := recover(); p != nil {
				log.Errorf(ctx, "run cron panic %v %s", p, log.GetStack())
			}
		}()
		fn(ctx, cronName, t)
	}
}
