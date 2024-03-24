package cron

import (
	"context"
	"fmt"
	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"time"
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
	log.LogIfError(ctx, err)
	if !b {
		// 有其他实例运行了
		return
	}
}
