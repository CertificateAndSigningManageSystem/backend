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

package filter

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/util"
)

const (
	antiShakeMinPeriod   = 800 * time.Millisecond
	antiShakeMaxPeriod   = time.Minute
	antiShakeRedisScript = `
-- 防抖使用的Redis Hash键
local key = 'anti:shake:hash';
local field = KEYS[1]..KEYS[2];
-- 获取当前时间
local nowArr = redis.call('time');
local curAccessTime = tonumber(nowArr[1]) * 1000);
-- 获取用户该请求的上次请求时间
local lastAccessTime = tonumber(redis.call('hget', key, field) or 0);
-- 比较与本次请求时间
local delta = curAccessTime - lastAccessTime;
local limit = tonumber(ARGV[1] or 0);
if (delta >= 0 and delta < limit) or (delta < 0 and delta > -limit) then
	return 0;
end
-- 通过校验更新时间值
redis.call('hset', key, field, curAccessTime);
return 1;
`
)

var antiShakeRedisCmdSha string

// InitialAntiShakeScript 初始化防抖脚本
func InitialAntiShakeScript(ctx context.Context) {
	var err error
	antiShakeRedisCmdSha, err = conn.GetRedisClient(ctx).ScriptLoad(ctx, antiShakeRedisScript).Result()
	if err != nil {
		log.Fatal(ctx, "load anti shake redis script error", err)
	}
}

// AntiShakeFilter 请求防抖过滤器
func AntiShakeFilter(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取并校验请求时间
	date := c.Request.Header.Get("Date")
	reqDate, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", date)
	if err != nil {
		c.Abort()
		util.Fail(c, http.StatusBadRequest, "unknown request date")
		return
	}
	// 请求时间超时
	if since := time.Since(reqDate); since > antiShakeMaxPeriod || since < 0 {
		c.Abort()
		util.Fail(c, http.StatusPreconditionFailed, "request timeout")
		return
	}

	// 执行Redis脚本
	userId := ctxs.UserId(ctx)
	reqPath := ctxs.RequestPath(ctx)
	b, err := conn.GetRedisClient(ctx).EvalSha(ctx, antiShakeRedisCmdSha,
		[]string{strconv.Itoa(int(userId)), reqPath}, antiShakeMinPeriod.Milliseconds()).Bool()
	if err != nil {
		c.Abort()
		log.Error(ctx, "exec redis anti shake script error", err)
		util.Fail(c, http.StatusInternalServerError, "system busy")
		return
	}
	// 丢掉请求
	if !b {
		c.Abort()
		util.Fail(c, http.StatusTooManyRequests, "too many requests")
		return
	}

	c.Next()
}
