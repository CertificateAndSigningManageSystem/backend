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
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitee.com/ivfzhou/gotools/v4"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	. "gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/service"
)

const apiAuthLimitScript = `
-- 拼接存放数据使用的键
local key = 'limit:'..KEYS[1]..':'..KEYS[2]..':hash';
-- 获取上次剩余请求量
local residue = tonumber(redis.call('hget', key, 'residue') or 0);
-- 获取上次请求时间
local lastAccessTime = tonumber(redis.call('hget', key, 'lastAccessTime') or 0);
-- 获取当前时间
local nowArr = redis.call('time');
local now = tonumber(nowArr[1]) * 1000000 + tonumber(nowArr[2]);
-- 计算出当前可用请求量
local genPerTime = tonumber(ARGV[1] or 0);
local max = tonumber(ARGV[2] or 0);
local canCost = math.min((now - lastAccessTime) * genPerTime + residue, max);
-- 判断是否可以放行
local need = tonumber(ARGV[3] or 0);
residue = canCost - need;
if residue >= 0 then
	redis.call('hmset', key, 'lastAccessTime', now, 'residue', residue);
	return 1
end
redis.call('hmset', key, 'lastAccessTime', now, 'residue', canCost);
return 0;`

var apiAuthLimitScriptSha string

// InitialAPIAuthLimitScript 获取 Redis 脚本 Sha。
func InitialAPIAuthLimitScript(ctx context.Context) {
	var err error
	apiAuthLimitScriptSha, err = conn.GetRedisClient(ctx).ScriptLoad(ctx, apiAuthLimitScript).Result()
	if err != nil {
		log.Fatal(ctx, "load apiauth script error", err)
	}
}

// APIAuthFilter API 访问鉴权
func APIAuthFilter(c *gin.Context) {
	ctx := c.Request.Context()

	// 获取凭证
	token := c.Request.Header.Get("Authorization")
	if len(token) <= 5 {
		c.Abort()
		util.FailByErr(c, errs.ErrNoAuth)
		return
	}
	token = token[5:]

	// 解析JWT凭证
	var authInfo *TAuthorization
	res, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		appId, err := token.Claims.GetIssuer()
		if err != nil {
			return nil, errs.NewSystemBusyErr(err)
		}
		authId, err := token.Claims.GetSubject()
		if err != nil {
			return nil, errs.NewSystemBusyErr(err)
		}
		authInfo, err = service.GetAuthInfo(ctx, appId, authId)
		if err != nil {
			return nil, err
		}
		if authInfo.Id <= 0 {
			return nil, errs.ErrNoAuth
		}
		return []byte(authInfo.Secret), nil
	})
	if err != nil {
		log.Error(ctx, err)
		c.Abort()
		util.FailByErr(c, err)
		return
	}

	// 校验
	switch {
	case !res.Valid:
		log.Warn(ctx, "api token invalid", token)
		c.Abort()
		util.FailByErr(c, errs.ErrNoAuth)
		return
	case errors.Is(err, jwt.ErrTokenMalformed):
		log.Warn(ctx, "api token malformed", token)
		c.Abort()
		util.FailByErr(c, errs.ErrNoAuth)
		return
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		log.Warn(ctx, "api token sign invalid", token)
		c.Abort()
		util.FailByErr(c, errs.ErrNoAuth)
		return
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		log.Warn(ctx, "api token expire", token)
		c.Abort()
		util.FailByErr(c, errs.ErrNoAuth)
		return
	}
	// 是否授权过期
	if time.Since(authInfo.ExpireTime) >= 0 {
		c.Abort()
		util.Fail(c, http.StatusForbidden, "token validity expire")
		return
	}
	// 签发时间大于当前时间
	issuedAt, err := res.Claims.GetIssuedAt()
	if err != nil {
		log.Error(ctx, err)
		c.Abort()
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	if time.Since(issuedAt.Time) <= 0 {
		c.Abort()
		util.Fail(c, http.StatusPreconditionFailed, "token invalid")
		return
	}
	// 凭证时效不能大于两小时
	expirationTime, err := res.Claims.GetExpirationTime()
	if err != nil {
		log.Error(ctx, err)
		c.Abort()
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	if expirationTime.Sub(issuedAt.Time) > 2*time.Hour {
		c.Abort()
		util.Fail(c, http.StatusPreconditionFailed, "too long token age")
		return
	}
	// 校验请求IP
	reqIP := c.Request.Header.Get("X-Real-IP")
	allowIPs := strings.Split(authInfo.IP, ",")
	if !gotools.Contains(allowIPs, "*") {
		reqIPNum := gotools.IPv4ToNum(reqIP)
		isPass := false
		for _, v := range allowIPs {
			// 是否是IP段
			if strings.Contains(v, "-") {
				ipArr := strings.Split(v, "-")
				begin := gotools.IPv4ToNum(ipArr[0])
				end := gotools.IPv4ToNum(ipArr[1])
				if reqIPNum >= begin && reqIPNum <= end {
					isPass = true
					break
				}
			} else {
				if gotools.IPv4ToNum(v) == reqIPNum {
					isPass = true
					break
				}
			}
		}
		if !isPass {
			c.Abort()
			util.Fail(c, http.StatusForbidden, "ip not allow")
			return
		}
	}
	// 请求限流校验
	b, err := conn.GetRedisClient(ctx).EvalSha(ctx, apiAuthLimitScriptSha,
		[]string{strconv.Itoa(int(authInfo.AppId)), strconv.Itoa(int(authInfo.Id))},
		authInfo.Frequency*60*1000*1000, authInfo.Frequency*60*1000*1000, 1).Bool()
	if err != nil {
		log.Error(ctx, err)
		c.Abort()
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	if !b {
		c.Abort()
		util.Fail(c, http.StatusTooManyRequests, "too many request")
		return
	}

	ctx = ctxs.WithAPIAuthId(ctx, authInfo.Id)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}
