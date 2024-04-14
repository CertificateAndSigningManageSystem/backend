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
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/consts"
	"backend/service"
)

// WebAuthFilter Web接口会话鉴权
func WebAuthFilter(c *gin.Context) {
	ctx := c.Request.Context()
	ip := ctxs.RequestIP(ctx)

	// 获取会话
	sessionCookie, err := c.Request.Cookie(consts.SessionKey)
	if err != nil {
		c.Abort()
		// 不存在会话凭证
		if errors.Is(err, http.ErrNoCookie) {
			util.Fail(c, http.StatusUnauthorized, "请先登陆")
		} else {
			log.Error(ctx, err)
			util.FailByErr(c, errs.NewSystemBusyErr(err))
		}
		return
	}

	// 获取会话信息
	sessionStr, err := conn.GetRedisClient(ctx).Get(
		ctx, fmt.Sprintf(conn.CacheKey_UserSession, sessionCookie.Value)).Result()
	if err != nil {
		c.Abort()
		if errors.Is(err, redis.Nil) {
			util.Fail(c, http.StatusUnauthorized, "请先登陆")
		} else {
			log.Error(ctx, err)
			util.FailByErr(c, errs.NewSystemBusyErr(err))
		}
		return
	}
	session, err := service.GetUserSessionInfo(ctx, sessionStr)
	if err != nil {
		c.Abort()
		// 删除非法会话
		if errors.Is(err, errs.ErrUnknownUser) {
			log.ErrorIf(ctx, conn.GetRedisClient(ctx).Del(ctx, sessionCookie.Value).Err())
		}
		util.FailByErr(c, err)
		return
	}

	// 校验状态和IP
	if session.TUser.Status != model.TUser_Status_OK {
		c.Abort()
		util.Fail(c, http.StatusForbidden, "账号已锁定")
		return
	}
	if session.LoginIP != ip {
		c.Abort()
		util.Fail(c, http.StatusUnauthorized, "请先登陆")
		return
	}

	ctx = ctxs.WithUserId(ctx, session.TUser.Id)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}
