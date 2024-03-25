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
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/service"
)

// WebAuthFilter Web接口会话鉴权
func WebAuthFilter(c *gin.Context) {
	ctx := c.Request.Context()
	ip := c.Request.Header.Get("X-Real-IP")

	// 获取会话
	sessionStr, err := c.Request.Cookie("csms_session")
	if err != nil {
		c.Abort()
		// 不存在会话凭证
		if errors.Is(err, http.ErrNoCookie) {
			util.Fail(c, http.StatusUnauthorized, "please login first 请先登录")
		} else {
			log.Error(ctx, "obtain cookie error 获取登录会话失败", err)
			util.Fail(c, http.StatusInternalServerError, "system busy 系统繁忙")
		}
		return
	}

	// 获取会话信息
	sessionVal, err := conn.GetRedisClient(ctx).Get(ctx, sessionStr.Value).Result()
	if err != nil {
		c.Abort()
		if errors.Is(err, redis.Nil) {
			util.Fail(c, http.StatusUnauthorized, "please login first 请先登录")
		} else {
			log.Error(ctx, "obtain redis key error 获取缓存信息失败", err)
			util.Fail(c, http.StatusInternalServerError, "system busy 系统繁忙")
		}
		return
	}
	session, err := service.GetSessionInfo(ctx, sessionVal)
	if err != nil {
		c.Abort()
		// 删除非法会话
		if errors.Is(err, service.ErrUnknownUser) {
			log.ErrorIf(ctx, conn.GetRedisClient(ctx).Del(ctx, sessionStr.Value).Err())
		}
		util.FailByErr(c, err)
		return
	}

	// 校验状态和IP
	if session.TUser.Status != model.TUser_Status_OK {
		c.Abort()
		util.Fail(c, http.StatusForbidden, "locked user 账户已锁")
		return
	}
	if session.LoginIP != ip {
		c.Abort()
		util.Fail(c, http.StatusUnauthorized, "illegal access 非法访问")
		return
	}

	c.Next()
}
