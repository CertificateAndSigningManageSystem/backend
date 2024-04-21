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
	"encoding/json"
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

// WebAuthFilter Web 接口会话鉴权
func WebAuthFilter(c *gin.Context) {
	ctx := c.Request.Context()
	ip := ctxs.RequestIP(ctx)

	// 获取会话
	skey, err := c.Cookie(consts.SessionKey)
	if err != nil {
		c.Abort()
		// 不存在会话凭证
		if errors.Is(err, http.ErrNoCookie) {
			util.FailByErr(c, errs.ErrNeedLogin)
		} else {
			log.Error(ctx, err)
			util.FailByErr(c, errs.NewSystemBusyErr(err))
		}
		return
	}
	user, err := c.Cookie(consts.SessionUser)
	if err != nil {
		c.Abort()
		if errors.Is(err, http.ErrNoCookie) {
			util.FailByErr(c, errs.ErrNeedLogin)
		} else {
			log.Error(ctx, err)
			util.FailByErr(c, errs.NewSystemBusyErr(err))
		}
	}

	// 获取会话信息
	session, err := conn.GetRedisClient(ctx).Get(
		ctx, fmt.Sprintf(conn.CacheKey_UserSessionFmt, user, skey)).Result()
	if err != nil {
		c.Abort()
		if errors.Is(err, redis.Nil) {
			util.FailByErr(c, errs.ErrNeedLogin)
		} else {
			log.Error(ctx, err)
			util.FailByErr(c, errs.NewSystemBusyErr(err))
		}
		return
	}

	// 反序列数据
	var data service.SessionInfo
	err = json.Unmarshal([]byte(session), &data)
	if err != nil {
		c.Abort()
		log.Error(ctx, err, session)
		util.FailByErr(c, errs.NewSystemBusyErr(err))
		return
	}
	if data.UserId <= 0 {
		c.Abort()
		util.FailByErr(c, errs.ErrNeedLogin)
		return
	}

	// 查库
	var tuser model.TUser
	err = conn.GetMySQLClient(ctx).Where("id = ?", data.UserId).Find(&tuser).Error
	if err != nil {
		c.Abort()
		log.Error(ctx, err)
		return
	}
	if tuser.Id <= 0 {
		c.Abort()
		log.Warn(ctx, "unknown user", session)
		util.FailByErr(c, errs.ErrNeedLogin)
		return
	}

	// 校验状态和IP
	if tuser.Status != model.TUser_Status_OK {
		c.Abort()
		util.Fail(c, http.StatusForbidden, "账号已锁定")
		return
	}
	if data.LoginIP != ip {
		c.Abort()
		util.FailByErr(c, errs.ErrNeedLogin)
		return
	}

	ctx = ctxs.WithUserId(ctx, tuser.Id)
	ctx = ctxs.WithUserName(ctx, tuser.NameEn)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}
