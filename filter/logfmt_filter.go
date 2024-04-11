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
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/util"
)

// LogfmtFilter 日志过滤器
func LogfmtFilter(c *gin.Context) {
	// 组装上下信息
	rid := c.Request.Header.Get("X-CSMS-Request-Id")
	if len(rid) <= 0 {
		rid = strings.ReplaceAll(uuid.New().String(), "-", "")
	}
	ctx := ctxs.WithRequestId(c.Request.Context(), rid)
	reqPath := strings.ToLower(c.Request.URL.Path)
	ctx = ctxs.WithRequestPath(ctx, reqPath)
	ip := c.Request.Header.Get("X-Real-IP")
	ctx = ctxs.WithRequestId(ctx, ip)
	c.Request = c.Request.WithContext(ctx)

	// 打印请求信息
	ct := c.Request.Header.Get(http.CanonicalHeaderKey("Content-Type"))
	cl := c.Request.Header.Get("Content-Length")
	log.Info(ctx, "START PROCESS", c.Request.Method, cl, ct, c.Request.URL.RawQuery)
	clNum, _ := strconv.ParseInt(cl, 10, 64)
	if s := strings.ToLower(ct); strings.HasPrefix(s, "application/json") ||
		strings.HasPrefix(s, "application/x-www-form-urlencoded") && clNum < 5*1024 {
		reqBody, _ := io.ReadAll(c.Request.Body)
		util.CloseIO(ctx, c.Request.Body)
		log.Info(ctx, "reqBody is", string(reqBody))
		c.Request.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	// 打印响应信息
	now := time.Now()
	defer func() {
		cost := time.Since(now)
		ctx = c.Request.Context()
		msg := c.Writer.Header().Get("X-CSMS-Error-Message")
		msg, err := url.QueryUnescape(msg)
		if err == nil && len(msg) > 0 {
			log.Warn(ctx, "END PROCESS",
				cost, c.Writer.Status(), http.StatusText(c.Writer.Status()),
				c.Writer.Header().Get("Content-Length"), msg)
		} else {
			log.Info(ctx, "END PROCESS",
				cost, c.Writer.Status(), http.StatusText(c.Writer.Status()),
				c.Writer.Header().Get("Content-Length"))
		}
	}()

	c.Next()
}
