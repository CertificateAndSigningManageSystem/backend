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
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/util"
)

// DateCheckFilter HTTP 请求头时间校验
func DateCheckFilter(c *gin.Context) {
	// 获取并校验请求时间
	date := c.Request.Header.Get("Date")
	reqDate, err := time.ParseInLocation("Mon, 02 Jan 2006 15:04:05 GMT", date, time.Local)
	if err != nil {
		c.Abort()
		util.FailByErr(c, &errs.Error{
			HTTPStatus: http.StatusBadRequest,
			WrappedErr: err,
		})
		return
	}
	// 请求时间超时
	if since := time.Since(reqDate); since > antiShakeMaxPeriod || since < 0 {
		c.Abort()
		util.FailByErr(c, &errs.Error{
			HTTPStatus: http.StatusBadRequest,
			WrappedErr: fmt.Errorf("since is %v", since),
		})
		return
	}

	c.Next()
}
