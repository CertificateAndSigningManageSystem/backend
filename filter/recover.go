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
	"net/http"

	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/util"
)

// Recover 恐慌恢复过滤器
func Recover(c *gin.Context) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf(c.Request.Context(), "handle request panic %v %s", err, log.GetStack())
			util.Fail(c, http.StatusInternalServerError, "system busy 系统繁忙")
		}
	}()
	c.Next()
}
