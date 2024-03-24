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
	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
)

// TransactionFilter 数据库事务过滤器
func TransactionFilter(c *gin.Context) {
	ctx := c.Request.Context()
	db := conn.GetMySQLClient(ctx)
	// 开启事务
	tx := db.Begin()
	// 事务会话设置到上下文中
	ctx = ctxs.WithTransaction(ctx, tx)
	c.Request = c.Request.WithContext(ctx)
	defer func() {
		ctx = c.Request.Context()
		// 检查响应头判断是否提交事务
		if len(c.Writer.Header().Get("X-CSMS-Error-Message")) > 0 {
			// 回滚事务
			log.ErrorIf(ctx, tx.Rollback().Error)
		} else {
			// 提交事务
			log.ErrorIf(ctx, tx.Commit().Error)
		}
	}()

	// 继续业务逻辑
	c.Next()
}
