package filter

import (
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
)

func TransactionFilter(c *gin.Context) {
	ctx := c.Request.Context()
	db := conn.GetMySQLClient(ctx)
	// 开启事务
	tx := db.Begin()
	// 事务会话设置到上下文中
	ctx = ctxs.WithTransaction(ctx, tx)
	c.Request = c.Request.WithContext(ctx)
	// 继续业务逻辑
	c.Next()
	ctx = c.Request.Context()
	// 检查响应头判断是否提交事务
	if len(c.Writer.Header().Get("CSMS-Error-Message")) > 0 {
		// 回滚事务
		log.LogIfError(ctx, tx.Rollback().Error)
	} else {
		// 提交事务
		log.LogIfError(ctx, tx.Commit().Error)
	}
}
