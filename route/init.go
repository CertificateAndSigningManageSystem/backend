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

package route

import (
	"context"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"gitee.com/CertificateAndSigningManageSystem/backend/filter"
)

// InitialRouter 初始化路由
func InitialRouter(ctx context.Context) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(filter.ExitFilter(ctx), filter.Recover, filter.LogfmtFilter)

	swagger := engine.Group("/swagger")
	swagger.GET("*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	web := engine.Group("/web")
	api := engine.Group("/api")
	initWebRoute(web)
	initAPIRoute(api)
	filter.InitialPathAuthoritiesDAT()
	filter.InitialAPIAuthLimitScript(ctx)
	filter.InitialAntiShakeScript(ctx)

	return engine
}

// InitialInternalRouter 初始化内部网络接口
func InitialInternalRouter(ctx context.Context) *gin.Engine {
	engine := gin.New()
	engine.Use(filter.ExitFilter(ctx), filter.Recover, filter.LogfmtFilter)

	hlk := engine.Group("/hlk")
	initHLKRoute(hlk)

	return engine
}
