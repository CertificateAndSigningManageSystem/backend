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
	"backend/filter"

	"github.com/gin-gonic/gin"
)

// InitialRouter 初始化路由
func InitialRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	filter.InitialAuthenticateFilter(map[string][]uint{})
	return engine
}
