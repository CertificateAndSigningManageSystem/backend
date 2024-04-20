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
	"github.com/gin-gonic/gin"

	"backend/api"
	"backend/filter"
)

func initWebRoute(r *gin.RouterGroup) {
	// 文件接口
	upload := &api.FileAPI{}
	uploadGroup := r.Group("/file", filter.DateCheckFilter, filter.WebAuthFilter)
	uploadGroup.POST("/initialUpload", filter.AntiShakeFilter, upload.InitialUpload)
	uploadGroup.PATCH("/uploadPart", upload.UploadPart)
	uploadGroup.POST("/mergePart", upload.MergePart)
	uploadGroup.GET("/download", upload.Download)

	// 用户管理模块
	user := &api.UserApi{}
	userGroup := r.Group("/user", filter.DateCheckFilter)
	userGroup.POST("/register", filter.TransactionFilter, user.Register)
	userGroup.POST("/login", filter.TransactionFilter, user.Login)
	userGroup.DELETE("/logout", filter.WebAuthFilter, filter.AntiShakeFilter, user.Logout)
	userGroup.GET("/info", filter.WebAuthFilter, user.Info)
	userGroup.PUT("/updateInfo", filter.WebAuthFilter, filter.AntiShakeFilter, user.UpdateInfo)
	userGroup.POST("/changePassword", filter.WebAuthFilter, filter.AntiShakeFilter, user.ChangePassword)
	userGroup.PUT("/changeAvatar", filter.WebAuthFilter, filter.AntiShakeFilter, filter.TransactionFilter, user.ChangeAvatar)
}
