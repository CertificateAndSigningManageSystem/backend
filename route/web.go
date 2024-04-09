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
	upload := &api.UploadAPI{}
	uploadGroup := r.Group("/upload")
	uploadGroup.POST("/initialUpload", filter.AntiShakeFilter, upload.InitialUpload)
	uploadGroup.PATCH("/uploadPart", upload.UploadPart)
	uploadGroup.POST("/mergePart", filter.AntiShakeFilter, upload.MergePart)

	// 用户管理模块
	user := &api.UserApi{}
	userGroup := r.Group("/user", filter.AntiShakeFilter)
	userGroup.POST("/register", user.Register)
	userGroup.POST("/login", user.Login)
	userGroup.DELETE("/logout", user.Logout)
	userGroup.PUT("/updateInfo", user.UpdateInfo)
	userGroup.POST("/changePasswd", user.ChangePasswd)
	userGroup.GET("/info", user.Info)
}
