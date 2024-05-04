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

	"gitee.com/CertificateAndSigningManageSystem/backend/api"
	"gitee.com/CertificateAndSigningManageSystem/backend/filter"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

func initWebRoute(r *gin.RouterGroup) {
	// 文件接口
	file := &api.FileAPI{}
	fileGroup := r.Group("/file", filter.DateCheckFilter, filter.WebAuthFilter)
	fileGroup.POST("/initialUpload", filter.AntiShakeFilter, file.InitialUpload)
	fileGroup.PATCH("/uploadPart", file.UploadPart)
	fileGroup.POST("/mergePart", file.MergePart)
	fileGroup.GET("/download", file.Download)

	// 用户管理模块
	user := &api.UserApi{}
	userGroup := r.Group("/user", filter.DateCheckFilter)
	userGroup.POST("/register", filter.TransactionFilter, user.Register)
	userGroup.POST("/login", filter.TransactionFilter, user.Login)
	userGroup.DELETE("/logout", filter.WebAuthFilter, user.Logout)
	userGroup.GET("/info", filter.WebAuthFilter, user.Info)
	userGroup.PUT("/updateInfo", filter.WebAuthFilter, filter.AntiShakeFilter, filter.TransactionFilter, user.UpdateInfo)
	userGroup.POST("/changePassword", filter.WebAuthFilter, filter.AntiShakeFilter, filter.TransactionFilter, user.ChangePassword)
	userGroup.PUT("/changeAvatar", filter.WebAuthFilter, filter.AntiShakeFilter, filter.TransactionFilter, user.ChangeAvatar)

	// 应用管理模块
	app := &api.AppApi{}
	appGroup := r.Group("/app", filter.DateCheckFilter, filter.WebAuthFilter)
	appGroup.POST("/create", filter.AntiShakeFilter, filter.TransactionFilter, app.Create)
	filter.AddPathAuthorities("/web/app/update", model.TUserRole_Role_AppAdmin)
	appGroup.POST("/update/:appId", filter.AntiShakeFilter, filter.AuthenticateFilter, filter.TransactionFilter, app.Update)
	filter.AddPathAuthorities("/web/app/delete", model.TUserRole_Role_AppAdmin)
	appGroup.DELETE("/delete/:appId", filter.AntiShakeFilter, filter.AuthenticateFilter, filter.TransactionFilter, app.Delete)
	filter.AddPathAuthorities("/web/app/changeLogo", model.TUserRole_Role_AppAdmin)
	appGroup.PUT("/changeLogo/:appId", filter.AntiShakeFilter, filter.AuthenticateFilter, filter.TransactionFilter, app.ChangeLogo)
	filter.AddPathAuthorities("/web/app/info", model.TUserRole_Role_Admin, model.TUserRole_Role_AppAdmin, model.TUserRole_Role_AppMember)
	appGroup.GET("/info/:appId", filter.AuthenticateFilter, app.Info)

	// open api 凭证管理
	openapi := &api.OpenApi{}
	openapiGroup := r.Group("/openapi", filter.DateCheckFilter, filter.WebAuthFilter)
	filter.AddPathAuthorities("/web/openapi/create", model.TUserRole_Role_AppAdmin)
	openapiGroup.POST("/create/:appId", filter.AntiShakeFilter, filter.AuthenticateFilter, filter.TransactionFilter, openapi.Create)
	filter.AddPathAuthorities("/web/openapi/update", model.TUserRole_Role_AppAdmin)
	openapiGroup.PUT("/update/:appId", filter.AntiShakeFilter, filter.AuthenticateFilter, filter.TransactionFilter, openapi.Update)

}
