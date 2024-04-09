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

package api

import "github.com/gin-gonic/gin"

// UserApi 用户管理模块
type UserApi struct{}

// Register 注册
func (*UserApi) Register(c *gin.Context) {

}

// Login 登录
func (*UserApi) Login(c *gin.Context) {

}

// Logout 登出
func (*UserApi) Logout(c *gin.Context) {

}

// UpdateInfo 更新个人信息
func (*UserApi) UpdateInfo(c *gin.Context) {

}

// ChangePasswd 修改密码
func (*UserApi) ChangePasswd(c *gin.Context) {

}

// Info 获取个人信息
func (*UserApi) Info(c *gin.Context) {

}
