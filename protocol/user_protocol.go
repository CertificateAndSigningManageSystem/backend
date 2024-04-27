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

package protocol

import "mime/multipart"

// User_RegisterReq 注册请求
type User_RegisterReq struct {
	NameZh    string
	NameEn    string
	Avatar    *multipart.FileHeader
	Password  string
	UserAgent string
}

// User_LoginReq 登陆请求
type User_LoginReq struct {
	Name      string `json:"name"`
	Password  string `json:"password"`
	UserAgent string `json:"userAgent"`
}

// User_InfoRsp 用户信息响应
type User_InfoRsp struct {
	NameEn string `json:"nameEn,omitempty"`
	Avatar string `json:"avatar,omitempty"`
	NameZh string `json:"nameZh,omitempty"`
}

// User_UpdateInfoReq 更新用户信息请求
type User_UpdateInfoReq struct {
	NameZh string `json:"nameZh"`
}

// User_ChangePasswordReq 更改密码请求
type User_ChangePasswordReq struct {
	OldPassword      string `json:"oldPassword"`
	NewPassword      string `json:"newPassword"`
	NewPasswordAgain string `json:"newPasswordAgain"`
}

// User_ChangeAvatarReq 修改头像请求
type User_ChangeAvatarReq struct {
	Avatar *multipart.FileHeader
}
