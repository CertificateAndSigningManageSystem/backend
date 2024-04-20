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

// RegisterReq 注册请求
type RegisterReq struct {
	NameZh    string                `json:"nameZh"`
	NameEn    string                `json:"nameEn"`
	Avatar    *multipart.FileHeader `json:"-"`
	Password  string                `json:"password"`
	UserAgent string                `json:"userAgent"`
}

// LoginReq 登陆请求
type LoginReq struct {
	Name      string `json:"name"`
	Password  string `json:"password"`
	UserAgent string `json:"userAgent"`
}

// UserInfoRsp 用户信息响应
type UserInfoRsp struct {
	NameEn string `json:"nameEn"`
	Avatar string `json:"avatar"`
	NameZh string `json:"nameZh"`
}

// UpdateInfoReq 更新用户信息请求
type UpdateInfoReq struct {
	NameZh string `json:"nameZh"`
	Avatar string `json:"avatar"`
}
