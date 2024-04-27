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

// App_CreateReq 创建应用请求
type App_CreateReq struct {
	Name     string
	Platform int
	Logo     *multipart.FileHeader
	Admins   []string
	Members  []string
}

// App_UpdateReq 更新应用信息请求
type App_UpdateReq struct {
	Name    string   `json:"name"`
	Admins  []string `json:"admins"`
	Members []string `json:"members"`
}

// App_ChangeLogoReq 修改应用图标请求
type App_ChangeLogoReq struct {
	LogoId string `json:"logoId"`
}

// App_InfoRsp 应用信息响应
type App_InfoRsp struct {
	AppId    string `json:"appId,omitempty"`
	Name     string `json:"name,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
	Platform int    `json:"platform,omitempty"`
	Admins   []*struct {
		NameEn string `json:"nameEn,omitempty"`
		NameZn string `json:"nameZh,omitempty"`
	} `json:"admins,omitempty"`
	Members []*struct {
		NameEn string `json:"nameEn,omitempty"`
		NameZn string `json:"nameZh,omitempty"`
	} `json:"members,omitempty"`
}
