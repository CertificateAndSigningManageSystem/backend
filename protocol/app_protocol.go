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

// CreateReq 创建应用请求
type CreateReq struct {
	Name     string
	Platform int
	Logo     *multipart.FileHeader
	Admins   []string
	Members  []string
}

type UpdateReq struct {
	Name    string   `json:"name"`
	Admins  []string `json:"admins"`
	Members []string `json:"members"`
}
