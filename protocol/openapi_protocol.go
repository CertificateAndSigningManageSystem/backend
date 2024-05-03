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

// Open_CreateReq 创建凭证请求
type Open_CreateReq struct {
	Id        string `json:"id"`
	IP        string `json:"ip"`
	Frequency int    `json:"frequency"`
	ActionIds []int  `json:"actionIds"`
}

// Open_CreateRsp 创建凭证响应
type Open_CreateRsp struct {
	Secret string `json:"secret"`
}

// Open_UpdateReq 修改凭证请求
type Open_UpdateReq struct {
	Id        string `json:"id"`
	IP        string `json:"ip"`
	Frequency int    `json:"frequency"`
	ActionIds []int  `json:"actionIds"`
}
