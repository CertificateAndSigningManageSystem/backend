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

import "time"

// HLK_QueryJobInfoReq 查询 hlk 测试任务请求
type HLK_QueryJobInfoReq struct {
	Id uint `form:"id"`
}

// HLK_QueryJobInfoRsp 查询 hlk 测试任务响应
type HLK_QueryJobInfoRsp struct {
	Id            uint      `json:"id"`
	UserId        uint      `json:"userId"`
	AppId         uint      `json:"appId"`
	FileId        string    `json:"fileId"`
	HLKTestSystem string    `json:"hlkTestSystem"`
	CreateTime    time.Time `json:"createTime"`
	FinishTime    time.Time `json:"finishTime"`
	Status        uint8     `json:"status"`
	TmpFileId     string    `json:"tmpFileId"`
	SignedFileId  string    `json:"signedFileId"`
}
