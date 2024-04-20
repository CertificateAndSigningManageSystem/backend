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

import "io"

const (
	// DownloadType_UserAvatar 下载用户头像
	DownloadType_UserAvatar = 1 + iota
)

const (
	UploadType_UserAvatar = 1 + iota
)

// InitialUploadReq 初始化分片上传请求参数
type InitialUploadReq struct {
	Type   int    `json:"type"`
	Name   string `json:"name"`
	Size   int    `json:"size"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// InitialUploadRsp 初始化分片上传响应数据
type InitialUploadRsp struct {
	Id     string `json:"id"`
	Exists bool   `json:"exists"`
}

// UploadPartReq 上传分片请求参数
type UploadPartReq struct {
	FileId    string
	ChunkNum  int
	ChunkSize int
	Chunk     io.Reader
}

// MergePartReq 合并分片请求
type MergePartReq struct {
	FileId string
}

// DownloadReq 下载请求参数
type DownloadReq struct {
	Type   int    `form:"type"`
	AppId  string `form:"appId"`
	FileId string `form:"fileId"`
}
