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
	// 下载用户头像
	File_DownloadType_UserAvatar = 1 + iota
	// 下载应用图标
	File_DownloadType_AppLogo
)

const (
	// 上传用户头像
	File_UploadType_UserAvatar = 1 + iota
	// 上传应用图标
	File_UploadType_AppLogo
)

// File_InitialUploadReq 初始化分片上传请求参数
type File_InitialUploadReq struct {
	Type   int    `json:"type"`
	Name   string `json:"name"`
	Size   int    `json:"size"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// File_InitialUploadRsp 初始化分片上传响应数据
type File_InitialUploadRsp struct {
	Id     string `json:"id,omitempty"`
	Exists bool   `json:"exists,omitempty"`
}

// File_UploadPartReq 上传分片请求参数
type File_UploadPartReq struct {
	FileId    string
	ChunkNum  int
	ChunkSize int
	Chunk     io.Reader
}

// File_MergePartReq 合并分片请求
type File_MergePartReq struct {
	FileId string
}

// File_DownloadReq 下载请求参数
type File_DownloadReq struct {
	Type   int    `form:"type"`
	AppId  string `form:"appId"`
	FileId string `form:"fileId"`
}
