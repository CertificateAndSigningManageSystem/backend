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

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"

	"backend/protocol"
)

type fileInfo struct {
	Name       string
	SHA1       string
	SHA256     string
	MD5        string
	CreateTime string
	UserId     uint
	AuthId     uint
	Size       int
}

// InitialUpload 初始化分片上传
func InitialUpload(ctx context.Context, req *protocol.InitialUploadReq) (*protocol.InitialUploadRsp, error) {
	// 查询数据库
	var file model.TFile
	err := conn.GetMySQLClient(ctx).Where("name = ? and md5 = ? and sha1 = ? and sha256 = ? and size = ?",
		req.Name, req.MD5, req.SHA1, req.SHA256, req.Size).Find(&file).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	if file.Id > 0 {
		return &protocol.InitialUploadRsp{
			Id:     file.FileId,
			Exists: true,
		}, nil
	}

	// 生成id
	id, err := GenerateId(ctx, IdScope_File)
	if err != nil {
		return nil, err
	}

	// 记录
	fileInfo := &fileInfo{
		UserId:     ctxs.UserId(ctx),
		AuthId:     ctxs.APIAuthId(ctx),
		Name:       req.Name,
		MD5:        req.MD5,
		SHA1:       req.SHA1,
		SHA256:     req.SHA256,
		Size:       req.Size,
		CreateTime: time.Now().Format("20060102150405"),
	}
	bs, _ := json.Marshal(fileInfo)
	err = conn.GetRedisClient(ctx).HSet(ctx, conn.CacheKey_UploadFiles, id, string(bs)).Err()
	if err != nil {
		log.Error(ctx, err)
		err = ReclaimId(ctx, IdScope_File, id)
		if err != nil {
			return nil, err
		}
		return nil, errs.NewParamsErr(err)
	}

	return &protocol.InitialUploadRsp{
		Id: file.FileId,
	}, nil
}

// UploadPart 上传分片
func UploadPart(ctx context.Context, req *protocol.UploadPartReq) error {
	if req.Chunk == nil || req.ChunkSize <= 0 || req.ChunkNum <= 0 || len(req.FileId) <= 0 {
		return errs.NewParamsErr(nil)
	}

	// 校验
	fileInfoStr, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFiles, req.FileId).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errs.NewParamsErr(err)
		}
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	var fileInfo fileInfo
	err = json.Unmarshal([]byte(fileInfoStr), &fileInfo)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)
	if userId != fileInfo.UserId || authId != fileInfo.AuthId {
		return &errs.Error{
			HTTPStatus: http.StatusUnauthorized,
			Msg:        "illegal request",
		}
	}

	// 加锁
	lockKey := fmt.Sprintf("%s-%d", req.FileId, req.ChunkNum)
	lock := conn.Lock(ctx, lockKey, 0)
	if !lock {
		return &errs.Error{
			HTTPStatus: http.StatusTooManyRequests,
			Msg:        "too many request",
		}
	}
	defer conn.Unlock(ctx, lockKey)

	// 获取分片信息
	result, err := conn.GetRedisClient(ctx).ZRange(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId),
		int64(req.ChunkNum), int64(req.ChunkNum)).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	hasPartId := ""
	if len(result) > 0 {
		// 存在上传的分片
		hasPartId = result[0]
	}

	// 上传到tusd
	location, err := conn.GetTusClient(ctx).UploadPartByIO(ctx, io.NopCloser(req.Chunk), req.ChunkSize)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 记录分片
	err = conn.GetRedisClient(ctx).ZAdd(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId), redis.Z{
		Score:  float64(req.ChunkNum),
		Member: location,
	}).Err()
	if err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}

	// 删除覆盖了的分片
	if len(hasPartId) > 0 {
		err = conn.GetTusClient(ctx).DiscardParts(ctx, []string{hasPartId})
		if err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
	}

	return nil
}

// MergePart 合并分片文件
func MergePart(ctx context.Context, req *protocol.MergePartReq) error {
	if len(req.FileId) <= 0 {
		return errs.NewParamsErr(nil)
	}

	// 校验
	fileInfoStr, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFiles, req.FileId).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errs.NewParamsErr(err)
		}
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	var fileInfo fileInfo
	err = json.Unmarshal([]byte(fileInfoStr), &fileInfo)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)
	if userId != fileInfo.UserId || authId != fileInfo.AuthId {
		return &errs.Error{
			HTTPStatus: http.StatusUnauthorized,
			Msg:        "illegal request",
		}
	}

	// 加锁
	lock := conn.Lock(ctx, req.FileId, 0)
	if !lock {
		return &errs.Error{
			HTTPStatus: http.StatusTooManyRequests,
			Msg:        "too many request",
		}
	}
	defer conn.Unlock(ctx, req.FileId)

	// 获取分片信息
	result, err := conn.GetRedisClient(ctx).ZRangeWithScores(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId),
		0, -1).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 检查分片
	slices.SortFunc(result, func(a, b redis.Z) int {
		return int(a.Score - b.Score)
	})
	partIds := make([]string, 0, len(result))
	for i, v := range result {
		if int(v.Score) != i+1 {
			log.Warn(ctx, "part number unexpected")
			return &errs.Error{
				HTTPStatus: http.StatusBadRequest,
				Msg:        "part number unexpected",
			}
		}
		partIds = append(partIds, fmt.Sprint(v.Member))
	}

	// 合并分片
	location, err := conn.GetTusClient(ctx).MergeParts(ctx, partIds)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 数据落库
	uid := userId
	if uid <= 0 {
		uid = authId
	}
	ext := ""
	index := strings.LastIndex(fileInfo.Name, ".")
	if index >= 0 {
		ext = fileInfo.Name[index+1:]
	}
	err = conn.GetMySQLClient(ctx).Create(&model.TFile{
		FileId:     req.FileId,
		UserId:     uid,
		TusdId:     location,
		Name:       fileInfo.Name,
		Ext:        ext,
		MD5:        fileInfo.MD5,
		SHA1:       fileInfo.SHA1,
		SHA256:     fileInfo.SHA256,
		Size:       fileInfo.Size,
		CreateTime: time.Now(),
	}).Error
	if err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}

	// 删除分片缓存信息
	err = conn.GetRedisClient(ctx).Del(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId)).Err()
	if err != nil {
		log.Error(ctx, err)
	}
	err = conn.GetRedisClient(ctx).HDel(ctx, conn.CacheKey_UploadFiles, req.FileId).Err()
	if err != nil {
		log.Error(ctx, err)
	}

	return nil
}
