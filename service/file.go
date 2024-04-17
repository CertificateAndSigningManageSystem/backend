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
	"strconv"
	"strings"
	"time"

	"gitee.com/ivfzhou/gotools/v4"
	"gitee.com/ivfzhou/tus_client"
	"github.com/redis/go-redis/v9"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/protocol"
)

type fileInfoCache struct {
	Name       string `json:"name,omitempty"`
	SHA1       string `json:"sha1,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	MD5        string `json:"md5,omitempty"`
	CreateTime string `json:"createTime,omitempty"`
	UserId     uint   `json:"userId,omitempty"`
	AuthId     uint   `json:"authId,omitempty"`
	Size       int    `json:"size,omitempty"`
}

// InitialUpload 初始化分片上传
func InitialUpload(ctx context.Context, req *protocol.InitialUploadReq) (*protocol.InitialUploadRsp, error) {
	// 校验参数
	if len(req.SHA1) != 40 || len(req.SHA256) != 64 || len(req.MD5) != 32 || len(req.Name) <= 0 || req.Size <= 0 {
		return nil, errs.NewParamsErr(nil)
	}

	// 查询数据库
	var file model.TFile
	err := conn.GetMySQLClient(ctx).Where("name = ? and md5 = ? and sha1 = ? and sha256 = ? and size = ?",
		req.Name, req.MD5, req.SHA1, req.SHA256, req.Size).Find(&file).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	if file.Id > 0 {
		// 存在，不必上传
		return &protocol.InitialUploadRsp{
			Id:     file.FileId,
			Exists: true,
		}, nil
	}

	// 生成唯一id
	id, err := GenerateId(ctx, IdScope_File)
	if err != nil {
		return nil, err
	}
	defer func() {
		// 回收唯一id
		if err != nil {
			log.ErrorIf(ctx, ReclaimId(ctx, IdScope_File, id))
		}
	}()

	// 记录到缓存
	fileInfo := &fileInfoCache{
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
		return nil, errs.NewSystemBusyErr(err)
	}

	return &protocol.InitialUploadRsp{Id: id}, nil
}

// UploadPart 上传分片
func UploadPart(ctx context.Context, req *protocol.UploadPartReq) error {
	// 校验参数
	if req.Chunk == nil || req.ChunkSize <= 0 || req.ChunkNum <= 0 || len(req.FileId) != FileIdLength {
		return errs.NewParamsErr(nil)
	}

	// 获取缓存记录
	fileInfoStr, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFiles, req.FileId).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errs.ErrFileNotExists
		}
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	var fileInfo fileInfoCache
	err = json.Unmarshal([]byte(fileInfoStr), &fileInfo)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 获取缓存，分片已上传大小
	fileSize, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFileSize, req.FileId).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 上传分片数据大小超过了可允许上传的大小
	if fileSize >= fileInfo.Size {
		return errs.NewParamsErr(nil)
	}

	// 校验请求，是同一人
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)
	if userId != fileInfo.UserId || authId != fileInfo.AuthId {
		return errs.ErrIllegalRequest
	}

	// 加锁，文件分片
	lockKey := fmt.Sprintf("%s-%d", req.FileId, req.ChunkNum)
	lock := conn.Lock(ctx, lockKey, 0)
	if !lock {
		return errs.ErrTooManyRequest
	}
	defer conn.Unlock(ctx, lockKey)

	// 是否缓存分片中已有该序号
	result, err := conn.GetRedisClient(ctx).ZRange(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId),
		int64(req.ChunkNum), int64(req.ChunkNum+1)).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	hasPartId := ""
	if len(result) > 0 {
		// 存在上传的分片
		hasPartId = result[0]
	}

	// 上传分片到tusd
	location, err := conn.GetTusClient(ctx).UploadPartByIO(ctx, io.NopCloser(req.Chunk), req.ChunkSize)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 记录分片序号到缓存
	txPipeline := conn.GetRedisClient(ctx).TxPipeline()
	err = txPipeline.ZAdd(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId), redis.Z{
		Score:  float64(req.ChunkNum),
		Member: fmt.Sprintf("%s,%d", location, req.ChunkSize),
	}).Err()
	if err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}

	// 记录上传数据大小
	err = txPipeline.HIncrBy(ctx, conn.CacheKey_UploadFileSize, req.FileId, int64(req.ChunkSize)).Err()
	if err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}
	_, err = txPipeline.Exec(ctx)
	if err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}

	// 删除覆盖了的分片
	if len(hasPartId) > 0 {
		go func(ctx context.Context) {
			log.ErrorIf(ctx, util.DoThreeTimesIfErr(func() error {
				return conn.GetTusClient(ctx).DiscardParts(ctx, []string{hasPartId})
			}))
		}(ctxs.CloneCtx(ctx))
	}

	return nil
}

// MergePart 合并分片文件
func MergePart(ctx context.Context, req *protocol.MergePartReq) error {
	// 校验参数
	if len(req.FileId) != FileIdLength {
		return errs.NewParamsErr(nil)
	}

	// 获取文件缓存信息
	fileInfoStr, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFiles, req.FileId).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errs.ErrFileNotExists
		}
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	var fileInfo fileInfoCache
	err = json.Unmarshal([]byte(fileInfoStr), &fileInfo)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 校验请求，是同一人
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)
	if userId != fileInfo.UserId || authId != fileInfo.AuthId {
		return errs.ErrIllegalRequest
	}

	// 加锁，文件，避免在处理垃圾分片
	lock := conn.LockWait(ctx, req.FileId, time.Second*3)
	if !lock {
		return errs.ErrTooManyRequest
	}
	defer conn.Unlock(ctx, req.FileId)

	// 获取文件分片信息
	result, err := conn.GetRedisClient(ctx).ZRangeWithScores(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId),
		0, -1).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 检查分片序号，排序
	slices.SortFunc(result, func(a, b redis.Z) int { return int(a.Score - b.Score) })
	partIds := make([]string, 0, len(result))
	fileSize := 0
	for i, v := range result {
		if int(v.Score) != i+1 {
			log.Warn(ctx, "part number unexpected")
			return &errs.Error{
				HTTPStatus: http.StatusBadRequest,
				Msg:        "part number unexpected",
			}
		}
		partIdSize := strings.Split(fmt.Sprint(v.Member), ",")
		if len(partIdSize) != 2 {
			log.Warn(ctx, "part size unexpected")
			return errs.NewSystemBusyErr(nil)
		}
		size, err := strconv.Atoi(partIdSize[1])
		if err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
		fileSize += size
		partIds = append(partIds, partIdSize[0])
	}

	// 分片数据大小与约定的大小不一致
	if fileSize != fileInfo.Size {
		return errs.NewParamsErr(nil)
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
	file := &model.TFile{
		FileId:     req.FileId,
		UserId:     uid,
		TusdId:     location,
		Name:       fileInfo.Name,
		MD5:        fileInfo.MD5,
		SHA1:       fileInfo.SHA1,
		SHA256:     fileInfo.SHA256,
		Size:       fileInfo.Size,
		CreateTime: time.Now(),
	}
	err = conn.GetMySQLClient(ctx).Table(file.TableName()).Create(file).Error
	if err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}

	// 删除文件缓存信息
	txPipeline := conn.GetRedisClient(ctx).TxPipeline()
	log.ErrorIf(ctx, txPipeline.Del(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId)).Err())
	log.ErrorIf(ctx, txPipeline.HDel(ctx, conn.CacheKey_UploadFiles, req.FileId).Err())
	log.ErrorIf(ctx, txPipeline.HDel(ctx, conn.CacheKey_UploadFileSize, req.FileId).Err())
	_, err = txPipeline.Exec(ctx)
	log.ErrorIf(ctx, err)

	return nil
}

// Download 下载文件
func Download(ctx context.Context, req *protocol.DownloadReq) (
	data io.ReadCloser, fileName string, fileSize int64, err error) {

	// 校验
	if len(req.FileId) <= FileIdLength {
		return nil, "", 0, errs.ErrFileNotExists
	}
	switch req.Type {
	case protocol.DownloadType_UserAvatar:
		// 查库
		var tuser model.TUser
		err = conn.GetMySQLClient(ctx).Where("id = ?", ctxs.UserId(ctx)).Find(&tuser).Error
		if err != nil {
			log.Error(ctx, err)
			return nil, "", 0, errs.NewSystemBusyErr(err)
		}
		if tuser.Avatar != req.FileId {
			return nil, "", 0, errs.NewParamsErr(nil)
		}
	default:
		return nil, "", 0, errs.NewParamsErr(nil)
	}

	// 查库
	tfile, err := GetFileById(ctx, req.FileId)
	if err != nil {
		return nil, "", 0, err
	}
	if tfile.Id <= 0 {
		return nil, "", 0, errs.ErrFileNotExists
	}

	// 下载
	getResult, err := conn.GetTusClient(ctx).Get(ctx, &tus_client.GetRequest{Location: tfile.TusdId})
	if err != nil {
		log.Error(ctx, err)
		return nil, "", 0, errs.NewSystemBusyErr(err)
	}

	return getResult.Body, tfile.Name, int64(getResult.ContentLength), nil
}

// CleanMultipartUpload 清理异常分片
func CleanMultipartUpload(ctx context.Context) error {
	// 获取所有文件缓存信息
	result, err := conn.GetRedisClient(ctx).HGetAll(ctx, conn.CacheKey_UploadFiles).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 检查清理超时任务
	for fileId, fileInfoStr := range result {
		func(fileId, fileInfoStr string) {
			// 加锁，避免在合并分片
			lock := conn.Lock(ctx, fileId, 0)
			if !lock {
				return
			}
			defer conn.Unlock(ctx, fileId)

			// 加锁后校验
			b, err := conn.GetRedisClient(ctx).HExists(ctx, conn.CacheKey_UploadFiles, fileId).Result()
			if err != nil {
				log.Error(ctx, err)
				return
			}
			if !b {
				// 文件缓存已经不存在了
				return
			}

			// 判断时间
			var fileInfo fileInfoCache
			err = json.Unmarshal([]byte(fileInfoStr), &fileInfo)
			if err != nil {
				log.Error(ctx, err)
				return
			}
			ct, err := time.ParseInLocation("20060102150405", fileInfo.CreateTime, time.Local)
			if err != nil {
				log.Error(ctx, err)
				return
			}
			if time.Since(ct) > 6*time.Hour {
				// 删除分片上传任务，但不删除分片信息键，因为可能还在上传添加分片
				partIds, err := conn.GetRedisClient(ctx).ZRange(ctx,
					fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId), 0, -1).Result()
				if err != nil {
					log.Error(ctx, err)
					return
				}
				if len(partIds) > 0 {
					if err = conn.GetTusClient(ctx).DiscardParts(ctx, partIds); err != nil {
						log.Error(ctx, err)
						return
					}
					log.ErrorIf(ctx, util.DoThreeTimesIfErr(func() error {
						return conn.GetRedisClient(ctx).ZRem(ctx,
							fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId),
							gotools.ConvertSlice(partIds, func(e string) any { return e })...).Err()
					}))
				}
				txPipeline := conn.GetRedisClient(ctx).TxPipeline()
				log.ErrorIf(ctx, txPipeline.HDel(ctx, conn.CacheKey_UploadFiles, fileId).Err())
				log.ErrorIf(ctx, txPipeline.HDel(ctx, conn.CacheKey_UploadFileSize, fileId).Err())
				_, err = txPipeline.Exec(ctx)
				log.ErrorIf(ctx, err)
			}
		}(fileId, fileInfoStr)
	}

	// 清除有分片但没文件信息的任务，在请求合并分片时，上传了分片导致。
	keys, err := conn.GetRedisClient(ctx).Keys(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, "*")).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	for _, key := range keys {
		arr := strings.Split(key, ":")
		fileId := arr[2]
		b, err := conn.GetRedisClient(ctx).HExists(ctx, conn.CacheKey_UploadFiles, fileId).Result()
		if err != nil {
			log.Error(ctx, err)
			continue
		}
		if !b {
			// 任务已不存在，删除分片
			partIds, err := conn.GetRedisClient(ctx).ZRange(ctx,
				fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId), 0, -1).Result()
			if err != nil {
				log.Error(ctx, err)
				continue
			}
			if len(partIds) > 0 {
				if err = conn.GetTusClient(ctx).DiscardParts(ctx, partIds); err != nil {
					log.Error(ctx, err)
					continue
				}
				log.ErrorIf(ctx, conn.GetRedisClient(ctx).ZRem(ctx,
					fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId),
					gotools.ConvertSlice(partIds, func(e string) any { return e })...).Err())
			}
		}
	}

	return nil
}
