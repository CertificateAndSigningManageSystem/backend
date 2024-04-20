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
	switch req.Type {
	case protocol.UploadType_UserAvatar:
		if ctxs.UserId(ctx) < 0 {
			return nil, errs.ErrIllegalRequest
		}
	default:
		return nil, errs.ErrIllegalRequest
	}

	// 查询数据库，是否存在相同信息的文件
	var file model.TFile
	err := conn.GetMySQLClient(ctx).Where("name = ? and md5 = ? and sha1 = ? and sha256 = ? and size = ?",
		req.Name, req.MD5, req.SHA1, req.SHA256, req.Size).Find(&file).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	// 存在该文件，不必上传
	if file.Id > 0 {
		return &protocol.InitialUploadRsp{
			Id:     file.FileId,
			Exists: true,
		}, nil
	}

	// 生成唯一文件 id
	id, err := GenerateId(ctx, IdScope_File)
	if err != nil {
		return nil, err
	}

	// 文件上传信息记录到缓存
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
	if err = conn.GetRedisClient(ctx).HSet(ctx, conn.CacheKey_UploadFiles, id, string(bs)).Err(); err != nil {
		log.Error(ctx, err)
		// 初始化上传失败，回收唯一文件 id
		log.ErrorIf(ctx, ReclaimId(ctx, IdScope_File, id))
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

	// 获取文件上传信息缓存记录
	fileInfoStr, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFiles, req.FileId).Result()
	if err != nil {
		// 文件上传记录不存在，可能没初始化上传，或者上传超时
		if errors.Is(err, redis.Nil) {
			return errs.ErrFileNotExists
		}
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	var fileInfo fileInfoCache
	if err = json.Unmarshal([]byte(fileInfoStr), &fileInfo); err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 校验请求是同一人所为
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)
	if userId != fileInfo.UserId || authId != fileInfo.AuthId {
		return errs.ErrIllegalRequest
	}

	// 分片缓存信息中是否已存在该序号分片
	existMember, err := conn.GetRedisClient(ctx).ZRangeByScore(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId),
		&redis.ZRangeBy{Min: strconv.Itoa(req.ChunkNum), Max: strconv.Itoa(req.ChunkNum)}).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	if len(existMember) > 0 {
		return errs.NewParamsErrMsg("该分片已存在，不可再上传")
	}

	// 加锁，文件分片
	lockKey := fmt.Sprintf("%s-%d", req.FileId, req.ChunkNum)
	if !conn.Lock(ctx, lockKey, 60*time.Second) {
		return errs.ErrTooManyRequest
	}
	defer conn.Unlock(ctx, lockKey)

	// 上传分片到 tusd
	location, err := conn.GetTusClient(ctx).UploadPartByIO(ctx, io.NopCloser(req.Chunk), req.ChunkSize)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 处理失败，删除分片，避免残留未追踪的分片
	defer func() {
		if err != nil {
			go func(ctx context.Context) {
				log.ErrorIf(ctx, conn.GetTusClient(ctx).DiscardParts(ctx, []string{location}))
			}(ctxs.CloneCtx(ctx))
		}
	}()

	// 记录该序号分片上传记录到缓存
	err = conn.GetRedisClient(ctx).ZAdd(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId), redis.Z{
		Score:  float64(req.ChunkNum),
		Member: fmt.Sprintf("%s,%d", location, req.ChunkSize),
	}).Err()
	if err != nil && !errors.Is(err, redis.Nil) {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	return nil
}

// MergePart 合并分片文件
func MergePart(ctx context.Context, req *protocol.MergePartReq) error {
	// 校验参数
	if len(req.FileId) != FileIdLength {
		return errs.NewParamsErr(nil)
	}

	// 获取文件上传缓存信息
	fileInfoStr, err := conn.GetRedisClient(ctx).HGet(ctx, conn.CacheKey_UploadFiles, req.FileId).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errs.ErrFileNotExists
		}
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	var fileInfo fileInfoCache
	if err = json.Unmarshal([]byte(fileInfoStr), &fileInfo); err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 校验请求是同一人
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)
	if userId != fileInfo.UserId || authId != fileInfo.AuthId {
		return errs.ErrIllegalRequest
	}

	// 加锁，文件，避免定时任务在处理垃圾分片
	if !conn.LockWait(ctx, req.FileId, time.Second*60) {
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

	// 检查分片序号
	partIds := make([]string, 0, len(result))
	fileSize := 0
	for i, v := range result {
		if int(v.Score) != i+1 {
			log.Warn(ctx, "part number unexpected")
			return &errs.Error{
				HTTPStatus: http.StatusBadRequest,
				Msg:        "上传的分片序号非法",
			}
		}
		partIdSize := strings.Split(fmt.Sprint(v.Member), ",")
		size, _ := strconv.Atoi(partIdSize[1])
		fileSize += size
		partIds = append(partIds, partIdSize[0])
	}

	// 分片数据大小与约定的大小不一致
	if fileSize != fileInfo.Size {
		return errs.NewParamsErr(nil)
	}

	// tusd 合并分片
	location, err := conn.GetTusClient(ctx).MergeParts(ctx, partIds)
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 文件信息落库
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
	if err = conn.GetMySQLClient(ctx).Table(file.TableName()).Create(file).Error; err != nil {
		log.Error(ctx, location, err)
		return errs.NewSystemBusyErr(err)
	}

	// 删除文件缓存信息
	txPipeline := conn.GetRedisClient(ctx).TxPipeline()
	// 不删除键，因为可能还有上传的分片。按 score 删除，避免删除同 tusId
	txPipeline.ZRemRangeByScore(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, req.FileId), "1", strconv.Itoa(len(result)))
	// 若删除失败也会在定时任务中删除
	txPipeline.HDel(ctx, conn.CacheKey_UploadFiles, req.FileId)
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
	log.Info(ctx, "start clean multipart upload")

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
			if !conn.Lock(ctx, fileId, 0) {
				return
			}
			defer conn.Unlock(ctx, fileId)

			// 加锁后校验
			b, err := conn.GetRedisClient(ctx).HExists(ctx, conn.CacheKey_UploadFiles, fileId).Result()
			if err != nil {
				log.Error(ctx, err)
				return
			}
			// 文件缓存已经不存在了
			if !b {
				return
			}

			// 获取文件上传缓存信息
			var fileInfo fileInfoCache
			if err = json.Unmarshal([]byte(fileInfoStr), &fileInfo); err != nil {
				log.Error(ctx, err)
				return
			}

			// 判断时间
			ct, err := time.ParseInLocation("20060102150405", fileInfo.CreateTime, time.Local)
			if err != nil {
				log.Error(ctx, err)
				return
			}
			if time.Since(ct) < 6*time.Hour {
				return
			}

			// 删除分片上传任务，但不删除分片信息键，因为可能还在上传添加分片
			members, err := conn.GetRedisClient(ctx).ZRange(ctx,
				fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId), 0, -1).Result()
			if err != nil {
				log.Error(ctx, err)
				return
			}
			partIds := gotools.ConvertSlice(members, func(e string) string { return strings.Split(e, ",")[0] })

			// 删除分片
			if len(partIds) > 0 {
				if err = conn.GetTusClient(ctx).DiscardParts(ctx, partIds); err != nil {
					log.Error(ctx, err)
					return
				}
			}

			// 按 member 删，因为可能还有上传的
			txPipeline := conn.GetRedisClient(ctx).TxPipeline()
			if len(members) > 0 {
				log.ErrorIf(ctx, txPipeline.ZRem(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId),
					gotools.ConvertSlice(members, func(e string) any { return e })...).Err())
			}

			// 删除上传文件信息
			txPipeline.HDel(ctx, conn.CacheKey_UploadFiles, fileId)
			if _, err = txPipeline.Exec(ctx); err != nil {
				log.Error(ctx, err)
				return
			}
		}(fileId, fileInfoStr)
	}

	// 清除有分片但没文件上传信息的任务。可能在合并分片时，上传了分片导致。
	keys, err := conn.GetRedisClient(ctx).Keys(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, "*")).Result()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	for _, key := range keys {
		arr := strings.Split(key, ":")
		fileId := arr[2]
		exists, err := conn.GetRedisClient(ctx).HExists(ctx, conn.CacheKey_UploadFiles, fileId).Result()
		if err != nil {
			log.Error(ctx, err)
			continue
		}

		// 任务存在
		if exists {
			continue
		}

		// 获取分片信息
		members, err := conn.GetRedisClient(ctx).ZRange(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId),
			0, -1).Result()
		if err != nil {
			log.Error(ctx, err)
			continue
		}
		partIds := gotools.ConvertSlice(members, func(e string) string { return strings.Split(e, ",")[0] })

		// 无分片处理
		if len(partIds) <= 0 {
			continue
		}

		// 删除分片
		if err = conn.GetTusClient(ctx).DiscardParts(ctx, partIds); err != nil {
			log.Error(ctx, err)
			continue
		}

		// 删除分片缓存，根据 member 删除，避免有在上传分片
		log.ErrorIf(ctx, conn.GetRedisClient(ctx).ZRem(ctx, fmt.Sprintf(conn.CacheKey_UploadPartFmt, fileId),
			gotools.ConvertSlice(members, func(e string) any { return e })...).Err())

		// 如果文件 id 不存在数据库中，则回收唯一 id。文件存在数据库中，说明合并文件分片时，还在上传文件分片。
		tfile, err := GetFileById(ctx, fileId)
		if err != nil {
			log.Error(ctx, err)
			continue
		}
		if tfile.Id <= 0 {
			log.ErrorIf(ctx, ReclaimId(ctx, IdScope_File, fileId))
		}

	}

	return nil
}
