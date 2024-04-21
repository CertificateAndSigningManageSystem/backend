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
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	"bytes"
	"context"
	"fmt"
	"image"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"gitee.com/ivfzhou/gotools/v4"
	"gitee.com/ivfzhou/tus_client"
	"github.com/google/uuid"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/protocol"
)

// Create 注册应用
func Create(ctx context.Context, req *protocol.CreateReq) (err error) {
	// 校验
	if len(req.Name) <= 0 || req.Platform <= 0 {
		return errs.NewParamsErr(nil)
	}
	if !gotools.Contains([]uint8{model.TApp_Platform_Apple, model.TApp_Platform_Windows, model.TApp_Platform_Android},
		uint8(req.Platform)) {
		return errs.NewParamsErr(nil)
	}
	adminNames := gotools.DropSliceZero(gotools.DistinctSlice(req.Admins))
	memberNames := gotools.DropSliceZero(gotools.DistinctSlice(req.Members))
	var admins []*model.TUser
	if len(adminNames) > 0 {
		if err = conn.GetMySQLClient(ctx).Where("name_en in ?", adminNames).Find(&admins).Error; err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
		if len(adminNames) != len(admins) {
			return errs.NewParamsErrMsg("选择了不存在的用户")
		}
	}
	var members []*model.TUser
	if len(memberNames) > 0 {
		if err = conn.GetMySQLClient(ctx).Where("name_en in ?", memberNames).Find(&members).Error; err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
		if len(memberNames) != len(members) {
			return errs.NewParamsErrMsg("选择了不存在的用户")
		}
	}
	fileId := ""
	uid := ctxs.UserId(ctx)
	userName := ctxs.UserName(ctx)
	now := time.Now()
	if req.Logo != nil {
		// 校验
		var (
			logo     []byte
			fileName string
			valid    bool
		)
		if logo, fileName, valid, err = IsValidAppLogo(ctx, req.Logo); err != nil {
			return err
		}
		if !valid {
			return errs.NewParamsErrMsg("Logo 非法")
		}

		// 获取 fileId
		if fileId, err = GenerateId(ctx, IdScope_File); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				log.ErrorIf(ctx, ReclaimId(ctx, IdScope_File, fileId))
			}
		}()

		// 上传到 Tus
		var location string
		if location, err = conn.GetTusClient(ctx).MultipleUploadFromReader(ctx, bytes.NewReader(logo)); err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
		defer func() {
			if err != nil {
				_, ignoredErr := conn.GetTusClient(ctx).Delete(ctx, &tus_client.DeleteRequest{Location: location})
				log.ErrorIf(ctx, ignoredErr)
			}
		}()

		// 文件信息落库
		_md5, _sha1, _sha256 := util.CalcSum(logo)
		err = CreateDBFile(ctx, &model.TFile{
			FileId:     fileId,
			UserId:     uid,
			TusdId:     location,
			Name:       fileName,
			MD5:        _md5,
			SHA1:       _sha1,
			SHA256:     _sha256,
			Size:       len(logo),
			CreateTime: now,
		})
		if err != nil {
			return err
		}
	}

	// 新增应用表记录
	tapp := &model.TApp{
		AppId:      strings.ReplaceAll(uuid.NewString(), "-", ""),
		Name:       req.Name,
		UserId:     uid,
		Avatar:     fileId,
		Platform:   uint8(req.Platform),
		CreateTime: now,
		Status:     model.TApp_Status_OK,
	}
	if err = conn.GetMySQLClient(ctx).Create(tapp).Error; err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 新增事件表记录
	err = conn.GetMySQLClient(ctx).Create(&model.TEvent{
		Type:      model.TEvent_Type_CreateApp,
		OccurTime: now,
		UserId:    uid,
		AppId:     tapp.Id,
		Content:   fmt.Sprintf("用户%s创建应用%s / %s", userName, tapp.Name, tapp.AppId),
	}).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 新增用户角色表记录
	tuserRoles := make([]*model.TUserRole, 0, len(admins)+len(members)+1)
	tuserRoles = append(tuserRoles, &model.TUserRole{
		UserId: uid,
		AppId:  tapp.Id,
		Role:   model.TUserRole_Role_AppAdmin,
	})
	gotools.ForeachSlice(admins, func(e *model.TUser) {
		tuserRoles = append(tuserRoles, &model.TUserRole{
			UserId: e.Id,
			AppId:  tapp.Id,
			Role:   model.TUserRole_Role_AppAdmin,
		})
	})
	gotools.ForeachSlice(members, func(e *model.TUser) {
		tuserRoles = append(tuserRoles, &model.TUserRole{
			UserId: e.Id,
			AppId:  tapp.Id,
			Role:   model.TUserRole_Role_AppMember,
		})
	})
	if err = conn.GetMySQLClient(ctx).CreateInBatches(tuserRoles, len(tuserRoles)).Error; err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	return nil
}

// Update 更新应用
func Update(ctx context.Context, req *protocol.UpdateReq) (err error) {
	// 校验
	appId := ctxs.AppId(ctx)
	if len(req.Name) <= 0 || appId <= 0 {
		return errs.NewParamsErr(nil)
	}
	adminNames := gotools.DropSliceZero(gotools.DistinctSlice(req.Admins))
	memberNames := gotools.DropSliceZero(gotools.DistinctSlice(req.Members))
	var admins []*model.TUser
	if len(adminNames) > 0 {
		if err = conn.GetMySQLClient(ctx).Where("name_en in ?", adminNames).Find(&admins).Error; err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
		if len(adminNames) != len(admins) {
			return errs.NewParamsErrMsg("选择了不存在的用户")
		}
	}
	var members []*model.TUser
	if len(memberNames) > 0 {
		if err = conn.GetMySQLClient(ctx).Where("name_en in ?", memberNames).Find(&members).Error; err != nil {
			log.Error(ctx, err)
			return errs.NewSystemBusyErr(err)
		}
		if len(memberNames) != len(members) {
			return errs.NewParamsErrMsg("选择了不存在的用户")
		}
	}

	// 更新应用信息表记录
	var tapp model.TApp
	if err = conn.GetMySQLClient(ctx).Where("id = ?", appId).Find(&tapp).Error; err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	if tapp.Status != model.TApp_Status_OK {
		return errs.NewParamsErrMsg("应用信息不可更改")
	}
	err = conn.GetMySQLClient(ctx).Model(&model.TApp{}).Where("id = ?", tapp.Id).UpdateColumn("name", req.Name).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// TODO: 待办

	// 更新用户角色表记录
	if err = conn.GetMySQLClient(ctx).Where("app_id = ?", tapp.Id).Delete(&model.TUserRole{}).Error; err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	tuserRoles := make([]*model.TUserRole, 0, len(admins)+len(members)+1)
	tuserRoles = append(tuserRoles, &model.TUserRole{
		UserId: tapp.UserId,
		AppId:  tapp.Id,
		Role:   model.TUserRole_Role_AppAdmin,
	})
	gotools.ForeachSlice(admins, func(e *model.TUser) {
		tuserRoles = append(tuserRoles, &model.TUserRole{
			UserId: e.Id,
			AppId:  tapp.Id,
			Role:   model.TUserRole_Role_AppAdmin,
		})
	})
	gotools.ForeachSlice(members, func(e *model.TUser) {
		tuserRoles = append(tuserRoles, &model.TUserRole{
			UserId: e.Id,
			AppId:  tapp.Id,
			Role:   model.TUserRole_Role_AppMember,
		})
	})
	if err = conn.GetMySQLClient(ctx).CreateInBatches(tuserRoles, len(tuserRoles)).Error; err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 记录操作事件
	err = conn.GetMySQLClient(ctx).Create(&model.TEvent{
		Type:      model.TEvent_Type_UpdateApp,
		OccurTime: time.Now(),
		UserId:    ctxs.UserId(ctx),
		AppId:     tapp.Id,
		Content:   fmt.Sprintf("用户%s修改应用信息%s / %s", ctxs.UserName(ctx), tapp.Name, tapp.AppId),
	}).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	return nil
}

// Delete 注销应用
func Delete(ctx context.Context) error {
	// 校验
	appId := ctxs.AppId(ctx)
	if appId <= 0 {
		return errs.NewParamsErr(nil)
	}

	// 查库
	var tapp model.TApp
	err := conn.GetMySQLClient(ctx).Where("id = ?", appId).Find(&tapp).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	if tapp.Status != model.TApp_Status_OK {
		return errs.NewParamsErrMsg("不可更改应用信息")
	}

	// 更新应用表记录
	err = conn.GetMySQLClient(ctx).Model(&model.TApp{}).Where("id = ?", tapp.Id).
		UpdateColumn("status", model.TApp_Status_Locked).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 新增事件表记录
	err = CreateEvent(ctx, &model.TEvent{
		Type:      model.TEvent_Type_LockApp,
		OccurTime: time.Now(),
		UserId:    ctxs.UserId(ctx),
		AppId:     tapp.Id,
		Content:   fmt.Sprintf("用户%s注销应用 %s / %s", ctxs.UserName(ctx), tapp.Name, tapp.AppId),
	})
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// TODO: 待办

	return nil
}

// IsValidAppLogo 头像是否合规
func IsValidAppLogo(ctx context.Context, file *multipart.FileHeader) ([]byte, string, bool, error) {
	if file.Size <= 0 {
		return nil, "", false, nil
	}
	fileName := file.Filename
	fileObj, err := file.Open()
	if err != nil {
		log.Error(ctx, err)
		return nil, fileName, false, errs.NewSystemBusyErr(err)
	}
	defer util.CloseIO(ctx, fileObj)
	fileData, err := io.ReadAll(fileObj)
	if err != nil {
		log.Error(ctx, err)
		return nil, fileName, false, errs.NewSystemBusyErr(err)
	}
	fileExt := strings.ToLower(filepath.Ext(fileName))
	if fileExt == ".jpg" {
		fileExt = ".jpeg"
	}
	switch fileExt {
	case ".jpeg":
	case ".png":
	case ".gif":
	default:
		return nil, fileName, false, nil
	}
	_, imgFmt, err := image.DecodeConfig(bytes.NewReader(fileData))
	if err != nil {
		log.Warn(ctx, err)
		return nil, fileName, false, errs.NewParamsErrMsg("头像格式内容错误")
	}
	if !strings.EqualFold("."+imgFmt, fileExt) {
		return nil, fileName, false, nil
	}
	return fileData, fileName, true, nil
}
