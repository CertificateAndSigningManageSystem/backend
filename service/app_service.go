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
	"gorm.io/gorm"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/consts"
	"backend/protocol"
)

// App_Create 注册应用
func App_Create(ctx context.Context, req *protocol.App_CreateReq) (err error) {
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

// App_Update 更新应用
func App_Update(ctx context.Context, req *protocol.App_UpdateReq) (err error) {
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

// App_Delete 注销应用
func App_Delete(ctx context.Context) error {
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
		UpdateColumns(map[string]any{
			"status": model.TApp_Status_Locked,
			"name":   gorm.Expr("concat(name, ?)", "（已注销）"),
		}).Error
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

// App_ChangeLogo 修改图标
func App_ChangeLogo(ctx context.Context, req *protocol.App_ChangeLogoReq) error {
	// 校验
	if len(req.LogoId) != consts.FileIdLength {
		return errs.NewParamsErr(nil)
	}
	appId := ctxs.AppId(ctx)
	if appId <= 0 {
		return errs.NewParamsErr(nil)
	}
	tfile, err := QueryDBFileById(ctx, req.LogoId)
	if err != nil {
		return err
	}
	if tfile.Id <= 0 {
		return errs.NewParamsErr(nil)
	}
	if !IsValidPicExt(ctx, tfile.Name) {
		return errs.NewParamsErrMsg("图标格式非法")
	}
	// 校验应用状态
	var appStatus uint8
	err = conn.GetMySQLClient(ctx).Model(&model.TApp{}).Select("status").Where("id = ?", appId).Find(&appStatus).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}
	if appStatus != model.TApp_Status_OK {
		return errs.NewParamsErrMsg("应用信息不可更改")
	}

	// 更新库表
	err = conn.GetMySQLClient(ctx).Model(&model.TApp{}).Where("id = ?", appId).UpdateColumn("avatar", req.LogoId).Error
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	// 记录事件
	userId := ctxs.UserId(ctx)
	err = CreateEvent(ctx, &model.TEvent{
		Type:      model.TEvent_Type_UpdateApp,
		OccurTime: time.Now(),
		UserId:    userId,
		AppId:     appId,
		Content:   fmt.Sprintf("用户%d更新应用%d图标 %s", userId, appId, req.LogoId),
	})
	if err != nil {
		return err
	}

	return nil
}

// App_Info 获取应用信息
func App_Info(ctx context.Context) (*protocol.App_InfoRsp, error) {
	// 查库
	appId := ctxs.AppId(ctx)
	var tapp model.TApp
	err := conn.GetMySQLClient(ctx).Where("id = ?", appId).Find(&tapp).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	var admins []*model.TUser
	err = conn.GetMySQLClient(ctx).Where("id in (?)",
		conn.GetMySQLClient(ctx).Model(&model.TUserRole{}).Select("user_id").
			Where("app_id = ? and role = ?", tapp.Id, model.TUserRole_Role_AppAdmin)).
		Find(&admins).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}
	var members []*model.TUser
	err = conn.GetMySQLClient(ctx).Where("id in (?)",
		conn.GetMySQLClient(ctx).Model(&model.TUserRole{}).Select("user_id").
			Where("app_id = ? and role = ?", tapp.Id, model.TUserRole_Role_AppMember)).
		Find(&members).Error
	if err != nil {
		log.Error(ctx, err)
		return nil, errs.NewSystemBusyErr(err)
	}

	// 处理数据
	res := &protocol.App_InfoRsp{
		AppId:    tapp.AppId,
		Name:     tapp.Name,
		Avatar:   tapp.Avatar,
		Platform: int(tapp.Platform),
	}
	for _, v := range admins {
		res.Admins = append(res.Admins, &struct {
			NameEn string `json:"nameEn,omitempty"`
			NameZn string `json:"nameZh,omitempty"`
		}{
			NameEn: v.NameEn,
			NameZn: v.NameZh,
		})
	}
	for _, v := range members {
		res.Members = append(res.Members, &struct {
			NameEn string `json:"nameEn,omitempty"`
			NameZn string `json:"nameZh,omitempty"`
		}{
			NameEn: v.NameEn,
			NameZn: v.NameZh,
		})
	}

	return res, nil
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
