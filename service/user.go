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
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"gitee.com/ivfzhou/gotools/v4"
	"gitee.com/ivfzhou/tus_client"
	"github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/protocol"
)

const MaxLoginFailTimes = 3

// SessionInfo 会话信息
type SessionInfo struct {
	UserId    uint   `json:"userId"`
	LoginIP   string `json:"loginIP"`
	UserAgent string `json:"userAgent"`
}

// Register 注册
func Register(ctx context.Context, req *protocol.RegisterReq) (session string, err error) {
	// 校验
	if !util.IsAllHanCharacters(req.NameZh) {
		return "", errs.NewParamsErrMsg("中文名应全是数字")
	}
	if len(req.NameZh) > 32 {
		return "", errs.NewParamsErrMsg("中文名过长")
	}
	if !IsValidUserNameEn(ctx, req.NameEn) {
		return "", errs.NewParamsErrMsg("英文名应全是字母且不超过16个字符")
	}
	if !IsValidPassword(ctx, req.Password) {
		return "", errs.NewParamsErrMsg("密码须是字母数字组合，至少包含三种字符类型，长度不小于八位")
	}
	if req.Avatar.Size <= 0 {
		return "", errs.NewParamsErrMsg("请上传头像")
	}
	fileName := req.Avatar.Filename
	file, err := req.Avatar.Open()
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}
	defer util.CloseIO(ctx, file)
	fileData, err := io.ReadAll(file)
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
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
		return "", errs.NewParamsErrMsg("头像格式不支持")
	}
	_, imgFmt, err := image.DecodeConfig(bytes.NewReader(fileData))
	if err != nil {
		log.Warn(ctx, err)
		return "", errs.NewParamsErrMsg("头像格式内容错误")
	}
	if !strings.EqualFold("."+imgFmt, fileExt) {
		return "", errs.NewParamsErrMsg("头像格式名错误")
	}

	// 生成头像文件Id
	fileId, err := GenerateId(ctx, IdScope_File)
	if err != nil {
		log.Error(ctx, err)
		return "", err
	}
	defer func() {
		if err != nil {
			log.ErrorIf(ctx, ReclaimId(ctx, IdScope_File, fileId))
		}
	}()

	// 组装数据库实体
	now := time.Now()
	tuser := &model.TUser{
		NameEn:        req.NameEn,
		NameZh:        req.NameZh,
		PasswdSalt:    gotools.RandomCharsCaseInsensitive(128),
		RegisterTime:  now,
		LastLoginTime: now,
		Status:        model.TUser_Status_OK,
		Avatar:        fileId,
	}

	// 计算密码散列值
	sum := md5.Sum([]byte(req.Password + tuser.PasswdSalt))
	tuser.PasswdDigest = hex.EncodeToString(sum[:])

	// 用户信息落库
	if err = conn.GetMySQLClient(ctx).Create(tuser).Error; err != nil {
		var e *mysql.MySQLError
		if errors.As(err, &e) && e.Number == 1062 {
			return "", errs.NewParamsErrMsg("该用户已注册")
		}
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}

	// 将头像上传到Tusd
	location, err := conn.GetTusClient(ctx).MultipleUploadFromReader(ctx, bytes.NewReader(fileData))
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}
	defer func() {
		if err != nil {
			_, err := conn.GetTusClient(ctx).Delete(ctx, &tus_client.DeleteRequest{
				Location: location,
			})
			log.ErrorIf(ctx, err)
		}
	}()

	// 文件信息落库
	_md5, _sha1, _sha256 := util.CalcSum(fileData)
	tfile := &model.TFile{
		FileId:     fileId,
		UserId:     tuser.Id,
		TusdId:     location,
		Name:       req.Avatar.Filename,
		Ext:        fileExt,
		MD5:        _md5,
		SHA1:       _sha1,
		SHA256:     _sha256,
		Size:       int(req.Avatar.Size),
		CreateTime: now,
	}
	if err = CreateFile(ctx, tfile); err != nil {
		log.Error(ctx, err)
		return "", err
	}

	// 事件信息落库
	tevent := &model.TEvent{
		Type:      model.TEvent_Type_Register,
		OccurTime: now,
		UserId:    tuser.Id,
		Content:   fmt.Sprintf("用户%s执行注册", tuser.NameEn),
	}
	if err = CreateEvent(ctx, tevent); err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}

	// 生成登陆会话信息
	session, sessionVal := createUserSession(ctx, tuser.Id, ctxs.RequestIP(ctx), req.UserAgent)
	err = conn.GetRedisClient(ctx).Set(ctx,
		fmt.Sprintf(conn.CacheKey_UserSessionFmt, tuser.NameEn, session), sessionVal, time.Hour*24).Err()
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}

	return session, nil
}

// Login 登陆
func Login(ctx context.Context, req *protocol.LoginReq) (session string, err error) {
	// 校验
	if len(req.Name) <= 0 {
		return "", errs.NewParamsErrMsg("姓名不能为空")
	}
	if len(req.Password) <= 0 {
		return "", errs.NewParamsErrMsg("密码不能为空")
	}
	if !IsValidUserNameEn(ctx, req.Name) {
		return "", errs.NewParamsErr(nil)
	}
	if !IsValidPassword(ctx, req.Password) {
		return "", errs.NewParamsErr(nil)
	}

	// 获取登陆失败次数
	loginFailTimes, err := conn.GetRedisClient(ctx).Get(ctx, fmt.Sprintf(conn.CacheKey_UserLoginFailTimesFmt, req.Name)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}
	if loginFailTimes >= MaxLoginFailTimes {
		return "", &errs.Error{
			HTTPStatus: http.StatusForbidden,
			Msg:        "今日限制登陆",
		}
	}

	// 查库
	var tuser model.TUser
	err = conn.GetMySQLClient(ctx).Where("name_en = ?", req.Name).Find(&tuser).Error
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}
	if tuser.Id <= 0 {
		return "", errs.NewParamsErrMsg("用户不存在")
	}
	if tuser.Status != model.TUser_Status_OK {
		return "", errs.NewParamsErrMsg("禁止登陆")
	}

	// 计算密码散列
	md5Sum := md5.Sum([]byte(req.Password + tuser.PasswdSalt))
	if tuser.PasswdDigest != hex.EncodeToString(md5Sum[:]) {
		// 记忆失败次数
		err = rememberLoginFailTimes(ctx, req.Name)
		if err != nil {
			log.Error(ctx, err)
			return "", errs.NewSystemBusyErr(err)
		}
		return "", errs.NewParamsErrMsg("密码错误")
	}

	// 记录事件
	now := time.Now()
	tevent := &model.TEvent{
		Type:      model.TEvent_Type_Login,
		OccurTime: now,
		UserId:    tuser.Id,
		Content:   fmt.Sprintf("用户%s登陆%s", tuser.NameEn, ctxs.RequestIP(ctx)),
	}
	if err = CreateEvent(ctx, tevent); err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}

	// 更新最后登陆时间
	err = conn.GetMySQLClient(ctx).Model(&model.TUser{}).Where("id = ?", tuser.Id).UpdateColumn("last_login_time", now).Error
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}

	// TODO: 多端登陆，踢出其他登陆会话。加锁，维度用户，redis 事务。

	// 记录会话
	session, sessionVal := createUserSession(ctx, tuser.Id, ctxs.RequestIP(ctx), req.UserAgent)
	err = conn.GetRedisClient(ctx).SetEx(ctx,
		fmt.Sprintf(conn.CacheKey_UserSessionFmt, tuser.NameEn, session), sessionVal, time.Hour*24).Err()
	if err != nil {
		log.Error(ctx, err)
		return "", errs.NewSystemBusyErr(err)
	}

	// 清除登陆失败次数
	err = conn.GetRedisClient(ctx).Del(ctx, fmt.Sprintf(conn.CacheKey_UserLoginFailTimesFmt, req.Name)).Err()
	if err != nil {
		log.Error(ctx, err)
	}

	return session, nil
}

// Logout 登出
func Logout(ctx context.Context, user, session string) error {
	// 删除会话缓存
	err := conn.GetRedisClient(ctx).Del(ctx, fmt.Sprintf(conn.CacheKey_UserSessionFmt, user, session)).Err()
	if err != nil {
		log.Error(ctx, err)
		return errs.NewSystemBusyErr(err)
	}

	return nil
}

// IsValidPassword 密码字符是否合法
func IsValidPassword(_ context.Context, passwd string) bool {
	hasNum := false
	hasUpper := false
	hasLower := false
	for _, v := range []rune(passwd) {
		if unicode.IsUpper(v) {
			hasUpper = true
		} else if unicode.IsLower(v) {
			hasLower = true
		} else if unicode.IsDigit(v) {
			hasNum = true
		} else {
			return false
		}
	}
	if !(hasNum && hasUpper && hasLower && len(passwd) >= 8) {
		return false
	}
	return true
}

// IsValidUserNameEn 英文名字符是否合法
func IsValidUserNameEn(_ context.Context, nameEn string) bool {
	if !util.IsAllLetterCharacters(nameEn) {
		return false
	}
	if len(nameEn) > 16 {
		return false
	}
	return true
}

// 创建用户会话
func createUserSession(_ context.Context, uid uint, ip, userAgent string) (session, sessionVal string) {
	session = gotools.RandomCharsCaseInsensitive(128)
	bs, _ := json.Marshal(&SessionInfo{
		UserId:    uid,
		LoginIP:   ip,
		UserAgent: userAgent,
	})
	sessionVal = string(bs)
	return
}

// 记忆登陆失败次数
func rememberLoginFailTimes(ctx context.Context, user string) error {
	err := conn.GetRedisClient(ctx).Incr(ctx, fmt.Sprintf(conn.CacheKey_UserLoginFailTimesFmt, user)).Err()
	if err != nil {
		log.Error(ctx, err)
		return err
	}
	now := time.Now()
	next := now.AddDate(0, 0, 1)
	sub := time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, time.Local).Sub(now)
	err = conn.GetRedisClient(ctx).Expire(ctx, fmt.Sprintf(conn.CacheKey_UserLoginFailTimesFmt, user), sub).Err()
	if err != nil {
		log.Error(ctx, err)
		return err
	}
	return nil
}
