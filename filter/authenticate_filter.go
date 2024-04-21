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

package filter

import (
	double_array_trie "gitee.com/ivfzhou/double-array-trie"
	"github.com/gin-gonic/gin"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/errs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"

	"backend/service"
)

var (
	authInfoDat       *double_array_trie.Dat
	authInfoArr       [][]uint
	pathToAuthorities = make(map[string][]uint)
)

// InitialPathAuthoritiesDAT 初始化鉴权函数
func InitialPathAuthoritiesDAT() {
	paths := make([]string, 0, len(pathToAuthorities))
	authInfoArr = make([][]uint, 0, len(pathToAuthorities))
	for path, authorities := range pathToAuthorities {
		paths = append(paths, path)
		authInfoArr = append(authInfoArr, authorities)
	}
	authInfoDat = double_array_trie.New(paths)
}

// AddPathAuthorities 添加请求权限
func AddPathAuthorities(path string, auths []uint) {
	pathToAuthorities[path] = auths
}

// AuthenticateFilter 鉴权函数
func AuthenticateFilter(c *gin.Context) {
	ctx := c.Request.Context()
	path := c.Request.URL.Path
	userId := ctxs.UserId(ctx)
	authId := ctxs.APIAuthId(ctx)

	// 如果userId合法则校验权限和状态
	if userId > 0 {
		// 获取 app 信息
		appId := c.Param("appId")
		var tapp model.TApp
		err := conn.GetMySQLClient(ctx).Where("app_id = ?", appId).Find(&tapp).Error
		if err != nil {
			c.Abort()
			log.Error(ctx, err)
			util.FailByErr(c, errs.NewSystemBusyErr(err))
			return
		}

		// 获取需要的权限项
		index := authInfoDat.MatchesIndex(path[:len(path)-len(appId)-1])
		// 需要权限
		if index >= 0 {
			// 检索数据库判断用户是否有权限
			authorities := authInfoArr[index]
			has, err := service.HasUserAnyAuthorities(ctx, userId, tapp.Id, authorities...)
			if err != nil {
				c.Abort()
				util.FailByErr(c, errs.NewSystemBusyErr(err))
				return
			}
			// 无权，限制请求
			if !has {
				c.Abort()
				util.FailByErr(c, errs.ErrNoAuth)
				return
			}
		}

		ctx = ctxs.WithAppId(ctx, tapp.Id)
		c.Request = c.Request.WithContext(ctx)
	}

	// 如果authId合法则校验权限和其应用状态
	if authId > 0 {
		// 获取需要的权限项
		index := authInfoDat.MatchesIndex(path)
		// 需要权限
		if index >= 0 {
			// 检索数据库判断用户是否有权限
			authorities := authInfoArr[index]
			has, err := service.HasAuthAnyAuthorities(ctx, authId, authorities...)
			if err != nil {
				c.Abort()
				util.FailByErr(c, errs.NewSystemBusyErr(err))
				return
			}
			// 无权，限制请求
			if !has {
				c.Abort()
				util.FailByErr(c, errs.ErrNoAuth)
				return
			}
		}
	}

	c.Next()
}
