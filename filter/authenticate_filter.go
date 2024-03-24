package filter

import (
	"backend/service"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/model"
	"gitee.com/CertificateAndSigningManageSystem/common/util"
	double_array_trie "gitee.com/ivfzhou/double-array-trie"
	"github.com/gin-gonic/gin"
	"net/http"
)

var (
	authInfoDat *double_array_trie.Dat
	authInfoArr [][]uint
)

// InitialAuthenticateFilter 初始化鉴权函数
func InitialAuthenticateFilter(pathToAuthorities map[string][]uint) {
	paths := make([]string, 0, len(pathToAuthorities))
	authInfoArr = make([][]uint, 0, len(pathToAuthorities))
	for path, authorities := range pathToAuthorities {
		paths = append(paths, path)
		authInfoArr = append(authInfoArr, authorities)
	}
	authInfoDat = double_array_trie.New(paths)
}

// AuthenticateFilter 鉴权函数
func AuthenticateFilter(c *gin.Context) {
	ctx := c.Request.Context()
	path := c.Request.URL.Path
	userID := ctxs.UserID(ctx)
	authID := ctxs.APIAuthID(ctx)

	// 如果userID合法则校验权限和状态
	if userID > 0 {
		userInfo, err := service.GetUserInfoByID(ctx, userID)
		if err != nil {
			c.Abort()
			util.Fail(c, http.StatusInternalServerError, "system busy 系统繁忙")
			return
		}
		// 用户不存在或者用户状态不正常，则限制请求
		if userInfo.ID <= 0 || userInfo.Status != model.TUser_Status_OK {
			util.Fail(c, http.StatusForbidden, "request restricted 请求受限")
			return
		}
		// 获取需要的权限项
		index := authInfoDat.MatchesIndex(path)
		// 不存在说明无需权限项，则放行
		if index < 0 {
			return
		}
		// 检索数据库判断用户是否有权限
		authorities := authInfoArr[index]
		has, err := service.HasUserAnyAuthorities(ctx, userID, authorities...)
		if err != nil {
			c.Abort()
			util.Fail(c, http.StatusInternalServerError, "system busy 系统繁忙")
			return
		}
		// 无权，限制请求
		if !has {
			c.Abort()
			util.Fail(c, http.StatusForbidden, "request restricted 请求受限")
			return
		}
	}

	// 如果authID合法则校验权限和其应用状态
	if authID > 0 {

	}
}
