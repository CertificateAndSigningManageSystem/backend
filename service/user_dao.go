package service

import (
	"context"

	"gitee.com/CertificateAndSigningManageSystem/common/model"
)

func GetUserInfoByID(ctx context.Context, id uint) (model.TUser, error) {

}

func HasUserAnyAuthorities(ctx context.Context, userID uint, authorities ... uint)(bool, error) {

}
