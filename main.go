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

package main

import (
	_ "backend/docs"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"

	"backend/conf"
	"backend/cron"
	"backend/route"
)

func init() {
	conf.InitialConf("config.ini")
	log.InitialLog(conf.Conf.Log.LogDir, conf.Conf.Log.Module, conf.Conf.Log.MaxAge, conf.Conf.Log.Rotation,
		conf.Conf.Log.Debug)
	ctx := ctxs.NewCtx("init")
	conn.InitialRedis(ctx, conf.Conf.Redis.Addr, conf.Conf.Redis.Passwd, conf.Conf.Redis.DB)
	conn.InitialMySQL(ctx, conf.Conf.MySQL.User, conf.Conf.MySQL.Passwd, conf.Conf.MySQL.Host, conf.Conf.MySQL.Port,
		conf.Conf.MySQL.DB, conf.Conf.MySQL.MaxIdea, conf.Conf.MySQL.MaxOpen)
	conn.InitialRabbitMQ(ctx, conf.Conf.RabbitMQ.URI)
	conn.InitialTusClient(ctx, conf.Conf.TusServer)
	cron.InitialCron(ctx)
	log.FatalIfError(ctx, conn.AutoMigrateAllTable(ctx))
}

func main() {
	ctx := ctxs.NewCtx("main")
	router := route.InitialRouter(ctx)
	log.Info(ctx, "start serve 启动服务")
	log.ErrorIf(ctx, router.Run(conf.Conf.ServeAddr))
	log.Warn(ctx, "exit serve 退出服务")
}
