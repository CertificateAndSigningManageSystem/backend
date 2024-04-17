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

	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitee.com/CertificateAndSigningManageSystem/common/conn"
	"gitee.com/CertificateAndSigningManageSystem/common/ctxs"
	"gitee.com/CertificateAndSigningManageSystem/common/log"

	"backend/conf"
	"backend/cron"
	"backend/filter"
	"backend/route"
)

func init() {
	var err error
	time.Local, err = time.LoadLocation("Asia/Shanghai")
	if err != nil {
		panic(err)
	}

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
	ctx, cancel := context.WithCancel(ctxs.NewCtx("main"))
	router := route.InitialRouter(ctx)
	log.Info(ctx, "start serve")
	go func() {
		router.Use(filter.ExitFilter(ctx))
		log.ErrorIf(ctx, router.Run(conf.Conf.ServeAddr))
	}()

	// 监听关闭信号
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV, syscall.SIGUSR2)
	<-ch
	log.Warn(ctx, "exiting server")
	cancel()
	time.Sleep(3 * time.Second)
	cron.CloseCron(ctx)
	conn.CloseRabbitMQClient(ctx)
	conn.CloseMysqlClient(ctx)
	conn.CloseRedisClient(ctx)
	log.Info(ctx, "server exit")
}
