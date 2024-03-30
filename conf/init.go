/*
 * Copyright (c) 2023 ivfzhou
 * common is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package conf

import (
	"time"

	"github.com/go-ini/ini"
)

// Conf 配置
var Conf Data

// Data 配置
type Data struct {
	ServeAddr string `ini:"serveAddr"`
	TusServer string `ini:"tusServer"`
	Log       `ini:"log"`
	Redis     `ini:"redis"`
	MySQL     `ini:"mysql"`
	RabbitMQ  `ini:"rabbitmq"`
}

// Log 日志配置
type Log struct {
	LogDir   string        `ini:"logDir"`
	Module   string        `ini:"module"`
	MaxAge   time.Duration `ini:"maxAge"`
	Rotation time.Duration `ini:"rotation"`
	Debug    bool          `ini:"debug"`
}

// Redis Redis连接配置
type Redis struct {
	Addr   string `ini:"addr"`
	Passwd string `ini:"passwd"`
	DB     int    `ini:"db"`
}

// MySQL MySQL连接配置
type MySQL struct {
	User    string `ini:"user"`
	Passwd  string `ini:"passwd"`
	Host    string `ini:"host"`
	Port    string `ini:"port"`
	DB      string `ini:"db"`
	MaxIdea int    `ini:"maxIdea"`
	MaxOpen int    `ini:"maxOpen"`
}

// RabbitMQ RabbitMQ相关配置
type RabbitMQ struct {
	URI string `ini:"uri"`
}

// InitialConf 初始化配置
func InitialConf(file string) {
	if len(file) <= 0 {
		file = "config.ini"
	}
	data, err := ini.Load(file)
	if err != nil {
		panic(err)
	}
	err = data.StrictMapTo(&Conf)
	if err != nil {
		panic(err)
	}
}
