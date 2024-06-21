package main

import (
	"github.com/a2234-liang/goUtils/utils"
	"testing"
)

func TestUtils(t *testing.T) {
	//utils.InitBleve(utils.WithTotal(1))
	//utils.InitBadger(utils.WithTotal(1),utils.WithCacheFolder("cache1"))
	/*var v1 []map[string]string
	for i := 0; i < 100; i++ {
		v1 = append(v1, map[string]string{
			"key":   fmt.Sprintf("key:%v", i),
			"value": fmt.Sprintf("value:%v", i),
		})
	}
	e := utils.BadgerBatch(v1)
	if e != nil {
		fmt.Println("err:", e)
	}*/
	//m, total, e := utils.BadgerScan("key:")
	//fmt.Println("m,total,e", m, total, e)
	//for i := range 10 {
	//	fmt.Println(10 - i)
	//}
	//utils.InitRedis(utils.WithDSN("redis://default:taiya168@168.com@127.0.0.1:6379/0?protocol=3"))
	//utils.InitGormDB(utils.WithDSN("suwen:suwen@36D@tcp(127.0.0.1:3308)/project02?charset=utf8mb4&parseTime=True&loc=Local"))
	utils.InitGormDB(utils.WithDSN("postgres://suwen:suwen@36D@127.0.0.1:5432/goadmin?Timezone=Asia/Shanghai"), utils.WithDbType("postgres"))
}
