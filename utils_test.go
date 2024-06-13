package main

import (
	"fmt"
	"github.com/a2234-liang/goUtils/utils"
	"testing"
)

func TestUtils(t *testing.T) {
	//utils.InitBleve(utils.WithTotal(1))
	utils.InitBadger(utils.WithTotal(1))
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
	for i := range 10 {
		fmt.Println(10 - i)
	}

}
