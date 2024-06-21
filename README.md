# goUtils

1、初始化redis
utils.InitRedis(utils.WithDSN("redis://default:taiya168@168.com@127.0.0.1:6379/0?protocol=3"))
使用
utils.Rdb
2、初始化缓存数据库
utils.InitBadger(utils.WithTotal(1),utils.WithCacheFolder("cache1"))
使用
utils.CacheDb[index]
3、初始化搜索引擎
utils.InitBleve(utils.WithTotal(1),utils.WithCacheFolder("cache2"))
使用
utils.Bleve[index]
4、初始化mysql/pgsql数据库
utils.InitGormDB(utils.WithDSN("suwen:suwen@36D@tcp(127.0.0.1:3308)/project02?charset=utf8mb4&parseTime=True&loc=Local"))
utils.InitGormDB(utils.WithDSN("postgres://suwen:suwen@36D@127.0.0.1:5432/goadmin?Timezone=Asia/Shanghai"), utils.WithDbType("postgres"))
