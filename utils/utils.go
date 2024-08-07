package utils

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/GUAIK-ORG/go-snowflake/snowflake"
	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/document"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/dgraph-io/badger/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

var (
	Db      *gorm.DB
	Rdb     *redis.Client
	Casbin  *casbin.Enforcer
	Bleve   []bleve.Index
	CacheDb []*badger.DB
)

// option模式
type options struct {
	total        int
	index        int
	ttl          int
	page         int
	pageSize     int
	field        string
	multikeyword []string
	returnFields []string
	sortFields   []string
	jwtSecureKey string
	cacheFolder  string
	aes128Key    string
	aes128Iv     string
	publicKey    string
	privateKey   string
	dsn          string
	dbType       string
	idleConns    int
	maxConns     int
	maxLifeTime  int
	noLogs       bool
}
type Option func(options *options)

func WithNoLogs(noLogs bool) Option {
	return func(options *options) {
		options.noLogs = noLogs
	}
}
func WithDbType(dbtype string) Option {
	return func(options *options) {
		options.dbType = dbtype
	}
}
func WithIdleConns(idleConns int) Option {
	return func(options *options) {
		options.idleConns = idleConns
	}
}
func WithmaxConns(maxConns int) Option {
	return func(options *options) {
		options.maxConns = maxConns
	}
}
func WithMaxLifeTime(maxLifeTime int) Option {
	return func(options *options) {
		options.maxLifeTime = maxLifeTime
	}
}
func WithDSN(dsn string) Option {
	return func(options *options) {
		options.dsn = dsn
	}
}
func WithTotal(total int) Option {
	return func(options *options) {
		options.total = total
	}
}
func WithIndex(index int) Option {
	return func(o *options) {
		if index-1 >= 0 {
			index--
		} else {
			index = 0
		}
		o.index = index
	}
}
func WithField(field string) Option {
	return func(o *options) {
		o.field = field
	}
}
func WithPage(page int) Option {
	return func(options *options) {
		options.page = page
	}
}
func WithPageSize(pagesize int) Option {
	return func(options *options) {
		options.pageSize = pagesize
	}
}
func WithSortField(field string) Option {
	return func(options *options) {
		options.sortFields = append(options.sortFields, field)
	}
}
func WithTtl(ttl int) Option {
	return func(o *options) {
		o.ttl = ttl
	}
}
func WithKeyword(keyword string) Option {
	return func(o *options) {
		o.multikeyword = append(o.multikeyword, keyword)
	}
}
func WithJwtSecureKey(jwtSecureKey string) Option {
	return func(o *options) {
		o.jwtSecureKey = jwtSecureKey
	}
}
func WithCacheFolder(folderName string) Option {
	return func(o *options) {
		o.cacheFolder = folderName
	}
}
func WithReturnField(field string) Option {
	return func(o *options) {
		o.returnFields = append(o.returnFields, field)
	}
}
func WithAesKeyAndIv(key, iv string) Option {
	return func(o *options) {
		o.aes128Key = key
		o.aes128Iv = iv
	}
}
func WithPubicPrivateKey(publicKey, privateKey string) Option {
	return func(o *options) {
		o.publicKey = publicKey
		o.privateKey = privateKey
	}
}

// 初始化指定目录
func InitDirectory(npath ...string) (string, bool) {
	path, _ := os.Getwd()
	slices.Insert(npath, 0, path)
	path = filepath.Join(npath...)
	if _, e := os.Stat(path); e != nil {
		_ = os.MkdirAll(path, 0755)
		return path, true
	}
	return path, false
}

// 初始化搜索引擎
func InitBleve(opts ...Option) error {
	var (
		op = options{total: 1, cacheFolder: "cache"}
	)
	for _, option := range opts {
		option(&op)
	}
	for i := 0; i < op.total; i++ {
		if dirPath, b := InitDirectory(op.cacheFolder, fmt.Sprintf("bleve%v", i)); b {
			indexMapping := bleve.NewIndexMapping()
			if _bleve, e := bleve.New(dirPath, indexMapping); e != nil {
				slog.Error("InitBleve", fmt.Sprintf("index=%v", i+1), e.Error())
			} else {
				Bleve = append(Bleve, _bleve)
			}
		} else {
			if _bleve, e := bleve.Open(dirPath); e != nil {
				slog.Error("InitBleve", fmt.Sprintf("index=%v", i+1), e.Error())
			} else {
				Bleve = append(Bleve, _bleve)
			}
		}
		if !op.noLogs {
			slog.Info("搜索引擎数据库初始化完成", "索引号", i+1)
		}
	}
	return nil
}

// 初始化kV缓存
func InitBadger(opts ...Option) {
	var (
		op = options{total: 1, cacheFolder: "cache"}
	)
	for _, option := range opts {
		option(&op)
	}
	for i := 0; i < op.total; i++ {
		dirPath, _ := InitDirectory(op.cacheFolder, fmt.Sprintf("badger%v", i))
		badgerOptions := badger.DefaultOptions(dirPath)
		_cachedb, err := badger.Open(badgerOptions)
		if err != nil {
			slog.Error("InitCache", "错误", err)
			os.Exit(1)
		}
		CacheDb = append(CacheDb, _cachedb)
		if !op.noLogs {
			slog.Info("缓存数据库初始化完成", "索引号", i+1)
		}
	}
}

// 初始化mysql/postgres数据库
func InitGormDB(opts ...Option) {
	var (
		op        = options{idleConns: 5, maxConns: 100, maxLifeTime: 8, dbType: "mariadb"}
		err       error
		dialector gorm.Dialector
	)
	for _, option := range opts {
		option(&op)
	}
	switch op.dbType {
	case "postgres":
		dialector = postgres.Open(op.dsn)
	case "mariadb":
		fallthrough
	default:
		dialector = mysql.Open(op.dsn)
	}
	if Db, err = gorm.Open(dialector, &gorm.Config{
		//dsn=suwen:suwen@36D@tcp(127.0.0.1:3308)/project02?charset=utf8mb4&parseTime=True&loc=Local
		//dsn=postgres://suwen:suwen@36D@127.0.0.1:5432/goadmin?Timezone=Asia/Shanghai
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	}); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	sqlDB, _ := Db.DB()
	sqlDB.SetMaxIdleConns(op.idleConns)
	sqlDB.SetMaxOpenConns(op.maxConns)
	sqlDB.SetConnMaxLifetime(time.Hour * time.Duration(op.maxLifeTime))
	if !op.noLogs {
		slog.Info("数据库初始化完成", "类型", op.dbType)
	}
}

// 初始化redis数据库
func InitRedis(opts ...Option) {
	//url := "redis://user:password@localhost:6379/0?protocol=3"
	var (
		op = options{dsn: "redis://default:@127.0.0.1:6379/0?protocol=3"}
	)
	for _, option := range opts {
		option(&op)
	}
	redisOpts, err := redis.ParseURL(op.dsn)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	Rdb = redis.NewClient(redisOpts)
	if _, err := Rdb.Ping(context.Background()).Result(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	} else {
		if !op.noLogs {
			slog.Info("数据库Redis初始化完成")
		}
	}

}

// 权限控制初始化
func InitCasbin(csvfile string, sub any) {
	var e error
	m, e := model.NewModelFromString(fmt.Sprintf(`
		[request_definition]
		r = sub, obj, act 
		[policy_definition]
		p = sub, obj, act
		[policy_effect]
		e = some(where (p.eft == allow))
		[role_definition]
		g = _, _
		[matchers]
		m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*") || r.sub == "%v"
	`, sub))
	p := fileadapter.NewAdapter(csvfile)
	Casbin, e = casbin.NewEnforcer(m, p)
	if e != nil {
		slog.Error("权限配置出错", "错误", e.Error())
	} else {
		slog.Info("权限加载完成", "csv", csvfile)
	}
}

// sha1加密
func SHA1(str string) string {
	sha1v := sha1.New()
	sha1v.Write([]byte(str))
	str = hex.EncodeToString(sha1v.Sum(nil))
	return str
}

// sha256加密
func SHA256(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// md5加密
func MD5(str string, is16 bool) string {
	hash := md5.New()
	hash.Write([]byte(str))
	s := hex.EncodeToString(hash.Sum(nil))
	if is16 {
		return s[8:24] //16位
	} else {
		return s
	}
}

// 创建JWT加密字串
func JwtCreate(data map[string]any, opts ...Option) (string, error) {
	var (
		jmap = make(jwt.MapClaims, 0)
		op   = options{jwtSecureKey: "7c4a8d09ca3762af61e59520943dc26494f8941b"}
	)
	for k, v := range data {
		jmap[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jmap)
	for _, option := range opts {
		option(&op)
	}
	return token.SignedString([]byte(op.jwtSecureKey))
}

// 检测JWT加密字串
func JwtValidate(tokenString string, opts ...Option) (any, error) {
	var (
		op = options{jwtSecureKey: "7c4a8d09ca3762af61e59520943dc26494f8941b"}
	)
	for _, option := range opts {
		option(&op)
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(op.jwtSecureKey), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	} else {
		return nil, err
	}
}

// 生成雪花订单号
func GetSnowflakeOrderNo() int64 {
	if s, e := snowflake.NewSnowflake(1, 1); e != nil {
		slog.Error("", e.Error())
		return 0
	} else {
		return s.NextVal()
	}
}

// 关闭所有连接
func CloseAllDbs() {
	for k, v := range Bleve {
		if e := v.Close(); e != nil {
			slog.Error("", "错误", e.Error())
		} else {
			slog.Info("", "Bleve关闭成功，序号", (k + 1))
		}
	}
	for k, v := range CacheDb {
		if e := v.Close(); e != nil {
			slog.Error("", "错误", e.Error())
		} else {
			slog.Info("", "CacheDb关闭成功，序号", (k + 1))
		}
	}
}

// 搜索引擎搜索指定关键字
func BleveSearch(s string, opts ...Option) ([]map[string]any, int64, error) {
	var (
		m       []map[string]any
		total   int64
		sResult *bleve.SearchResult
		e       error
		op      = options{field: "Body", returnFields: []string{"Body"}, index: 0, sortFields: []string{}, page: 1, pageSize: 10}
	)
	for _, option := range opts {
		option(&op)
	}
	op.multikeyword = append(op.multikeyword, s)
	if op.index+1 > len(Bleve) {
		return nil, 0, fmt.Errorf("引擎索引过界了")
	}
	boolQuery := bleve.NewBooleanQuery()
	for _, v := range op.multikeyword {
		query := bleve.NewMatchPhraseQuery(v)
		query.SetField(op.field)
		query.SetBoost(10)
		boolQuery.AddMust(query)
	}
	//query := bleve.NewMatchQuery(s)
	//query.SetField("body")
	//query := bleve.NewQueryStringQuery(s)
	//query := bleve.NewMatchPhraseQuery(s)
	//query.SetField(op.field)
	//query.SetBoost(10)
	var searchRequest *bleve.SearchRequest
	searchRequest = bleve.NewSearchRequestOptions(boolQuery, op.pageSize, (op.page-1)*op.pageSize, false)
	if len(op.sortFields) > 0 {
		searchRequest.SortBy(op.sortFields)
	}
	//searchRequest.Highlight = bleve.NewHighlight()
	sResult, e = Bleve[op.index].Search(searchRequest)
	if e != nil {
		return nil, 0, e
	}
	for _, v := range sResult.Hits {
		if doc, e := Bleve[op.index].Document(v.ID); e != nil {
			slog.Error("", "文档ID错误", e.Error())
		} else {
			m0 := map[string]any{}
			for _, v1 := range doc.(*document.Document).Fields {
				m0["id"] = v.ID
				if slices.Contains(op.returnFields, strings.ToLower(v1.Name())) {
					m0[strings.ToLower(v1.Name())] = string(v1.Value())
				}
			}
			m = append(m, m0)
		}
	}
	total = int64(sResult.Total)
	return m, total, nil
}

// 内容加入搜索引擎
func BleveIndex(id string, data map[string]any, opts ...Option) error {
	var (
		op = options{}
	)
	for _, option := range opts {
		option(&op)
	}
	if op.index+1 > len(Bleve) {
		return fmt.Errorf("引擎索引过界了")
	}
	if e := Bleve[op.index].Index(id, data); e != nil {
		slog.Error("", "错误", e.Error())
		return e
	} else {
		if !op.noLogs {
			slog.Info("加入搜索引擎成功", "id", id)
		}
		return nil
	}
}

// 删除搜索引擎中指定文档
func BleveRemove(id string, opts ...Option) error {
	var (
		op = options{}
	)
	for _, option := range opts {
		option(&op)
	}
	if op.index+1 > len(Bleve) {
		return fmt.Errorf("引擎索引过界了")
	}
	e := Bleve[op.index].Delete(id)
	return e
}

// 根据id得到搜索引擎中文档内容
func BleveDocument(id string, opts ...Option) (map[string]any, error) {
	var (
		op = options{}
		m  = make(map[string]any)
	)
	for _, option := range opts {
		option(&op)
	}
	if op.index+1 > len(Bleve) {
		return nil, fmt.Errorf("引擎索引过界了")
	}
	if doc, e := Bleve[op.index].Document(id); e != nil {
		slog.Error("", "文档ID错误", e.Error())
		return nil, e
	} else {
		m["nid"] = id
		for _, v1 := range doc.(*document.Document).Fields {
			m[strings.ToLower(v1.Name())] = string(v1.Value())
		}
		return m, nil
	}
}

// 搜索引擎文档总数
func BleveDocCount(opt ...Option) (uint64, error) {
	var (
		op = options{}
	)
	for _, option := range opt {
		option(&op)
	}
	if op.index+1 > len(Bleve) {
		return 0, fmt.Errorf("引擎索引过界了")
	}
	return Bleve[op.index].DocCount()
}

// 设置缓存key和值以及时效
func BadgerSet(key string, data any, opts ...Option) error {
	var (
		op = options{index: 0}
	)
	for _, option := range opts {
		option(&op)
	}
	e := CacheDb[op.index].Update(func(txn *badger.Txn) error {
		b, _ := json.Marshal(data)
		ev := badger.NewEntry([]byte(key), b)
		if op.ttl > 0 {
			ev.WithTTL(time.Second * time.Duration(op.ttl))
		}
		if e := txn.SetEntry(ev); e != nil {
			slog.Error("BadgerSet", "错误", e.Error())
			return e
		}
		if !op.noLogs {
			slog.Info("BadgerSet", "写入缓存", key)
		}
		return nil
	})
	return e
}

// 根据key取缓存
func BadgerGet(key string, opts ...Option) (any, error) {
	var (
		op = options{index: 0}
		b  []byte
	)
	for _, option := range opts {
		option(&op)
	}
	e := CacheDb[op.index].View(func(txn *badger.Txn) error {
		items, e := txn.Get([]byte(key))
		if e != nil {
			return fmt.Errorf(e.Error())
		}
		e = items.Value(func(val []byte) error {
			b = append(b, val...)
			return nil
		})
		return e
	})
	if e != nil {
		return nil, e
	} else {
		var m any
		_ = json.Unmarshal(b, &m)
		return m, nil
	}
}

// 删除指定key的缓存
func BadgerRemove(key string, opts ...Option) error {
	var (
		op = options{index: 0}
	)
	for _, option := range opts {
		option(&op)
	}
	e := CacheDb[op.index].Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
	return e
}

// 判断指定key缓存是否存在
func BadgerExists(key string, opts ...Option) bool {
	var (
		op = options{index: 0}
	)
	for _, option := range opts {
		option(&op)
	}
	e := CacheDb[op.index].View(func(txn *badger.Txn) error {
		_, e := txn.Get([]byte(key))
		return e
	})
	return e == nil
}

// 批处理新增数据
func BadgerBatch(dats []map[string]string, opts ...Option) error {
	var (
		op = options{index: 0}
	)
	for _, option := range opts {
		option(&op)
	}
	txn := CacheDb[op.index].NewTransaction(true)
	defer txn.Discard()
	for i, v := range dats {
		if value, o := v["key"]; o {
			_ = txn.Set([]byte(value), []byte(v["value"]))
		}

		if i%5000 == 0 {
			_ = txn.Commit()
			txn = CacheDb[op.index].NewTransaction(true)
		}
	}
	return txn.Commit()
}

// 从缓存中只查询对应的key
func BadgerScanKeyOnly(prefix string, opts ...Option) ([]string, uint64, error) {
	var (
		op    = options{index: 0}
		keys  []string
		total uint64
	)
	for _, option := range opts {
		option(&op)
	}
	e := CacheDb[op.index].View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if strings.HasPrefix(string(item.Key()), prefix) {
				keys = append(keys, string(item.Key()))
				total++
			}
		}
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	return keys, total, nil
}

// 从缓存中查询对应的key和值
func BadgerScan(prefix string, opts ...Option) ([]map[string]any, uint64, error) {
	var (
		op    = options{index: 0}
		total uint64
		m     []map[string]any
	)
	for _, option := range opts {
		option(&op)
	}
	e := CacheDb[op.index].View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(prefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			e := item.Value(func(v []byte) error {
				m = append(m, map[string]any{"key": string(item.Key()), "value": string(v)})
				return nil
			})
			if e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	return m, total, nil
}

// AES对称加密
func Aes128Encrypt(str string, opts ...Option) (s string) {
	defer func() {
		if v := recover(); v != nil {
			slog.Error("recover", v)
			s = ""
		}
	}()
	var (
		op = options{aes128Key: "378f73a1aacefa60", aes128Iv: "73c5bc89799703e3"}
	)
	for _, option := range opts {
		option(&op)
	}
	block, err := aes.NewCipher([]byte(op.aes128Key))
	if err != nil {
		panic(err.Error())
	}
	//填充内容，如果不足16位字符
	blockSize := block.BlockSize()
	originData := _pad([]byte(str), blockSize)
	//加密方式
	blockMode := cipher.NewCBCEncrypter(block, []byte(op.aes128Iv))
	//加密，输出到[]byte数组
	crypted := make([]byte, len(originData))
	blockMode.CryptBlocks(crypted, originData)
	return base64.StdEncoding.EncodeToString(crypted)
}

// AES对称解密
func Aes128Decrypt(str string, opts ...Option) (s string) {
	defer func() {
		if v := recover(); v != nil {
			slog.Error("recover", v)
			s = ""
		}
	}()
	var (
		op = options{aes128Key: "378f73a1aacefa60", aes128Iv: "73c5bc89799703e3"}
	)
	for _, option := range opts {
		option(&op)
	}
	decode_data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		panic(err.Error())
	}
	//生成密码数据块cipher.Block
	block, _ := aes.NewCipher([]byte(op.aes128Key))
	//解密模式
	blockMode := cipher.NewCBCDecrypter(block, []byte(op.aes128Iv))
	//输出到[]byte数组
	origin_data := make([]byte, len(decode_data))
	blockMode.CryptBlocks(origin_data, decode_data)
	//去除填充,并返回
	return string(_unpad(origin_data))
}

func _pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func _unpad(ciphertext []byte) []byte {
	length := len(ciphertext)
	//去掉最后一次的padding
	unpadding := int(ciphertext[length-1])
	return ciphertext[:(length - unpadding)]
}

// 非对称加密
func RsaEncrypt(origData []byte, opts ...Option) ([]byte, error) {
	var (
		op = options{publicKey: "", privateKey: ""}
	)
	for _, option := range opts {
		option(&op)
	}
	//解密pem格式的公钥
	block, _ := pem.Decode([]byte(op.publicKey))
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 非对称解密
func RsaDecrypt(ciphertext []byte, opts ...Option) ([]byte, error) {
	var (
		op = options{publicKey: "", privateKey: ""}
	)
	for _, option := range opts {
		option(&op)
	}
	//解密
	block, _ := pem.Decode([]byte(op.privateKey))
	if block == nil {
		return nil, errors.New("private key error!")
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 解密
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
