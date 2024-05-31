package utils

import (
	"bytes"
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
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	Db      *gorm.DB
	Casbin  *casbin.Enforcer
	Bleve   []bleve.Index
	CacheDb []*badger.DB
)

// option模式
type options struct {
	total        int
	index        int
	ttl          int
	field        string
	multikeyword []string
	returnFields []string
	jwtSecureKey string
	cacheFolder  string
	aes128Key    string
	aes128Iv     string
	publicKey    string
	privateKey   string
}
type Option func(options *options)

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
		slog.Info("搜索引擎数据库初始化完成", "索引号", i+1)
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
		slog.Info("缓存数据库初始化完成", "索引号", i+1)
	}
}

// 初始化mysql数据库
func InitMariaDB(dbsParams map[string]any) {
	var (
		err error
		DSN = dbsParams["Dsn"].(string)
	)
	if Db, err = gorm.Open(mysql.Open(DSN), &gorm.Config{
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	}); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	sqlDB, _ := Db.DB()
	if dbsParams["idleConns"].(string) != "" {
		n, _ := strconv.Atoi(dbsParams["idleConns"].(string))
		sqlDB.SetMaxIdleConns(n)
	} else {
		sqlDB.SetMaxIdleConns(5) // SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	}
	if dbsParams["maxConns"].(string) != "" {
		n, _ := strconv.Atoi(dbsParams["maxConns"].(string))
		sqlDB.SetMaxOpenConns(n)
	} else {
		sqlDB.SetMaxOpenConns(250) // SetMaxOpenConns sets the maximum number of open connections to the database.
	}
	if dbsParams["maxLifeTime"].(string) != "" {
		n, _ := strconv.Atoi(dbsParams["maxLifeTime"].(string))
		sqlDB.SetConnMaxLifetime(time.Minute * time.Duration(n))
	} else {
		sqlDB.SetConnMaxLifetime(time.Hour * 6) // SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	}
	slog.Info("数据库Mariadb初始化完成")
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
		op      = options{field: "body", returnFields: []string{"body"}}
	)
	for _, option := range opts {
		option(&op)
	}
	op.multikeyword = append(op.multikeyword, s)
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
	searchRequest := bleve.NewSearchRequest(boolQuery)
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
	if e := Bleve[op.index].Index(id, data); e != nil {
		slog.Error("", "错误", e.Error())
		return e
	} else {
		slog.Info("加入搜索引擎成功", "id", id)
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
	if doc, e := Bleve[op.index].Document(id); e != nil {
		slog.Error("", "文档ID错误", e.Error())
		return nil, e
	} else {
		for _, v1 := range doc.(*document.Document).Fields {
			m["id"] = id
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
	return Bleve[op.index].DocCount()
}

// 设置缓存key和值以及时效
func BadgerSet(key string, data any, opts ...Option) error {
	var (
		op = options{}
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
		slog.Info("BadgerSet", "订单写入缓存", key)
		return nil
	})
	return e
}

// 根据key取缓存
func BadgerGet(key string, opts ...Option) (any, error) {
	var (
		op = options{}
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
		op = options{}
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
		op = options{}
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
		op = options{}
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
		op    = options{}
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
		op    = options{}
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
