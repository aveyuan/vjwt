package vjwt

import (
	"time"

	"github.com/kataras/jwt"
)



type VjwtP struct {
	Key      string        //加密key
	Alg      string        //加密算法
	MaxAge   time.Duration //最大时间
	BlockExp time.Duration //阻止过期回收时间
}

type Vjwt[T any] struct {
	key       []byte         //加密key
	alg       jwt.Alg        //加密算法
	maxAge    time.Duration  //最大时间
	blocklist *jwt.Blocklist //组织队列
}

func NewJwt[T any](t *VjwtP) *Vjwt[T] {

	var alg jwt.Alg
	if t.Alg == "hs256" || t.Alg == "" {
		alg = jwt.HS256
	}
	if t.Alg == "hs384" {
		alg = jwt.HS384
	}

	if t.Alg == "hs512" {
		alg = jwt.HS512
	}

	if t.BlockExp == 0 {
		t.BlockExp = 15 * time.Second
	}

	if t.MaxAge == 0 {
		t.MaxAge = 2 * time.Hour
	}

	return &Vjwt[T]{
		key:       []byte(t.Key),
		alg:       alg,
		maxAge:    t.MaxAge,
		blocklist: jwt.NewBlocklist(t.BlockExp),
	}
}

// Token 通过Claims 生成token
func (t *Vjwt[T]) Token(Claims *T) (token string, exp int64, err error) {
	now := time.Now()
	expTime := now.Add(t.maxAge)
	jtoken, err := jwt.Sign(t.alg, t.key, Claims, jwt.Claims{
		IssuedAt: now.Unix(),
		Expiry:   expTime.Unix(),
	})
	return string(jtoken), expTime.Unix(), err
}

// Verify 验证，通过后返回jwt信息
// 验证失败过期和未生效都会返回错误信息
func (t *Vjwt[T]) Verify(token string) (*jwt.VerifiedToken, error) {
	jv, err := jwt.Verify(jwt.HS256, t.key, []byte(token))
	if err != nil {
		return nil, err
	}
	// 判断是否被阻止
	if err := t.blocklist.ValidateToken(jv.Token, jv.StandardClaims, nil); err != nil {
		return nil, err
	}
	return jv, nil
}

// Block 用于退出时，让token失效
func (t *Vjwt[T]) Block(token string) error {
	jv, err := jwt.Verify(jwt.HS256, t.key, []byte(token))
	if err != nil {
		return err
	}
	return t.blocklist.InvalidateToken(jv.Token, jv.StandardClaims)
}

// ReferToken 刷新token，需要确认刷新的用户数据结构用来重新生成
func (t *Vjwt[T]) ReferToken(token string, dest *T) (refertoken string, exp int64, err error) {
	jv, err := jwt.Verify(jwt.HS256, t.key, []byte(token))
	if err != nil {
		return "", 0, err
	}

	// 判断是否被阻止
	if err := t.blocklist.ValidateToken(jv.Token, jv.StandardClaims, nil); err != nil {
		return "", 0, err
	}
	// 加入到阻止列表,前端是异步请求，后面保证用刷新的即可不做限制
	// if err := t.Block(token); err != nil {
	// 	return "", 0, err
	// }
	now := time.Now()
	expTime := now.Add(t.maxAge)
	// 颁发新的token,老的进行阻止
	if err := jv.Claims(dest); err != nil {
		return "", 0, err
	}

	referToken, err := jwt.Sign(t.alg, t.key, dest, jwt.Claims{
		IssuedAt: now.Unix(),
		Expiry:   expTime.Unix(),
	})
	return string(referToken), expTime.Unix(), nil
}
