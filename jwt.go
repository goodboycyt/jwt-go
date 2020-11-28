package jwt_go

import (
	"encoding/base64"
	"fmt"
)

type Jwt struct {
	secret string //密钥
	iss string //jwt签发者
	sub string//jwt所面向的用户
	aud string//接收jwt的一方
	exp int64//jwt的过期时间，这个过期时间必须要大于签发时间
	nbf int64//定义在什么时间之前，该jwt都是不可用的.
	iat int64//jwt的签发时间
	jti string//jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

	publicPayload []map[string]interface{}//公共信息
	recPayload []map[string]interface{}//接收到的信息
	//header string//头部信息
}

func (jwt Jwt) SetSecret(st string) {//设置密钥
	jwt.secret = st
}
func (jwt Jwt) SetIss(iss string) {//设置密钥
	jwt.iss = iss
}
func (jwt Jwt) SetSub(sub string) {//设置密钥
	jwt.sub = sub
}
func (jwt Jwt) SetAud(aud string) {//设置密钥
	jwt.aud = aud
}
func (jwt Jwt) SetExp(exp int64) {//设置密钥
	jwt.exp = exp
}
func (jwt Jwt) SetNbf(nbf int64) {//设置密钥
	jwt.nbf = nbf
}
func (jwt Jwt) SetIat(iat int64) {//设置密钥
	jwt.iat = iat
}
func (jwt Jwt) SetJti(jti string) {//设置密钥
	jwt.jti = jti
}
func (jwt Jwt) SetPublicPd(publicPayload []map[string]interface{}) {//设置密钥
	jwt.publicPayload = publicPayload
}

func (jwt Jwt) GenSignature() {//生成jwt字符串
	header := base64.StdEncoding.EncodeToString([]byte("{\"typ\":\"JWT\",\"alg\":\"HS256\"}"))//头部
	payload := map[string]interface{}{"iss":jwt.iss, "sub":jwt.sub,"aud":jwt.aud,"exp":jwt.exp,"nbf":jwt.nbf,"iat":jwt.iat,"jti":jwt.jti}
	fmt.Println(header,payload)
}