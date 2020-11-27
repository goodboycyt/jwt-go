package jwt_go

import "fmt"

type jwt struct {
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
	header string//头部信息
}
var jwtob jwt
func (jwtob jwt) setSecret(st string) {
	jwtob.secret = st
	fmt.Println(jwtob.secret)
}