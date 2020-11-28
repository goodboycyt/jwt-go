package jwt_go

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type JwtI interface {
	SetPublicPd()
}

type Jwt struct {
	secret string //密钥
	iss string //jwt签发者
	sub string//jwt所面向的用户
	aud string//接收jwt的一方
	exp int64//jwt的过期时间，这个过期时间必须要大于签发时间
	nbf int64//定义在什么时间之前，该jwt都是不可用的.
	iat int64//jwt的签发时间
	jti string//jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

	publicPayload map[string]interface{}//公共信息
	RecPayload map[string]interface{}//接收到的信息
	//header string//头部信息
}

func (jwt *Jwt) SetSecret(st string) {//设置密钥
	jwt.secret = st
}
func (jwt *Jwt) SetIss(iss string) {//设置密钥
	jwt.iss = iss
}
func (jwt *Jwt) SetSub(sub string) {//设置密钥
	jwt.sub = sub
}
func (jwt *Jwt) SetAud(aud string) {//设置密钥
	jwt.aud = aud
}
func (jwt *Jwt) SetExp(exp int64) {//设置密钥
	jwt.exp = exp
}
func (jwt *Jwt) SetNbf(nbf int64) {//设置密钥
	jwt.nbf = nbf
}
func (jwt *Jwt) SetIat(iat int64) {//设置密钥
	jwt.iat = iat
}
func (jwt *Jwt) SetJti(jti string) {//设置密钥
	jwt.jti = jti
}
func (jwt *Jwt) SetPublicPd(publicPayload map[string]interface{}) {//设置密钥
	jwt.publicPayload = publicPayload
}

func (jwt *Jwt) GenSignature() (string,error){//生成jwt字符串
	if jwt.secret=="" {
		return "",errors.New("secret must not be empty!")
	}
	header := base64.StdEncoding.EncodeToString([]byte("{\"typ\":\"JWT\",\"alg\":\"HS256\"}"))//头部
	payload := map[string]interface{}{"iss":jwt.iss, "sub":jwt.sub,"aud":jwt.aud,"exp":jwt.exp,"nbf":jwt.nbf,"iat":jwt.iat,"jti":jwt.jti}
	for k ,v := range jwt.publicPayload {
		payload[k] = v
	}
	pyJson,_ :=json.Marshal(payload)
	tmp := base64.StdEncoding.EncodeToString(pyJson)
	return header+"."+tmp+"."+hmacSha256(header+md5T(tmp)+tmp, jwt.secret),nil
	//return "wew"

}

func (jwt *Jwt) VailDecSign(token string) (bool,error){//生成jwt字符串
	tokenArr :=strings.Split(token,".")
	if jwt.secret=="" || len(tokenArr)!=3{
		return false,errors.New("secret must not be empty!.token struct error")
	}
	if hmacSha256(tokenArr[0]+md5T(tokenArr[1])+tokenArr[1], jwt.secret) != tokenArr[2] {
		return false,errors.New("token is illegal")
	}
	payload, err0 := base64.StdEncoding.DecodeString(tokenArr[1])
	if err0!=nil {
		return false,errors.New("payload base64 decode error")
	}
	var payMap map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &payMap); err != nil {
		return false,errors.New("payload json struct error")
	}
	jwt.RecPayload = payMap

	return true,nil


}

func hmacSha256(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func md5T(str string) string {
	m5 := md5.New()
	_,err := m5.Write([]byte(str))
	if err != nil {
		panic(err)
	}
	md5String := hex.EncodeToString(m5.Sum(nil))
	return md5String
}

func (jwt *Jwt) IsExp() bool{
	if int64(jwt.RecPayload["exp"].(float64))<time.Now().Unix() {
		return true
	} else {
		return false
	}
}