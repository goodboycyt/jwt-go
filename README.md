## jwt go lib

### use mod config
`require github.com/goodboycyt/jwt-go latest`
or
`go get -u github.com/goodboycyt/jwt-go`


### 生成token
```go
var jwtob jwt.Jwt
jwtob.SetSecret("xDE}o4L1dVW+'@;P#=9]SFvVzPs'~Z")
jwtob.SetExp(1700000000)
jwtob.SetPublicPd(map[string]interface{}{"username":"sdsad", "userid":12121})
a, err :=jwtob.GenSignature()
```
### 验证jwt字符串的真实性
```go
b, _ :=jwtob.VailDecSign(a)
fmt.Println(b)//true or false
```
### 验证签名是否过期
```go
fmt.Println(jwtob.IsExp())//if had exp return,either return  false
```

### 获取payload信息
```go
//before do this,you must 'VailDecSign' the token
fmt.Println(jwtob.RecPayload["username"])//RecPayload is a map,u can get fields with this var
```