玉符SDK
======
玉符SDK集成了签署和验证JWT令牌的功能，使得身份提供者（IDP）和服务提供者（SP）只需要用很少的代码就可以轻松将玉符提供的单点登录和其他功能集成到现有的服务之中。

---
## 使用SDK之前
* 作为身份提供者（IDP），可以使用玉符SDK为用户生成并签署JWT令牌，并送到玉符服务器上认证并登录到第三方服务提供商。
  >需从玉符注册并获取相应的身份提供者ID，并生成pem格式的公私钥文件。

* 作为服务提供者（SP），可以使用玉符SDK验证JWT令牌的有效性（包括有效期、签名等），成功后进行相应的建权。
* 如果服务提供者（SP）还为用户/租户提供身份联合、第三方登录的功能，可以使用玉符SDK生成并签署JWT令牌，并送到玉符服务器上认证并跳转到第三方身份提供者。(需额外生成pem格式的公私钥文件)

---
## 安装SDK
在Gemfile中加入:
·gem 'yufu'·

然后执行
`$ bundle`

或者直接通过gem安装

·$ gem install yufu·
---

## 使用SDK
**身份提供者（IDP)**
1. 实例化SDK的身份提供商。
```
  idProvider = ::Yufu::YufuAuth.new
  idProvider.idp = "idp-07b40589-a585-40ea-9e86-979f3c652b56"
  idProvider.tenent = "yufu"
  idProvider.private_key_path = "{PATH_TO_PRIVATE_KEY}.pem}"
```

2. 根据用户选取或提前定义的服务应用ID，可以为用户生成并签署对应令牌`generateIDPRedirectUrl`，并向用户发送302跳转登录到第三方服务提供商，代码样式
```
  payload = {
    sub: "lizheng@yufuid.com",
    spid: "sp-d3ba0ab4-1256-4195-b515-8e287c8c5e49",
    stype: "email",
  }
  
  puts idProvider.generateIDPRedirectUrl(payload)                               
  // 跳转用户至玉符云服务器认证授权，可根据需求在URL中添加定制的请求参数(如内网ip)便于后期审计
```

**服务提供者（SP)**
1. 实例化SDK的服务提供商。
```
  serviceProvider = ::Yufu::YufuAuth.new
  serviceProvider.public_key_path = Dir.pwd + '/public_key.pem'
```

2. 实现单点登录：接收并验证`verify`JWT令牌的有效性（包括有效期、签名等），如通过，说明该令牌来自玉符信任的有效租户(企业/组织)的用户，样例
```
  idToken = getIdToken()               // 从URL中获得 ID token
  claims = serviceProvider.verify(id_token)   // 使用验证玉符SDK实例进行验证, 如果成功会返回包含用户信息的对象，失败则会产生授权错误的异常
  username = serviceProvider.getSubject();        // 用户名称
  clientId = serviceProvider.getAudience();       // 玉符签发的唯一识别码
```

3. 根据第2步获取的用户信息，您的系统可进行鉴权和赋予登录系统等相应权限，否则提示用户登录失败。推荐鉴权方案:
  * 服务提供商(SP)允许租户管理员输入一个玉符的唯一识别码
  * 在第2步Token验证通过后，根据获取的租户名称/ID和识别码, 查看是否匹配该租户在服务提供商(SP)所提供的唯一识别码，如匹配则表示租户为有效租户。
  * 接着查看用户是否存在于租户中，如果存在，则赋予登录系统的权限。

---
## 异常说明
TODO
---
## FAQ

---
## 联系玉符
contact@yufuid.com