# SpringVulnBoot Backend

## 项目介绍

基于 Vue + SpringBoot 构建的 Java 安全靶场，一个专为安全爱好者、开发人员和渗透测试人员打造的实战演练平台。

1. 前端是基于流行的vue-admin-template基础模板进行改改改，[前端工程](https://github.com/bansh2eBreak/SpringVulnBoot-frontend)
2. 后端是基于SpringBoot 2.7.14开发的，[后端工程](https://github.com/bansh2eBreak/SpringVulnBoot-backend)

## 效果图
![img_1.png](images/img_1.png)
![img_2.png](images/img_2.png)
![img_3.png](images/img_3.png)
![img_4.png](images/img_4.png)
![img_5.png](images/img_5.png)
![img_6.png](images/img_6.png)

## 更新日志
2025/02/21（最新更新）：
- 增加路径穿越漏洞，并可以前端直接复现

2025/02/10：
- 增加组件漏洞-Fastjson漏洞，并可以前端直接复现

2025/02/08：
- 增加身份认证漏洞-密码登录暴力破解漏洞，包括普通的账号密码登录、HTTP Basic认证登录、带图形验证码登录几种场景。

## 靶场已编写的漏洞
- SQLi注入
  - 基于Jdbc的SQLi注入
  - 基于Mybatis的SQLi注入
- XSS跨站脚本
  - 反射型XSS
  - 存储型XSS
- 任意命令执行
  - Runtime方式
  - ProcessBuilder方式
- 任意URL跳转
- 路径穿越漏洞
- 身份认证漏洞 
  - 密码登录暴力破解
    - 普通的账号密码登录暴力破解
    - 绕过单IP限制暴力破解
    - HTTP Basic认证登录暴力破解
    - 图形验证码登录暴力破解
- 组件漏洞
  - Fastjson漏洞
  - Log4j2漏洞

## 未完待续
- 文件上传漏洞
- SSRF漏洞
- CSRF漏洞
- 逻辑漏洞
- 业务漏洞
- ...

