# SpringVulnBoot Backend

## 项目介绍
SpringBoot靶场后端工程：SpringVulnBoot-backend

通过Springboot打造的java安全靶场，尽可能编写出各种常见的漏洞，供大家学习和测试。<br>

1. 前端是基于流行的vue-admin-template基础模板进行改改改，[前端工程](https://github.com/bansh2eBreak/SpringVulnBoot-frontend)
2. 后端是基于springboot开发的，[后端工程](https://github.com/bansh2eBreak/SpringVulnBoot-backend)

## 效果图
![img_1.png](img_1.png)
![img_2.png](img_2.png)
![img_3.png](img_3.png)
![img_4.png](img_4.png)

## 更新日志
本次更新（2025/02/10）：
- 增加组件漏洞-Fastjson漏洞，并可以前端直接复现
2025/02/08：
- 增加身份认证漏洞-密码登录暴力破解漏洞，包括普通的账号密码登录、HTTP Basic认证登录、带图形验证码登录几种场景。

靶场已编写的漏洞有：
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
- 身份认证漏洞 
  - 密码登录暴力破解
    - 普通的账号密码登录暴力破解
    - 绕过单IP限制暴力破解
    - HTTP Basic认证登录暴力破解
    - 图形验证码登录暴力破解
- 组件漏洞
  - Fastjson漏洞

未完待续：
- 文件上传漏洞
- SSRF漏洞
- CSRF漏洞
- 逻辑漏洞
- 业务漏洞
- ...

