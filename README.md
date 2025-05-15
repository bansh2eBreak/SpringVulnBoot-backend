# SpringVulnBoot Backend

## 项目介绍

基于 Vue + SpringBoot 构建的 Java 安全靶场，一个专为安全爱好者、开发人员和渗透测试人员打造的实战演练平台。

1. 前端是基于流行的vue-admin-template基础模板进行改改改，[前端工程](https://github.com/bansh2eBreak/SpringVulnBoot-frontend)
2. 后端是基于SpringBoot 2.7.14开发的，[后端工程](https://github.com/bansh2eBreak/SpringVulnBoot-backend)

## 更新日志
2025/05/13：
- 增加身份认证漏洞-MFA登录漏洞中的MFA绑定与MFA解绑操作
- 增加越权漏洞：
  - 平行越权漏洞
  - 未授权访问漏洞
  - 垂直越权漏洞

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
- 文件上传漏洞
- 越权漏洞
  - 水平越权漏洞
  - 垂直越权漏洞
  - 未授权访问漏洞
- 身份认证漏洞 
  - 密码登录暴力破解
    - 普通的账号密码登录暴力破解
    - 绕过单IP限制暴力破解
    - HTTP Basic认证登录暴力破解
    - 图形验证码登录暴力破解
  - 短信认证漏洞
    - 短信轰炸
    - 短信验证码回显
    - 暴力破解短信验证码
- 组件漏洞
  - Fastjson漏洞
  - Log4j2漏洞

## 未完待续
- SSRF漏洞
- CSRF漏洞
- 逻辑漏洞
- 配置漏洞

## 效果图
![img_11.png](images/img_11.png)
![img_12.png](images/img_12.png)
![img_13.png](images/img_13.png)
![img_9.png](images/img_9.png)
![img_10.png](images/img_10.png)
![img_1.png](images/img_1.png)
![img_2.png](images/img_2.png)
![img_3.png](images/img_3.png)
![img_4.png](images/img_4.png)
![img_5.png](images/img_5.png)
![img_6.png](images/img_6.png)
![img_7.png](images/img_7.png)
![img_8.png](images/img_8.png)

