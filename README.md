Java靶场SpringVulnBoot后端工程：SpringVulnBoot-backtend

通过Springboot打造的java安全靶场，尽可能编写出各种常见的漏洞，供大家学习和测试。<br>
前端是基于流行的vue-admin-template基础模板进行改改改，参考：https://github.com/bansh2eBreak/SpringVulnBoot-frontend

![img_1.png](img_1.png)

本次更新（2025/02/08）：
- 增加身份认证漏洞-密码登录暴力破解漏洞，包括普通的账号密码登录、HTTP Basic认证登录、带图形验证码登录几种场景。

靶场已编写的漏洞有：
- SQLi注入
- XSS跨站脚本
- 任意命令执行
- 任意URL跳转
- 身份认证漏洞 
  - 密码登录-暴力破解（包含图形验证码的漏洞）

未完待续：
- 文件上传漏洞
- SSRF漏洞
- CSRF漏洞
- 逻辑漏洞
- 业务漏洞
- ...

