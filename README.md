Java靶场 -- SpringVulnBoot

通过Springboot打造的java安全靶场，尽可能编写出各种常见的漏洞，供大家学习和测试。
前端是通过流行的vue-admin-template基础模板进行开发，参考：https://github.com/bansh2eBreak/SpringVulnBoot-frontend

![img.png](img.png)

本次更新：
- 增加了登录认证，通过spring框架的Interceptor+WebMvcConfigurer配置类实现登录校验
- 实现了管理员登录Jwt会话的生产和验证逻辑
- 抛弃原始前端框架的Cookie技术，改为从LocalStorage中读写

靶场已编写的漏洞有：
- SQLi注入
- XSS跨站脚本
- 任意命令执行
- 任意URL跳转

未完待续：
- 文件上传漏洞
- SSRF漏洞
- CSRF漏洞
- 逻辑漏洞
- 业务漏洞
- ...

