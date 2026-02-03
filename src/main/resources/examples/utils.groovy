/**
 * 安全脚本示例 - utils.groovy
 * 部署位置：/app/file/utils.groovy（容器中）
 * 源文件位置：src/main/resources/examples/utils.groovy
 * 
 * 安全说明：
 * - 此文件在容器构建时被复制到 /app/file/ 根目录
 * - 攻击者只能上传文件到 /app/file/upload/（用户上传目录，子目录）
 * - 攻击者无法写入 /app/file/ 根目录（白名单脚本位置，权限隔离）
 */

out.println("<html><head><meta charset='UTF-8'><title>安全脚本执行</title>")
out.println("<style>")
out.println("body { font-family: Arial, sans-serif; background: #f0f9ff; padding: 30px; }")
out.println("h2 { color: #22c55e; }")
out.println(".info { background: #fff; padding: 20px; border-radius: 8px; border-left: 4px solid #22c55e; margin-bottom: 15px; }")
out.println(".warning { background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107; }")
out.println("code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }")
out.println("</style></head><body>")

out.println("<h2>✅ 安全脚本执行成功</h2>")

out.println("<div class='info'>")
out.println("<p><strong>📋 脚本信息：</strong></p>")
out.println("<p>• 脚本名称: <code>utils.groovy</code></p>")
out.println("<p>• 部署位置: <code>/app/file/utils.groovy</code></p>")
out.println("<p>• 目录说明: <code>/app/file/</code> 是靶场项目统一的文件管理目录</p>")
out.println("</div>")

out.println("<div class='info'>")
out.println("<p><strong>🔒 三层安全机制：</strong></p>")
out.println("<ul>")
out.println("<li><strong>第1层 - 白名单验证：</strong>只允许执行预定义的脚本名称（utils.groovy, helpers.groovy, validators.groovy）</li>")
out.println("<li><strong>第2层 - 固定目录：</strong>从 <code>/app/file/</code> 根目录读取，不是用户上传目录</li>")
out.println("<li><strong>第3层 - 权限隔离：</strong>攻击者只能写 <code>/app/file/upload/</code>，无法写 <code>/app/file/</code> 根目录</li>")
out.println("</ul>")
out.println("</div>")

out.println("<div class='warning'>")
out.println("<p><strong>⚠️ 为什么不能从用户上传目录读取？</strong></p>")
out.println("<p>假设之前的漏洞实现：白名单验证通过后，从 <code>/app/file/upload/</code> 读取</p>")
out.println("<p><strong style='color: #dc3545;'>攻击场景：</strong></p>")
out.println("<ol>")
out.println("<li>攻击者上传恶意脚本</li>")
out.println("<li>将文件命名为 <code>utils.groovy</code>（白名单名称）</li>")
out.println("<li>访问安全接口：<code>/groovy/sec?file=utils.groovy</code></li>")
out.println("<li>✅ 白名单验证通过（文件名匹配）</li>")
out.println("<li>❌ 但读取的是攻击者上传的恶意脚本！</li>")
out.println("</ol>")
out.println("<p><strong style='color: #22c55e;'>现在的防御：</strong></p>")
out.println("<p>即使攻击者上传 <code>/app/file/upload/utils.groovy</code>，系统读取的是 <code>/app/file/utils.groovy</code>（应用预置的安全脚本）</p>")
out.println("</div>")

out.println("</body></html>")
