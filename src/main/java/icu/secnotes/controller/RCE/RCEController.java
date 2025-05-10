package icu.secnotes.controller.RCE;

import icu.secnotes.pojo.Result;
import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@RestController
@Slf4j
@RequestMapping("/rce")
public class RCEController {

    /**
     * @Poc：http://127.0.0.1:8080/rce/ping?ip=127.0.0.1 -c 1;whoami
     * @param ip IP地址
     * @return  返回命令执行结果
     */
    @GetMapping("/vulnPing")
    public Result vulnPing(String ip) {
        System.out.println(ip);
        String line;    // 用于保存命令执行结果
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};
        log.info("执行的命令: {}", Arrays.toString(cmd));

        try {
            // 执行命令并获取进程
            Process process = Runtime.getRuntime().exec(cmd);

            // 获取命令的输出流
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            // 获取命令的错误流
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            int exitValue = process.waitFor();
            System.out.println("Process exited with value " + exitValue);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        //将命令执行结果或者错误结果输出
        return Result.success(sb.toString());
    }

    /**
     * @Poc：http://127.0.0.1:8080/rce/secPing?ip=127.0.0.1 -c 1;whoami
     * @param ip
     * @return
     */
    @GetMapping("/secPing")
    public Result secPing(String ip) {
        if (Security.checkCommand(ip)) {
            log.warn("非法字符：{}", ip);
            return Result.error("检测到非法命令注入！");
        }

        String line;
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};
        log.info("执行的命令: {}", Arrays.toString(cmd));

        try {
            // 执行命令并获取进程
            Process process = Runtime.getRuntime().exec(cmd);

            // 获取命令的输出流
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            // 获取命令的错误流
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            int exitValue = process.waitFor();
            System.out.println("Process exited with value " + exitValue);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        //将命令执行结果或者错误结果输出
        return Result.success(sb.toString());
    }

    /**
     * @Poc： http://127.0.0.1:8080/rce/vulnPing2?ip=127.0.0.1 -c 1;whoami
     * @param ip
     * @return
     */
    @GetMapping("/vulnPing2")
    public Result vulnPing2(String ip) {
        String line;
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};
        log.info("执行的命令: {}", Arrays.toString(cmd));

        try {
            // 执行命令并获取进程
            ProcessBuilder processBuilder = new ProcessBuilder(cmd);
            // ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", "ping " + ip); // 也可以这样写

            Process process = processBuilder.start();

            // *** 正确的超时设置方法 ***
            // 等待进程结束，最多等待 10 秒
            boolean finished = process.waitFor(10, TimeUnit.SECONDS);

            if (!finished) {
                // 如果进程在 10 秒内没有结束，则强制终止它
                process.destroyForcibly();
                sb.append("命令执行超时，已被终止。\n");
                // 等待进程完全终止
                process.waitFor(); // 这一行确保进程清理完毕
            }

            // 获取命令的输出流
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            // 获取命令的错误流
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                sb.append(line).append("\n");
            }

            int exitValue = process.waitFor();
            System.out.println("Process exited with value " + exitValue);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        //将命令执行结果或者错误结果输出
        return Result.success(sb.toString());
    }

    /**
     * @Poc：http://127.0.0.1:8080/rce/secPing2?ip=127.0.0.1 -c 1;whoami
     * @param ip
     * @return
     */
    @GetMapping("/secPing2")
    public Result secPing2(String ip) {
        if (Security.checkIp(ip)) {
            String line;
            StringBuilder sb = new StringBuilder();

            // 要执行的命令
            String[] cmd = {"bash" , "-c", "ping " + ip};
            log.info("执行的命令: {}", Arrays.toString(cmd));

            try {
                // 执行命令并获取进程
                ProcessBuilder processBuilder = new ProcessBuilder(cmd);

                // 设置超时时间为10秒
                // 退出值为 124 表示进程因为超时被终止
                processBuilder.command().add(0, "timeout");
                processBuilder.command().add(1, "10s");

                Process process = processBuilder.start();

                // 获取命令的输出流
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }

                // 获取命令的错误流
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                while ((line = errorReader.readLine()) != null) {
                    sb.append(line).append("\n");
                }

                int exitValue = process.waitFor();
                System.out.println("Process exited with value " + exitValue);

            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
            //将命令执行结果或者错误结果输出
            return Result.success(sb.toString());
        } else {
            log.warn("IP地址不合法：{}", ip);
            return Result.error("IP地址不合法！");
        }
    }
}
