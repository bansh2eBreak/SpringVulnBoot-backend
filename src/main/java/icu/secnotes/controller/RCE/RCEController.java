package icu.secnotes.controller.RCE;

import icu.secnotes.utils.Security;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

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
    public String vulnPing(String ip) {
        String line;    // 用于保存命令执行结果
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};

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
        return sb.toString();
    }

    /**
     * @Poc：http://127.0.0.1:8080/rce/secPing?ip=127.0.0.1 -c 1;whoami
     * @param ip
     * @return
     */
    @GetMapping("/secPing")
    public String secPing(String ip) {
        if (Security.checkCommand(ip)) {
            log.warn("非法字符：{}", ip);
            return "检测到非法命令注入！";
        }

        String line;
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};

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
        return sb.toString();
    }

    /**
     * @Poc： http://127.0.0.1:8080/rce/vulnPing2?ip=127.0.0.1 -c 1;whoami
     * @param ip
     * @return
     */
    @GetMapping("/vulnPing2")
    public String vulnPing2(String ip) {
        String line;
        StringBuilder sb = new StringBuilder();

        // 要执行的命令
        String[] cmd = {"bash" , "-c", "ping " + ip};

        try {
            // 执行命令并获取进程
            ProcessBuilder processBuilder = new ProcessBuilder(cmd);
            // ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", "ping " + ip); // 也可以这样写

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
        return sb.toString();
    }

    /**
     * @Poc：http://127.0.0.1:8080/rce/secPing2?ip=127.0.0.1 -c 1;whoami
     * @param ip
     * @return
     */
    @GetMapping("/secPing2")
    public String secPing2(String ip) {
        if (Security.checkIp(ip)) {
            String line;
            StringBuilder sb = new StringBuilder();

            // 要执行的命令
            String[] cmd = {"bash" , "-c", "ping " + ip};

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
            return sb.toString();
        } else {
            log.warn("IP地址不合法：{}", ip);
            return "IP地址不合法！";
        }
    }
}
