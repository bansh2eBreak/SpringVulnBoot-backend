package icu.secnotes.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class RuntimeDemo {
    public static void main(String[] args) {
        try {
            // 要执行的命令
            String command = "ping 127.0.0.1 -c 2;whoami";

            // 执行命令并获取进程
            Process process = Runtime.getRuntime().exec(command);

            // 获取命令的输出流
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // 获取命令的错误流
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                System.err.println(line);
            }

            int exitValue = process.waitFor();
            System.out.println("Process exited with value " + exitValue);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
