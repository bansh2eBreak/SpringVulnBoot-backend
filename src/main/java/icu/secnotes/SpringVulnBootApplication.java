package icu.secnotes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@ServletComponentScan //开启了对servlet组件的支持
@SpringBootApplication
public class SpringVulnBootApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringVulnBootApplication.class, args);
    }

}
