package icu.secnotes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@ServletComponentScan //开启了对servlet组件的支持
@SpringBootApplication
public class SpringVulnBootApplication {

    public static void main(String[] args) {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");

        // **新增这一行，以启用Commons Collections反序列化支持**
        System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "true");
        SpringApplication.run(SpringVulnBootApplication.class, args);
    }

}
