package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

//@EnableJpaRepositories("com.example.demo.*")
//@ComponentScan(basePackages = "com.example.demo.*")
//@EntityScan("com.example.demo.*")
@SpringBootApplication
public class MywebprojectApplication {

	public static void main(String[] args) {
		SpringApplication.run(MywebprojectApplication.class, args);
	}

}
