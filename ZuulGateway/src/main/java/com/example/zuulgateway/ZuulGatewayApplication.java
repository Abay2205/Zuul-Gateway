package com.example.zuulgateway;

import com.example.zuulgateway.Entity.Role;
import com.example.zuulgateway.Entity.User;
import com.example.zuulgateway.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableZuulProxy
@EnableFeignClients
public class ZuulGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ZuulGatewayApplication.class, args);
    }

@Bean
    PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
}

//    @Bean
//    CommandLineRunner run(UserService userService) {
//        return args -> {
//            userService.saveRole(new Role(null, "ROLE_USER1"));
//            userService.saveRole(new Role(null, "ROLE_MANAGER"));
//            userService.saveRole(new Role(null, "ROLE_ADMIN1"));
//            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//            userService.saveUser(new User(null, "John Travolta", "john", "1234", new ArrayList<>()));
//            userService.saveUser(new User(null, "Will Smith", "will", "1234", new ArrayList<>()));
//            userService.saveUser(new User(null, "Jake Jillenhall", "jake", "1234", new ArrayList<>()));
//            userService.saveUser(new User(null, "Rayan Gosling", "rayan", "1234", new ArrayList<>()));
//
//            userService.addRoleToUser("john", "ROLE_USER1");
////            userService.addRoleToUser("john", "ROLE_MANAGER");
//            userService.addRoleToUser("will", "ROLE_MANAGER");
//            userService.addRoleToUser("jake", "ROLE_ADMIN1");
//            userService.addRoleToUser("rayan", "ROLE_SUPER_ADMIN");
////            userService.addRoleToUser("rayan", "ROLE_ADMIN1");
////            userService.addRoleToUser("rayan", "ROLE_USER1");
//        };
//    }
}
