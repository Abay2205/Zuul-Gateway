//package com.example.zuulgateway.auth;
//
//import com.google.common.collect.Lists;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Repository;
//import org.springframework.web.bind.annotation.PostMapping;
//
//import java.util.List;
//import java.util.Optional;
//
//import static com.example.zuulgateway.security.ApplicationUserRole.*;
//
//@Repository("fake")
//public class FakeApplicationUserDao implements ApplicationUserDao {
//
//    private final PasswordEncoder passwordEncoder;
//    @Autowired
//    public FakeApplicationUserDao(PasswordEncoder passwordEncoder) {
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    @Override
//    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
//        return getApplicationUsers()
//                .stream()
//                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
//                .findFirst();
//    }
//
//    private List<ApplicationUser> getApplicationUsers(){
//        List<ApplicationUser> applicationUsers = Lists.newArrayList(
//                new ApplicationUser(
//                        "aba",
//                        passwordEncoder.encode("aba"),
//                        USER.getGrantedAuthorities(),
//                        true,
//                        true,
//                        true,
//                        true
//                ),
//                new ApplicationUser(
//                        "adil",
//                        passwordEncoder.encode("adil"),
//                        ADMIN.getGrantedAuthorities(),
//                        true,
//                        true,
//                        true,
//                        true
//                ),
//                new ApplicationUser(
//                        "ula",
//                        passwordEncoder.encode("ula"),
//                        ADMINTRAINEE.getGrantedAuthorities(),
//                        true,
//                        true,
//                        true,
//                        true
//                )
//        );
//        return applicationUsers;
//    }
//}
