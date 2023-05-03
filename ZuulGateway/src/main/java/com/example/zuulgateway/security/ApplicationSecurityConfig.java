//package com.example.zuulgateway.security;
//
//import com.example.zuulgateway.auth.ApplicationUserService;
//import com.example.zuulgateway.jwt.JwtConfig;
//import com.example.zuulgateway.jwt.JwtTokenVerifier;
//import com.example.zuulgateway.jwt.JwtUserPasswordAuthFilter;
//import io.jsonwebtoken.security.Keys;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//import javax.crypto.SecretKey;
//
//import java.util.concurrent.TimeUnit;
//
//import static com.example.zuulgateway.security.ApplicationUserRole.*;
//
//@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
//
//    private final PasswordEncoder passwordEncoder;
//    private final ApplicationUserService applicationUserService;
////    @Autowired
////    private SecretKey secretKey;
//
//    private final JwtConfig jwtConfig;
//
//
//    @Autowired
//    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
//                                     ApplicationUserService applicationUserService, JwtConfig jwtConfig) {
//        this.passwordEncoder = passwordEncoder;
//        this.applicationUserService = applicationUserService;
//        this.jwtConfig = jwtConfig;
//    }
//
//    @Bean
//    public SecretKey secretKey(){
//        return Keys.hmacShaKeyFor(jwtConfig.getSecretKey().getBytes());
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
////                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////                .and()
//                .cors().disable()
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .addFilter(new JwtUserPasswordAuthFilter(authenticationManager(), jwtConfig, secretKey()))
//                .addFilterAfter(new JwtTokenVerifier(secretKey(), jwtConfig), JwtUserPasswordAuthFilter.class)
//                .authorizeRequests()
//                .antMatchers(HttpMethod.PUT, "/back1/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//                .antMatchers(HttpMethod.DELETE, "/back1/**").hasRole(ADMIN.name())
//                .antMatchers(HttpMethod.POST, "/back1/**").hasRole(ADMIN.name())
//                .antMatchers(HttpMethod.PUT, "/back3/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//                .antMatchers(HttpMethod.DELETE, "/back3/**").hasRole(ADMIN.name())
//                .antMatchers(HttpMethod.POST, "/back3/**").hasRole(ADMIN.name())
//                .antMatchers(HttpMethod.GET, "/back2/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//                .antMatchers(HttpMethod.PUT, "/back2/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//                .antMatchers(HttpMethod.POST, "/back2/**").hasAnyRole(ADMIN.name())
//                .antMatchers(HttpMethod.DELETE, "/back2/**").hasAnyRole(ADMIN.name())
////              .antMatchers("/back1/**").hasAnyRole(USER.name(), ADMIN.name(), ADMINTRAINEE.name())
////              .antMatchers("/back2/**").hasAnyRole(USER.name(), ADMIN.name(), ADMINTRAINEE.name())
////              .antMatchers("/back3/**").hasAnyRole(USER.name(), ADMIN.name(), ADMINTRAINEE.name())
//                .anyRequest()
//                .authenticated();
////                .and()
////                .formLogin()
////                   .loginPage("/login")
////                   .permitAll()
////                   .defaultSuccessUrl("/products", true)
////                   .usernameParameter("username")
////                   .passwordParameter("password")
////                .and()
////                .rememberMe()
////                   .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
////                   .key("somethingverysecret")
////                   .rememberMeParameter("remember-me")
////                .and()
////                .logout()
////                   .logoutUrl("/logout")
////                   .logoutRequestMatcher( new AntPathRequestMatcher("/logout", "GET"))
////                   .clearAuthentication(true)
////                   .invalidateHttpSession(true)
////                   .deleteCookies("remember-me", "JSESSIONID")
////                   .logoutSuccessUrl("/login");
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }
//
//    @Bean
//    public DaoAuthenticationProvider daoAuthenticationProvider(){
//        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(passwordEncoder);
//        provider.setUserDetailsService(applicationUserService);
//        return provider;
//    }
//
//}
