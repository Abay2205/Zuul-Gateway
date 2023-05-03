package com.example.zuulgateway.security;

import com.example.zuulgateway.Filter.CustomAuthenticationFilter;
import com.example.zuulgateway.Filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
//        customAuthenticationFilter.setFilterProcessesUrl("/login1");
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new CustomAuthenticationFilter(authenticationManagerBean()))
                .addFilterAfter(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/zuul/login/**", "/zuul/auth/token/refresh/**").permitAll()
                .antMatchers(HttpMethod.GET, "/zuul/auth/useers/**").hasAnyRole("User")
                .antMatchers(HttpMethod.POST, "/auth/user/save/**").permitAll()
                .antMatchers(HttpMethod.DELETE, "/auth/delete/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.PUT, "/auth/update/**").hasAnyAuthority("Admin")

                .antMatchers(HttpMethod.GET, "/back1/**").hasAnyAuthority("Admin", "User")
                .antMatchers(HttpMethod.PUT, "/back1/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.DELETE, "/back1/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.POST, "/back1/**").hasAnyAuthority("Admin")

                .antMatchers(HttpMethod.GET, "/back3/**").hasAnyAuthority("Admin", "User")
                .antMatchers(HttpMethod.PUT, "/back3/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.DELETE, "/back3/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.POST, "/back3/**").hasAnyAuthority("Admin")

                .antMatchers(HttpMethod.GET, "/back2/**").hasAnyAuthority("Admin", "User")
                .antMatchers(HttpMethod.PUT, "/back2/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.POST, "/back2/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.DELETE, "/back2/**").hasAnyAuthority("Admin")

                .antMatchers(HttpMethod.GET, "/back10/**").hasAnyAuthority("Admin", "User")
                .antMatchers(HttpMethod.PUT, "/back10/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.POST, "/back10/**").hasAnyAuthority("Admin")
                .antMatchers(HttpMethod.DELETE, "/back10/**").hasAnyAuthority("Admin")
//                .antMatchers("/zuul/back1/**").hasAnyRole("ROLE_USER1", "ROLE_ADMIN1")
//                .antMatchers("/zuul/back2/**").hasAnyRole("ROLE_USER1", "ROLE_ADMIN1")
//                .antMatchers("/zuul/back3/**").hasAnyRole("ROLE_USER1", "ROLE_ADMIN1")
                .anyRequest()
                .authenticated();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
