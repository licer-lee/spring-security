package com.alex.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .permitAll();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin")
                .password("{bcrypt}$2a$10$aN7vmCEqzmsbAGIitTndA.zBRU/dyoI5Opx9ibwTIheVNBG9igHu6")
                .roles("USER");
    }

    /**
     * 指定一种密码编码方式
     * 指定密码编码，数据库中只要存储密文即可：例如
     * $2a$10$aN7vmCEqzmsbAGIitTndA.zBRU/dyoI5Opx9ibwTIheVNBG9igHu6
     * @return
     */
//    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 支持多种密码编码方式
     * 配置这种密码编码方式，数据库中存储密码时需要同时存储编码方式前缀：例如
     * {bcrypt}$2a$10$aN7vmCEqzmsbAGIitTndA.zBRU/dyoI5Opx9ibwTIheVNBG9igHu6
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoderSecond(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String encodePwd = bCryptPasswordEncoder.encode("admin");
        System.out.println("encodePwd = " + encodePwd);
    }
}
