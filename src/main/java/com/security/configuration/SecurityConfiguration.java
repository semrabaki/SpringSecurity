package com.security.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    //Web securtityConfigurerAdapter icerisindeki HTTP secuirty metodunu override ediyorum
    @Override
    protected void configure(HttpSecurity http) throws Exception {

       // http.authorizeRequests().anyRequest().permitAll(); //sifereleri devre disi biraktm

        //http.authorizeRequests().anyRequest().authenticated();//Sifreleri devreye soktu

        http.
                csrf().disable().//Cross-Site=Request-Forgerybdisable yapinca out, post vs authize aktif olmadna da kullanilir ama tavsiye edilmez
                authorizeRequests().//Istekleri denetle
                antMatchers("/","index","css/*","js/*").permitAll().//bu sayfalara izin evr
                anyRequest().//tum istekleri
                authenticated().//sifreli olarak kullan
                and().//Ve farkli islemleri birlestirmek icin
              //  formLogin().//form login sayfasi giris yapilsin
             //   and().//Ve farkli islemleri birlestirmek icin
                httpBasic(); //burda security i http i basic yontemi kullanmak istoyorum

    }
}
