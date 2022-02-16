package com.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    //Sifremizi kodlayacak olan encoderin eklenmesi
    private PasswordEncoder passwordEncoder;
    //SecurityConfiguration classsinin constructori ve burda dependency injeksion yapiyorum
    @Autowired
    public SecurityConfiguration(PasswordEncoder passwordEncoder){
        this.passwordEncoder=passwordEncoder;
    }

    //Web securtityConfigurerAdapter icerisindeki HTTP secuirty metodunu override ediyorum
    @Override
    protected void configure(HttpSecurity http) throws Exception {

       // http.authorizeRequests().anyRequest().permitAll(); //sifereleri devre disi biraktm

        //http.authorizeRequests().anyRequest().authenticated();//Sifreleri devreye soktu

        http.
                csrf().disable().//Cross-Site=Request-Forgerybdisable yapinca out, post vs authize aktif olmadna da kullanilir ama tavsiye edilmez
                authorizeRequests().//Istekleri denetle
                antMatchers("/","index","css/*","js/*").permitAll().//bu sayfalara izin evr

                //-=========Role Based Authentication========/
                //USER rolune sahip kullanicinin erisebilcegi path in tanumlanmasi
                antMatchers("/kisiler").hasRole(KisiRole.USER.name()).
                //ADMIN rolune sahip olan kullanicinin eirsebilcegi path in tanimlanmasi
                antMatchers("/kisiler/**").hasRole(KisiRole.ADMIN.name()).
                anyRequest().//tum istekleri
                authenticated().//sifreli olarak kullan
                and().//Ve farkli islemleri birlestirmek icin
              //  formLogin().//form login sayfasi giris yapilsin
             //   and().//Ve farkli islemleri birlestirmek icin
                httpBasic(); //burda security i http i basic yontemi kullanmak istoyorum

    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails user1= User.builder().
                username("user").
                password(passwordEncoder.encode("1234")).
               // roles("USER").build();  //burda user 1 adinda bir user olusturduk. adi user sifesi 1234
                authorities(KisiRole.USER.name()).build();//Olusturdugumuz rolun kullanilmasi

        UserDetails admin1= User.builder().
                username("admin").
                password(passwordEncoder.encode("5678")).
                //roles("ADMIN").build();
                authorities(KisiRole.ADMIN.name()).build(); //Enumda olusturdugunuz rolun kullanilmasi
        return new InMemoryUserDetailsManager(user1,admin1);

    }
}
