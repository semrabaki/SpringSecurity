package com.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity //Klasik web guvenligini aktif hale getirir
@EnableGlobalMethodSecurity(prePostEnabled = true) //Method based authentication annotasynlarini etkin hale getirir
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
                antMatchers("/","index","css/*","js/*").permitAll().
                // ==================== ROLE-BASED AUTHENTICATION =====================
                // USER rolune sahip kullanicinin eri??ebilece??i path'in tan??mlanmas
//                antMatchers("/kisiler").hasRole(KisiRole.USER.name()).
//                // ADMIN rolune sahip olan kullanicinin eri??ebeilce??i paty in tanimlanmasi
//                antMatchers("/kisiler/**").hasRole(KisiRole.ADMIN.name()).

                // ==================== METHOD-BASED AUTHENTICATION =====================
                // Metot-tabanl?? kimlik denetimi i??in yap??lmas?? gereken ad??mlar.
                // 1- @EnableGlobalMethodSecurity(prePostEnabled = true) anotasyonunun Security
                //    class'??na konulmas?? gerekir.
                // 2- Rollerin ROLE_ISIM ??eklinde tan??mlanmas?? gerekir. Bunlar hard-coded olabilece??i
                //    gibi KisiRole i??erisinde varolan rollerin kullan??lmasi ile de olabilir.
                //    Tabi bunun i??in Enum olan role isimleri ile sabit "ROLE_" kelimesini birle??irecek bir
                //    metot yazmak gerekir.
                // 3- UserDetailService metodu i??erisinde ki??ilerin roles() tan??mlamalar??n?? authorities() olarak ,
                //    de??i??tirmeli ve KisiRole isimlerini ROLE_ISIM ??eklinde almak i??in KisiRole i??erisinde yazd??????m??z
                //    metotu kullanmal??y??z.
                // 4- ??zinleri ayarlamak i??in KisiContorller'a giderek metot ba????na hangi Rollere izin verilece??ini
                //    belirlemek gerekmektedir.Bunun i??in  @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
                //    anotasyonu kullan??labilir.
                        anyRequest().               // tum istekleri
                authenticated().            // ??ifreli olarak kullan
                and().                      // VE farkl?? i??mleri birle??tirmek i??in
                httpBasic().and().          // basic http kimlik denetimini kullan
                formLogin().                // form login sayfasi giri?? yap??lsin

                // === kendi login sayfam??z?? kullanmak i??in======
                // 1- Webapp klas??r??nde yeni login.html sayfas?? olu??turlur.
                //  2- HomeController i??erisinde bir RequestMapping metodu ile path tan??mlan??r
                //  3- SecurityConfig i??erisinde loginPage(/login) metodu ile aktif hale getirilir.
                        loginPage("/login").permitAll().
                 defaultSuccessUrl("/success").and().
                 logout().                       //logout yap??l??nca ??ifre vb. bilgileri sil.
                clearAuthentication(true).      // ??ifrelemeleri sil.
                invalidateHttpSession(true).    // Http oturmunu bitir
                deleteCookies("JESSIONID").     // session id'yi sil
                logoutSuccessUrl("/login").permitAll();    // logout sonras??nda tekrardan login'e y??nlendir.

    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

        UserDetails user1= User.builder().
                username("user").
                password(passwordEncoder.encode("1234")).
               // roles("USER").build();  //burda user 1 adinda bir user olusturduk. adi user sifesi 1234
              //  roles(KisiRole.USER.name()).build();//Olusturdugumuz rolun kullanilmasi
                      authorities(KisiRole.USER.otoriteleriAl()).build();  //method based role tahisis

        UserDetails admin1= User.builder().
                username("admin").
                password(passwordEncoder.encode("5678")).
                //roles("ADMIN").build();             //Hard coded role tahisis
              // roles(KisiRole.ADMIN.name()).build();// Enumda olusturdugunuz rolun kullanilmasi
              authorities(KisiRole.ADMIN.otoriteleriAl()).build();  //method based role tahisis

        return new InMemoryUserDetailsManager(user1,admin1);

    }
}
