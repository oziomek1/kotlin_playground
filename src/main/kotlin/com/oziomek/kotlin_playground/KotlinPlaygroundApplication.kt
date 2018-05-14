package com.oziomek.kotlin_playground

import org.hibernate.SessionFactory
import org.hibernate.annotations.FetchMode
import org.hibernate.annotations.FetchProfile
import org.hibernate.annotations.FetchProfiles
import org.hibernate.criterion.Restrictions
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Controller
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import javax.persistence.*
import javax.transaction.Transactional

@SpringBootApplication
class KotlinPlaygroundApplication

fun main(args: Array<String>) {
    runApplication<KotlinPlaygroundApplication>(*args)
}

@Entity
data class Roles(@field: Id @field: GeneratedValue var id: Int = 0,
                 @field: ManyToOne(targetEntity=BasicUser::class) var user : BasicUser,
                 var role : String = "")

@FetchProfiles(
        FetchProfile(name = "default",
                fetchOverrides = arrayOf(
                        FetchProfile.FetchOverride(entity = BasicUser::class, association = "roles", mode = FetchMode.JOIN)
                ))
)
@Entity
data class BasicUser(@field: Id @field: GeneratedValue var id: Int = 0,
                    var userName: String = "",
                    var password: String = "",
                    var enabled: Boolean = true,
                    var accountNonExpired: Boolean = true,
                    var credentialsNonExpired: Boolean = true,
                    var accountNonLocked: Boolean = true,
                    @field: OneToMany(targetEntity = Roles::class) var roles: MutableCollection<Roles> = mutableSetOf()) {

    fun toCommonUser() : User {
        var authorities = mutableListOf<GrantedAuthority>()
        roles.forEach { authorities.add(SimpleGrantedAuthority(it.role)) }
        return User(userName, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities)
    }
}

@Configuration
class DataConfig {
    @Bean
    fun sessionFactory(@Autowired entityManagerFactory: EntityManagerFactory) :
            SessionFactory = entityManagerFactory.unwrap(SessionFactory::class.java)
}

@Transactional
@Service
class UserService(@Autowired private val userRepository: UserRepository) : UserDetailsService {

    override fun loadUserByUsername(userName: String): UserDetails  = userRepository.loadByName(userName).toCommonUser()

    fun saveOrUpdate(user: BasicUser) {
        user.password = BCryptPasswordEncoder().encode(user.password)
        userRepository.saveOrUpdate(user)
    }

    fun loadAllUsers() = userRepository.loadAllUsers()
}

@Repository
class UserRepository(@Autowired private val sessionFactory: SessionFactory){

    fun saveOrUpdate(user: BasicUser) {
        sessionFactory.currentSession.saveOrUpdate(user)
    }

    fun loadByName(userName: String) : BasicUser =
            sessionFactory.currentSession.createCriteria(BasicUser::class.java, "su")
                    .add(Restrictions.eq("su.userName", userName)).uniqueResult() as BasicUser
    }

    @Suppress("DEPRECATION")
    fun loadAllUsers(profile : String = "default") : List<BasicUser> {
        val session = sessionFactory.currentSession
        session.enableFetchProfile(profile)
        return session.createCriteria(BasicUser::class.java).list() as List<BasicUser>
    }
}

@Configuration
class SecurityConfig(@Autowired private val userService: UserService) : WebSecurityConfigurerAdapter() {

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(userService).passwordEncoder(BCryptPasswordEncoder())
    }

    override fun configure(http: HttpSecurity) {
        http
                .formLogin()
                .and()
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/main")
                .authenticated()
                .anyRequest()
                .permitAll()
    }
}

@Controller
@RequestMapping("/signup")
class RegisterController(@Autowired private val userService: UserService) {

    @RequestMapping(method = arrayOf(RequestMethod.POST))
    fun doPost(user : BasicUser) : String {
        userService.saveOrUpdate(user)
        return "redirect:/main"
    }

    @RequestMapping(method = arrayOf(RequestMethod.GET))
    fun doGet(model : Model) : String {
        model.addAttribute("user", BasicUser())
        return "signup"
    }
}

@Controller
@RequestMapping("/main")
class UserMain(@Autowired private val userService: UserService) {

    @RequestMapping(method = arrayOf(RequestMethod.GET))
    fun doGet(model : Model) : String {
        model.addAttribute("users", userService.loadAllUsers())
        return "main"
    }
}