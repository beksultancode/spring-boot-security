package springbootsecurity;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.*;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.security.PermitAll;
import javax.persistence.*;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.*;

@SpringBootApplication
public class SpringBootSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityApplication.class, args);
    }
}

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
class UserController {

    private final UserRepository userRepository;

    // get all users
    @GetMapping
    @PermitAll
    List<User> findAll() {
        return userRepository.findAll();
    }

    // find user by id
    @GetMapping("/{userId}")
    @PermitAll
    User findById(@PathVariable Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(EntityNotFoundException::new);
    }

    // save new user
    @PostMapping
    @PermitAll
//    @PreAuthorize("hasAuthority('ADMIN')")
    User save(@RequestBody UserRequest userRequest) {
        User user = new User(userRequest);
        return userRepository.save(user);
    }

    // update user
    @PutMapping("/{userId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    User update(@PathVariable Long userId,
                @RequestBody UserRequest userRequest) {

        User user = userRepository.findById(userId)
                .orElseThrow(EntityNotFoundException::new);

        user.setName(userRequest.name());
        user.setEmail(userRequest.email());

        return userRepository.save(user);
    }

    // delete user
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('ADMIN')")
    Map<String, String> deleteById(@PathVariable Long userId) {

        if (!userRepository.existsById(userId)) throw new EntityNotFoundException();

        userRepository.deleteById(userId);

        return Map.of(
                "message", "User successfully deleted!"
        );
    }
}

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
class AuthenticationController {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    // login
    @PostMapping
    AuthResponse authenticate(@RequestBody AuthRequest authRequest) {

        User user = userRepository.customFindByEmail(authRequest.email())
                .orElseThrow(EntityNotFoundException::new);

        if (!user.getPassword().equals(authRequest.password())) {
            throw new IllegalStateException("Invalid password!");
        }

        String token = jwtService.generateToken(user.getEmail());

        return new AuthResponse(user.getEmail(), token);
    }
}

record AuthRequest(String email, String password) {
}

@Data
@NoArgsConstructor
@AllArgsConstructor
class AuthResponse {
    private String email;
    private String token;
}

record UserRequest(String name, String email, String password) {
}

@Entity
@Table(name = "users")
@Data
class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    public User() {
    }

    public User(UserRequest userRequest) {
        this.name = userRequest.name();
        this.email = userRequest.email();
        this.password = userRequest.password();
        this.role = Role.USER;
    }

    public User(Long id, String name, String email, String password, Role role) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }
}

enum Role implements GrantedAuthority {
    USER,
    ADMIN;

    @Override
    public String getAuthority() {
        return this.name();
    }
}

interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByEmail(String email);

    @Query("select u from User u where u.email = ?1")
    Optional<User> customFindByEmail(String email);

    @Query("select u from User u where u.email = :email")
    User customGetUserByEmail(@Param("email") String email);
}

@ConfigurationProperties(prefix = "app.security.jwt")
@Service
@Data
class JwtService {

    private String issuer;

    private String secret;

    private long expiresAt;

    // generate token
    public String generateToken(String email) {
        return JWT.create()
                .withIssuer(issuer)
                .withIssuedAt(new Date())
                .withClaim("email", email)
                .withExpiresAt(Date.from(ZonedDateTime.now().plusDays(expiresAt).toInstant()))
                .sign(Algorithm.HMAC512(secret));
    }

    // validate token
    public String verifyToken(String token) {
        return JWT.require(Algorithm.HMAC512(secret))
                .withIssuer(issuer)
                .build()
                .verify(token)
                .getClaim("email")
                .asString();
    }
}

@Configuration
class SwaggerConfig {

    private static final String API_KEY = "Bearer Token";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes(API_KEY, apiKeySecuritySchema())) // define the apiKey SecuritySchema
                .info(new Info().title("Security"))
                .security(Collections.singletonList(new SecurityRequirement().addList(API_KEY))); // then apply it. If you don't apply it will not be added to the header in cURL
    }

    public SecurityScheme apiKeySecuritySchema() {
        return new SecurityScheme()
                .name("Authorization") // authorisation-token
                .description("Just put the token")
                .in(SecurityScheme.In.HEADER)
                .type(SecurityScheme.Type.HTTP)
                .scheme("Bearer");
    }
}

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        prePostEnabled = true
)
class WebAppSecurity {

    @Bean
    @SneakyThrows
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, TokenFilter filter) {

        httpSecurity.cors().and().csrf().disable()
                .authorizeHttpRequests(authz -> {
                    authz.antMatchers("/api-docs", "/v3/api-docs")
                            .permitAll()
                            .anyRequest()
                            .permitAll();
                });

        httpSecurity.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}

@Component
class TokenFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    TokenFilter(JwtService jwtService,
                UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Optional<String> optionalToken = getTokenFromRequest(request);

        optionalToken.ifPresent(token -> {

            String email = jwtService.verifyToken(token);

            User user = userRepository.customFindByEmail(email)
                    .orElseThrow(EntityNotFoundException::new);

            userRepository.findAll().forEach(System.out::println);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    user.getEmail(),
                    null,
                    Collections.singletonList(user.getRole())
            );

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        });

        filterChain.doFilter(request, response);
    }

    private Optional<String> getTokenFromRequest(HttpServletRequest request) {

        String header = request.getHeader("Authorization"); // header = Bearer as;ldfj;welkcjfmawoijcfnoaijnfcoasifuh

        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return Optional.of(header.substring("Bearer ".length()));
        }

        return Optional.empty();
    }

}
