---
title: "[FILMEET] 인증 인가 개발기"
date: 2025-01-10 12:00:00 +0900
categories: ["프로젝트", "FILMEET"]
tags: ["Spring Security", "OAuth2", "OIDC"]
description: "FILMEET 프로젝트 인증, 인가 시스템 설명"
comment: true
---

## 개발 이전의 목표

FILMEET 프로젝트에서는 Spring Security의 기본 기능을 최대한 활용하여 인증과 인가를 구현했으며, 특히 JWT, OAuth2, OIDC 등을 적용하면서 보안성과 확장성을 모두 고려했다.

이 글에서는 FILMEET 프로젝트의 인증 및 인가 설계 과정과 Spring Security의 기능을 최대한 활용하면서도 커스텀한 부분을 설명한다.


<br/>

### Spring Security 기능을 적극 활용해야 하는 이유
Spring Security는 복잡한 인증, 인가 시스템을 쉽게 구현할 수 있도록 도와주는 강력한 프레임워크이다.
즉, 개발자가 직접 구현하지 않아도 다양한 보안 기능을 손쉽게 활용할 수 있다.

이번에 인증/인가 시스템을 개발하면서 버그를 해결하는 과정에서 디버깅을 통해 알아낸 점은 생각보다 Spring Security가 많은 것을 도와주고 있었다는 것이었다.
예를 들어서 소셜 로그인을 개발할 때 CSRF, ID Token 재사용 공격 등을 막기 위한 값들을 자동으로 생성해서 넣어주는 것을 확인할 수 있었고,
Spring Security에서 제공하는 기능들을 최대한 활용하기 잘했다는 생각이 들었다.

state
: CSRF(Cross-Site Request Forgery) 공격을 방지하기 위해 사용

|    단계     | 관련 클래스 | 역할 |
|:---------:|:------:|:--:|
| `state`생성 |    `OAuth2AuthorizationRequestRedirectFilter`    |  	`OAuth2AuthorizationRequest`를 생성할 때 `state` 값을 생성  |
|     `state` 저장      |    `HttpSessionOAuth2AuthorizationRequestRepository`    |  생성된 `state` 값을 세션에 저장  |
|     `state` 검증      |    `OAuth2LoginAuthenticationFilter`    |  Authorization Server에서 받은 `state` 값을 세션 값과 비교  |

nonce
: ID Token 재사용 공격 방지

Nonce 역시 디버깅을 통해 비슷한 방식으로 동작함을 확인할 수 있었다.

<br/>

### 인증 인가 구성
우리 프로젝트의 인증 및 인가는 Spring Security + JWT + OAuth2(OIDC 포함)으로 구성되었다.
이러한 구성을 선택한 이유는 아래와 같다.


✅ 왜 Spring Security + JWT + OAuth2(OIDC 포함) 인증 구조를 선택했는가?
1. SPA + REST API 기반 인증 방식에 최적화 됨
   : 서버 세션 관리 없이 인증 유지 가능 (Stateless)
2. JWT 인증으로 서버 확장성 확보
   : 백엔드 서버에 Auto Scaling이 적용되어 있어 global cache(Redis) + JWT 적용
3. Spring Security 강력한 보안 기능과 권한 관리 기능
   : 빠른 개발을 도울뿐만 아니라 강력한 기능들을 제공함

<br/>

## Spring Security 설정 코드

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http, RoleHierarchy roleHierarchy) throws Exception {
    http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .formLogin(formLogin -> formLogin.disable())
            .httpBasic(httpBasic -> httpBasic.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .oauth2Login(oauth2 -> oauth2
                    .authorizationEndpoint(authorization -> authorization
                            .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository))
                    .userInfoEndpoint(
                            userInfo -> userInfo.oidcUserService(customOidcUserService) // OIDC Flow (Google)
                                    .userService(customOAuth2UserService))// OAuth2 Flow (Naver)

                    .successHandler(
                            (request, response, authentication) -> oAuth2AuthenticationSuccessHandler.onAuthenticationSuccess(
                                    request, response, authentication)))

            .addFilterAfter(jwtAuthenticationFilter, ExceptionTranslationFilter.class)

            .exceptionHandling(handler -> handler
                    .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                    .accessDeniedHandler(customAccessDeniedHandler))

      ...
```

### 각 설정 설명

### 🔹 Authorization Endpoint 설정
- OAuth2 인가 요청 정보를 **쿠키에 저장**하기 위해 `HttpCookieOAuth2AuthorizationRequestRepository` 사용
- OAuth2 로그인 시 인가 코드 요청 정보(state, redirect URI 등)를 유지하기 위해 쿠키를 활용
- 세션 없이(stateless) OAuth2 인증을 수행하도록 구현.

#### ✅ OAuth2 로그인 흐름에서 이 설정이 필요한 이유
1. 사용자가 `http://localhost:8080/oauth2/authorize/google` 같은 URL을 요청하면
2. Spring Security는 **인가 요청 객체(OAuth2AuthorizationRequest)** 를 생성하고, `state` 값을 포함하여 OAuth2 공급자로 리디렉션한다.
3. Session이 Stateless로 설정되어 있기 때문에 인가 요청 객체를 세션 대신 **쿠키에 저장**하고, OAuth2 인증 완료 후 이를 다시 불러온다.

---

### 🔹 User Info Endpoint 설정
- **OAuth2 로그인 후 사용자 정보를 가져오는 부분**
- `Google`과 같은 OIDC 기반 인증은 `customOidcUserService` 에서 처리
- `Naver`와 같은 OAuth2 기반 인증은 `customOAuth2UserService` 에서 처리

#### ✅ OIDC와 OAuth2를 구분하는 이유
- OIDC를 지원하지 않는 플랫폼이 존재하기 때문
- **OIDC (OpenID Connect)** 는 `IdToken`을 반환하여 **ID 인증**이 포함됨
- **OAuth2** 는 인증이 아니라 **권한 위임** 방식이므로 추가적으로 `userInfo` API 호출이 필요함

---

### 🔹 Success Handler 설정
- **인증 성공 시 실행할 핸들러를 지정**
- `oAuth2AuthenticationSuccessHandler` 에서는 **JWT를 생성하여 반환하는 로직**이 포함됨
- 즉, **다양한 인증 방식 이후 JWT를 발급하고, 프론트엔드로 전달하는 역할**

#### ✅ OAuth2 로그인 흐름에서 성공 핸들러가 하는 일
1. 로그인 성공 후 Spring Security는 **인증 객체를 생성**
2. `oAuth2AuthenticationSuccessHandler.onAuthenticationSuccess()` 가 실행됨
3. **JWT를 생성하여 Set-Cookie 혹은 JSON Response 로 반환**
4. 프론트엔드는 받은 JWT를 저장하고 이후 API 요청에서 사용

---

### 🔹 JWT 인증 필터 설정
- JWT 기반 인증을 위해 커스텀 필터를 추가
- ExceptionTranslationFilter 뒤에 추가하여, 인증 예외 발생 시 Spring Security의 예외 처리 기능을 활용할 수 있도록 설정

#### ✅ JWT 필터가 수행하는 역할
1. 요청이 들어오면, 헤더에서 Authorization Bearer 토큰을 추출
2. 토큰이 유효하면, Security Context에 Authentication 객체를 저장

#### ⚠ 커스텀 인증 필터는 어디에 위치해야 하는가?
> `ExecptionTranslationFilter`는 인증 및 인가 과정에서 발생하는 예외를 처리하기 때문에 Security의 공통 예외 처리를 사용 유무에 따라 해당 필터의 앞에 둘 것인지 뒤에 둘 것인지 결정
{: .prompt-warning }

> `FilterSecurityInterceptor` 최종적인 권한 검사를 수행하는 필터로 인증 필터는 미리 완료되어야하므로 해당 필터 앞에 위치해야함
{: .prompt-warning } 

결론적으로 Spring Security 로그 레벨을 DEBUG로 설정하면 내 Security 설정에 따라 변경된 Filter Chain을 확인할 수 있다.

인증 필터의 시작이 어디인지 직접 확인하고, 가장 많이 활용되는 필터를 가장 앞에 두면 효율적으로 사용할 수 있다.

Security의 로그 레벨 설정하는 법 (택 1)
1. Security Config에 `@EnableWebSecurity(debug = true)`
2. application.yml에 `spring.security.debug=true`

---

### 🔹 예외 처리 (exceptionHandling)

#### ✅ authenticationEntryPoint (인증 예외 처리)
- 요청이 인증에 실패하면 실행되는 로직
- ID 로그인, 소셜 로그인, JWT 인증 모두 실패하면 실행

#### ✅ accessDeniedHandler (인가 예외 처리)
- 인증은 되었지만, 해당 리소스에 대한 권한이 부족할 경우 실행되는 로직
- 일반 사용자가 관리자 페이지에 접근하려고 하는 경우 등

<br/>
<br/>

---
<br/>

## 커스텀 JWT 필터 구현
`OncePerRequestFilter`를 상속받아 JwtAuthenticationFilter를 구현하였다.

이 필터는 매 요청마다 실행되며, JWT를 추출하여 인증을 처리한다. `OncePerRequestFilter`를 사용한 이유는 인증 요청 시 포워딩 등의 과정에서 필터가 여러 번 실행되지 않도록 하여 자원 낭비를 줄이기 위함이다.

🔹 특징
- `OncePerRequestFilter`를 상속받아 매 요청마다 JWT를 검증
- `jjwt` 라이브러리를 활용하여 JWT 생성 및 검증 수행
- 서버가 오토스케일링이 적용되어 있기 때문에 글로벌 캐시(Redis)를 활용하여 Refresh Token을 저장

### JwtAuthenticationFilter 코드
```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserQueryService userQueryService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = resolveToken(request);

        if (token != null) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    Authentication authentication = getAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (ExpiredJwtException e) {
                throw new AccessTokenExpiredException(e.getMessage());
            } catch (Exception e) {
                throw new JwtAuthenticationException(e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private Authentication getAuthentication(String token) {
        String tokenUsername = jwtTokenProvider.getUsername(token);
        User user = userQueryService.findByUsername(tokenUsername);

        return new UsernamePasswordAuthenticationToken(
                user,
                null,
                user.getRole().getAuthorities()
        );
    }
}
```

## ID / Password 로그인 구현
일반 ID 로그인 및 관리자 로그인을 지원하기 위한 기능

### IdPwAuthenticationService 코드

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class IdPwAuthenticationService {

    private final UserQueryService userQueryService;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public LoginResponse authenticate(LoginRequest request) {
        User user = userQueryService.findByUsername(request.username());

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new InvalidPasswordException("Password is not matched");
        }
        TokenResponse tokens = tokenService.generateTokens(
                new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getRole().getAuthorities())
        );
        LoginResponse loginResponse = new LoginResponse(user.isFirstLogin(), tokens);
        user.setFirstLoginFalse();

        // Access/Refresh Token 생성
        return loginResponse;
    }
}
```

## 소셜 로그인 구현
Spring Security에서 이미 강력한 소셜 로그인 기능을 지원하기 때문에
우리는 알맞는 클래스를 상속받고, `application.yml`에 설정 값과 우리 서비스 DB에서 유저 정보를 받아오는 메소드만 재정의하면 된다.

OAuth 2.0, OpenID Connect의 차이는 아래의 이전 포스팅을 참고!
<article class="col">
  <a href="/posts/oauth-oidc/" class="post-preview card h-100">
    <div class="card-body">
      <h4 class="pt-0 my-2">[FILMEET] OIDC VS OAuth</h4>
      <div class="text-muted">
        <p>아직도 소셜로그인에 OIDC 적용 안하는 사람이 있어?</p>
      </div>
    </div>
  </a>
</article>

<br/>

### HttpCookieOAuth2AuthorizationRequestRepository 코드
```java
@Component
@Slf4j
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "OAUTH2_AUTHORIZATION_REQUEST";

    private final String cookieName;

    private final int cookieExpireSeconds;

    public HttpCookieOAuth2AuthorizationRequestRepository() {
        this(OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, 180);
    }

    public HttpCookieOAuth2AuthorizationRequestRepository(String cookieName, int cookieExpireSeconds) {
        this.cookieName = cookieName;
        this.cookieExpireSeconds = cookieExpireSeconds;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getCookie(request)
                .map(this::getOAuth2AuthorizationRequest)
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            getCookie(request).ifPresent(cookie -> clear(cookie, response));
        } else {
            String value = Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(authorizationRequest));
            Cookie cookie = new Cookie(cookieName, value);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            cookie.setMaxAge(cookieExpireSeconds);
            response.addCookie(cookie);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        return getCookie(request)
                .map(cookie -> {
                    OAuth2AuthorizationRequest oauth2Request = getOAuth2AuthorizationRequest(cookie);
                    clear(cookie, response);
                    return oauth2Request;
                })
                .orElse(null);
    }

    private Optional<Cookie> getCookie(HttpServletRequest request) {
        return ofNullable(WebUtils.getCookie(request, cookieName));
    }

    private void clear(Cookie cookie, HttpServletResponse response) {
        cookie.setValue("");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private OAuth2AuthorizationRequest getOAuth2AuthorizationRequest(Cookie cookie) {
        return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(
                Base64.getUrlDecoder().decode(cookie.getValue())
        );
    }

}
```


### CustomOAuth2UserService 코드
```java
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final UserCommandService userCommandService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 기본 사용자 정보 로드
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // registrationId로 Provider 식별
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Provider provider = Provider.fromName(registrationId)
                .orElseThrow(() -> new OAuth2AuthenticationException("Unsupported OAuth2 Provider: " + registrationId));

        // 사용자 정보 매핑
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String providerId;
        String name;
        String profileImage;

        switch (provider) {
            case NAVER -> {
                Map<String, Object> response = (Map<String, Object>) attributes.get("response");
                providerId = provider.getName() + "_" + response.get("id");
                name = (String) response.get("name");
                profileImage = (String) response.get("profile_image");
            }
            default -> throw new OAuth2AuthenticationException("Unsupported OAuth2 Provider: " + registrationId);
        }

        User user = userRepository.findByUsername(providerId)
                .orElseGet(() -> userCommandService.createTemporaryUser(
                        providerId, name, Provider.NAVER, profileImage));


        // 권한 설정
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getRole().name()));
        Map<String, Object> copyAttributes = new HashMap<>(oAuth2User.getAttributes());
        copyAttributes.put("id", providerId);

        return new CustomOAuth2User(
                oAuth2User.getAuthorities(),
                copyAttributes,
                "id",
                providerId
        );
    }
}

```

OAuth 2.0  플랫폼마다 원하는 정보의 파라미터의 명칭이 다를 수 있으므로 `Provider`라는 Enum 클래스와 Switch문을 활용하여 새로운 
인증 제공자를 추가하기 쉬운 구조로 개발하였다.

### CustomOidcUserService 코드

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final UserCommandService userCommandService;
    private final UserRepository userRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        log.info("oidcUser: {}", oidcUser);

        // ID 토큰과 claims 추출
        OidcIdToken idToken = oidcUser.getIdToken();
        Map<String, Object> claims = idToken.getClaims();

        // iss 값으로 Provider 확인
        String issuer = claims.get("iss").toString();
        Provider provider = Provider.fromIssuer(issuer);

        // Provider에서 nameKey 가져와서 사용자 이름 동적 추출
        String tmpProviderId = claims.get("sub").toString();
        String name = claims.getOrDefault(provider.getNameKey(), "name").toString();
        String picture = claims.getOrDefault("picture", "profile_image").toString();

        String providerId = provider.getName() + "_" + tmpProviderId;

        // 사용자 조회 또는 임시 사용자 생성
        User user = userRepository.findByUsername(providerId)
                .orElseGet(() -> userCommandService.createTemporaryUser(
                        providerId, name, provider, picture));

        // 권한 설정
        Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getRole().name()));

        return new CustomOidcUser(
                oidcUser.getAuthorities(),
                idToken,
                oidcUser.getUserInfo(),
                providerId
        );
    }
}
```

OIDC는 OAuth와 다르게 ID Token에 포함되는 정보가 정해져있기 때문에 인증 제공자를 추가하는 것이 OAuth 2.0에 비해 굉장히 쉽다.

실제로 Google 로그인을 개발한 이후에 Kakao 로그인을 추가하는데 30분 정도 소요됐다!

또한 OAuth Code Grant 방식 기준 외부 API 호출이 33% 감소되어 훨씬 효율적이다.

빨리 Naver 등 다른 플랫폼에서도 OIDC를 지원했으면 좋겠다.

(현재 ISO/IEC, IETF에서 공식 인증 프로토콜로 지정 중!)

<br/>

## 인증 및 인가 예외 처리

### 개발 중 만난 문제 상황

**❌ 문제점**
- Tomcat의 기본 예외 메시지가 반환되는 문제가 발생했다.
- 프로젝트에서 GlobalAdvice를 통해 공통적인 예외 처리를 하려고 했으나, Spring Security의 필터 체인이 Dispatcher Servlet 외부에서 실행되기 때문에 커스텀 예외 처리가 적용되지 않았다.

.

**🔹 인증 및 인가 예외 처리에서의 Trade-off 고민**
예외 처리 방식에서 성능과 개발 생산성 사이에서 균형을 맞추는 것이 핵심 고민이었다.

- 옵션 1: Spring Security 필터 체인 내부에서 모든 예외를 처리하여 최대한 빠르게 응답할 수 있도록 한다.
  - ✅ 장점: 불필요한 컨트롤러 호출 없이 성능 최적화 가능
  - ❌ 단점: GlobalAdvice에서 일관된 예외 처리가 어렵고, 예외 처리 방식이 분산될 가능성이 있음
- 옵션 2: 예외를 컨트롤러까지 전달하여 GlobalAdvice를 통해 일관된 방식으로 처리한다.
  - ✅ 장점: 모든 예외를 하나의 예외 처리 로직에서 관리 가능 → 유지보수 용이
  - ❌ 단점: 컨트롤러까지 예외를 전달하는 과정에서 미미한 성능 저하 가능

**🎯 결정**

프로젝트의 특성상 짧은 기간 동안 빠르게 개발을 진행해야 했기 때문에 일관된 예외 처리가 더 중요하다고 판단했다.
이에 따라 예외를 컨트롤러까지 넘기는 방식으로 개발하여, 일관된 예외 메시지를 반환하고,
팀원 모두가 예외를 편하게 관리할 수 있었다.

### JwtAuthenticationEntryPoint 코드

```java
@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final HandlerExceptionResolver resolver;

    public JwtAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        log.error("Exception in JwtAuthenticationEntryPoint: {}", authException.getMessage());
        log.error("getCause = {}", authException.getCause());
        resolver.resolveException(request, response, null, authException);
    }
}
```

### CustomAccessDeniedHandler 코드

```java
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final HandlerExceptionResolver resolver;

    public CustomAccessDeniedHandler(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        resolver.resolveException(request, response, null, accessDeniedException);
    }
}
```

## 권한 설계

초기 서비스 설계 시, 사용자의 역할을 어린이 계정, 성인 계정, 관리자 계정으로 구분했지만, 관리자가 수행해야 할 작업이 매우 다양했다.

영화 관리, 리뷰 관리, 외부 API 호출 등 다양한 업무를 고려했을 때, 실제 서비스 운영을 위해 더욱 세분화된 권한 구조가 필요했다.

**🔹 권한 모델의 설계 방식**
1. Permission (행위 단위 권한)
   - 특정 기능을 수행할 수 있는 최소 단위의 권한 (예: 영화 추가, 리뷰 삭제 등)
2. PrivilegeSets (권한 묶음)
   - 여러 개의 Permission을 조합하여 특정 역할이 수행할 수 있는 작업 범위를 정의
3. Role (역할)
   - PrivilegeSets를 하나 이상 포함하여 역할을 정의 (예: 영화 관리자, 리뷰 관리자 등)

**🔹 계층 구조 적용**
- 역할 관리가 용이하도록 권한에 계층 구조를 부여하여, 상위 역할이 하위 역할의 권한을 포함하도록 설계했다.
- 이를 통해 새로운 역할을 추가하거나 기존 역할을 확장할 때 중복된 권한 설정 없이 쉽게 관리할 수 있도록 구성하였다.

### Permission 코드
```java
@Getter
public enum Permission {
    // 공통 권한
    COMMON_READ("COMMON_READ_AUTHORITY"),
    COMMON_CREATE("COMMON_CREATE_AUTHORITY"),
    COMMON_UPDATE("COMMON_UPDATE_AUTHORITY"),
    COMMON_DELETE("COMMON_DELETE_AUTHORITY"),

    // 성인 권한
    ADULT_READ("ADULT_READ_AUTHORITY"),

    // 영화 관련 권한
    MOVIE_CREATE("MOVIE_CREATE_AUTHORITY"),
    MOVIE_UPDATE("MOVIE_UPDATE_AUTHORITY"),
    MOVIE_DELETE("MOVIE_DELETE_AUTHORITY"),
    MOVIE_RECOMMEND("MOVIE_RECOMMEND_AUTHORITY"),

    // 리뷰 관련 권한 (예: 모든 리뷰 조회, 블라인드 처리)
    REVIEW_READ_ALL("REVIEW_READ_ALL_AUTHORITY"),
    REVIEW_BLIND("REVIEW_BLIND_AUTHORITY"),

    // 외부 API 관련 권한
    EXTERNAL_API_READ("EXTERNAL_API_READ_AUTHORITY");

    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }
}
```

### PrivilegeSets 코드
```java
public class PrivilegeSets {
    // 관리자용 영화 관련 권한 집합
    public static final Set<Permission> ADMIN_MOVIE_PRIVILEGES = Set.of(
            Permission.MOVIE_CREATE,
            Permission.MOVIE_UPDATE,
            Permission.MOVIE_DELETE,
            Permission.MOVIE_RECOMMEND
    );

    // 관리자용 외부 API 관련 권한 집합
    public static final Set<Permission> ADMIN_EXTERNAL_API_PRIVILEGES = Set.of(
            Permission.EXTERNAL_API_READ
    );

    // 관리자용 리뷰 관련 권한 집합
    public static final Set<Permission> ADMIN_REVIEW_PRIVILEGES = Set.of(
            Permission.REVIEW_READ_ALL,
            Permission.REVIEW_BLIND
    );

    // 성인 유저 추가 권한 집합
    public static final Set<Permission> ADULT_USER_PRIVILEGES = Set.of(
            Permission.ADULT_READ
    );

    // 일반 유저가 가지는 공통 권한 집합
    public static final Set<Permission> USER_COMMON_PRIVILEGES = Set.of(
            Permission.COMMON_READ,
            Permission.COMMON_CREATE,
            Permission.COMMON_UPDATE,
            Permission.COMMON_DELETE
    );

}

```

### Role 코드
```java
@Getter
public enum Role {
    ROLE_MINOR_USER(
            USER_COMMON_PRIVILEGES
    ),
    ROLE_ADULT_USER(
            Stream.of(ADULT_USER_PRIVILEGES)
                    .flatMap(Set::stream).collect(Collectors.toSet())
    ),
    ROLE_MOVIE_ADMIN(
            Stream.of(ADMIN_MOVIE_PRIVILEGES, ADMIN_EXTERNAL_API_PRIVILEGES)
                    .flatMap(Set::stream).collect(Collectors.toSet())
    ),
    ROLE_REVIEW_ADMIN(
            Stream.of(ADMIN_REVIEW_PRIVILEGES)
                    .flatMap(Set::stream).collect(Collectors.toSet())
    ),
    ROLE_SUPER_ADMIN(Collections.emptySet());

    private final Set<Permission> permissions;
    private static RoleHierarchy roleHierarchy;

    public static void setRoleHierarchy(RoleHierarchy hierarchy) {
        roleHierarchy = hierarchy;
    }

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public List<SimpleGrantedAuthority> getAuthorities() {
        List<Role> reachableRoles = roleHierarchy.getReachableGrantedAuthorities(
                        List.of(new SimpleGrantedAuthority(this.name()))
                ).stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_")) // ROLE_XXX만 필터링
                .map(Role::valueOf)
                .toList();

        List<SimpleGrantedAuthority> authorities = reachableRoles.stream()
                .flatMap(role -> role.permissions.stream())
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());

        reachableRoles.stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .forEach(authorities::add);

        return authorities;
    }
}
```

### RoleHierarchy (Security Config) 코드
```java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();

    // 계층 설정
    String hierarchy = """
            ROLE_SUPER_ADMIN > ROLE_MOVIE_ADMIN
            ROLE_SUPER_ADMIN > ROLE_REVIEW_ADMIN
            ROLE_MOVIE_ADMIN > ROLE_ADULT_USER
            ROLE_REVIEW_ADMIN > ROLE_ADULT_USER
            ROLE_ADULT_USER > ROLE_MINOR_USER
            """;

    roleHierarchy.setHierarchy(hierarchy);

    Role.setRoleHierarchy(roleHierarchy);

    return roleHierarchy;
}
```
