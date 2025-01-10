---
title: "[FILMEET] OIDC VS OAuth"
date: 2025-01-08 16:00:00 +0900
categories: ["프로젝트", "FILMEET"]
tags: ["Spring Security", "OAuth2", "OIDC"]
description: "아직도 소셜로그인에 OIDC 적용 안하는 사람이 있어?"
comment: true
---

## 이야기에 앞서
LG Uplus 유레카 과정을 수료하면서, 프로젝트 발표회에서 모든 팀들이 OIDC에 대해서 모르고 있는 것 같아서 저번 최종 프로젝트 발표회에서 공유했었다.
그래서 발표했던 내용을 포스팅 해보려고 한다!

이 글에서 강조하고 싶은 내용은 소셜 로그인 즉 인증을 구현하려면 OIDC를 적극 활용하자는 것이다.



## OAuth 2.0 VS OpenID Connect(OIDC)

### OpenID Connect (OIDC) 란?
![oidc](https://velog.velcdn.com/images/junlight94/post/23bed3da-0ea8-4b04-b1fb-1d22ea877850/image.png){: width="972" height="589" .w-75 .normal}

OpenID Connect 1.0은 OAuth 2.0 [RFC6749] 프로토콜 위에 있는 간단한 `id 계층`이다.

즉, OAuth2.0 위에 개발된 유저의 **인증(Authentication)**에 초점을 맞춘 프로토콜이다.

### OAuth 2.0 이란?
![oauth](https://upload.wikimedia.org/wikipedia/commons/d/d2/Oauth_logo.svg){: width="972" height="589" .w-75 .normal}

#### OAuth 2.0 (RFC6749)

> OAuth 2.0은 `인가(Authorization)`를 위한 업계 표준 프로토콜입니다.
>
> OAuth 2.0은 웹 애플리케이션, 데스크톱 애플리케이션, 모바일 기기, 거실 장치 등 다양한 환경에 적합한 특정 인가 흐름을 제공하면서, 클라이언트 개발자에게 간단함을 제공합니다.


흔히 소셜 로그인에 사용된다고 알고 있는 OAuth는 권한허가를 처리하기 위해 만들어진 표준 프로토콜이다. Google 등 다양한 플랫폼에서 자신의 서비스를 외부 시스템에서 사용할 수 있게 제공해주기 위해서 생겨난 기술이다.
여기서 인가라는 것은 정확히 어떤 의미일까?

일상 생활에서는 인증과 인가를 혼용하여 사용하지만, 개발자는 헷갈리면 안되는 개념이다!

![auth](https://images.velog.io/images/djaxornwkd12/post/24d9f2d0-25c5-4949-bdfb-ae0f170d988a/security-authentication-user-authorization-websites.png){: width="972" height="589" .w-75 .normal}

인증은 사용자의 신원을 검증하는 행위이고, 인가는 리소스나 기능에 액세스할 수 있는 권한을 부여하는 것을 말한다.

예를들어, 전산부 소속 직원 이동현은 ID 카드를 통해서 본인임을 인증하고 전산실에 들어갈 수 있다.
하지만 전산실에 들어갈 수 있다고 해서 이동현임을 특정할 수는 없다.

즉, **인증 -> 인가**로 이어질 수 있지만

**인가 -> 인증**으로는 이어질 수 없다.

[또한, OAuth 진영에서 OAuth 기술은 Authentication 기술이 아니라고 명시합니다.](https://oauth.net/articles/authentication/)

## OAuth 2.0 으로 소셜 로그인을 구현하면 안되는가?
Nope! 실제로 국내에는 OIDC 프로토콜을 지원하는 곳이 카카오밖에 없어서 많은 소셜 로그인 기능이 OAuth 2.0을 활용하고 있다.

### OAuth 2.0 에서 인증이 가능한 이유
1. 사용자가 OAuth 2.0을 통해 로그인 요청
2. OAuth 제공자가 Access Token 발급
3. 서버가 Access Token을 사용하여 `/userinfo` API 요청
4. 응답받은 사용자 정보를 서버의 DB와 대조하여 로그인 처리
5. 이후 우리 서버에서 자체적인 JWT(Access Token)를 발급하여 인증 관리

위처럼 OAuth 2.0을 사용하더라도, Access Token을 직접 인증 수단으로 사용하지 않고 /userinfo API를 통해 사용자 정보를 확인한 후 자체적인 인증 시스템을 구축하면 보안적으로 문제가 없다.

## 🔥 OIDC를 활용하는 것이 더 좋은 이유
OIDC(OpenID Connect)는 OAuth 2.0을 확장하여 "사용자 인증(Authentication)" 기능을 추가한 프로토콜이다.
따라서, OAuth 2.0보다 보안성이 높고, 인증 과정이 더 간단하며, 서버 부하를 줄일 수 있다.

### ✅ 네트워크 요청 감소로 성능 향상
![flows](https://file.notion.so/f/f/51c7b4fb-08b6-453b-8338-ba68e6d944f1/6cb97050-e842-4815-bc34-843bd8b61182/image.png?table=block&id=9a62bae5-e75d-4d62-a2ac-c5fee7897b2d&spaceId=51c7b4fb-08b6-453b-8338-ba68e6d944f1&expirationTimestamp=1736344800000&signature=TFU6rJ2E7DlyQqVy4LOgXLb_j9IVWyYNeE891kzQ5l4&downloadName=image.png){: width="972" height="589" }
OIDC에서는 `/userinfo` API를 호출할 필요 없이 ID Token만으로 인증할 수 있으므로 네트워크 부하가 줄어든다.
즉, OAuth 2.0보다 로그인 속도가 빨라지고, 서버 부하가 감소한다.

#### 💡 비교

| OAuth 2.0 (OAuth Login) | OIDC (OIDC Login) |
|----------------|----------------|
| 사용자 정보 조회 방식 | `/userinfo` API 호출 필요 | ID Token 검증만 수행 |
| 네트워크 요청 | ✅ 추가 요청 발생 | ❌ 불필요 (서버 내부 검증 가능) |
| 성능 | 네트워크 지연 발생 가능 | 빠름 (서버 내부 검증) |

---

### ✅ 장점2. 서명 검증을 통한 보안성 향상
OIDC에서 제공하는 ID Token은 JWT(JSON Web Token) 형식이므로 서명을 검증하여 위변조된 토큰을 차단할 수 있다.
즉, 공격자가 Access Token을 탈취하더라도, ID Token 없이 로그인하는 것은 불가능하다.

🚀 **OAuth 2.0보다 보안이 강화되는 이유**
- ID Token에는 `iss`, `aud`, `sub` 등의 필드가 포함되어 있어 인증이 보다 신뢰할 수 있다.
  - ✅ 1. 발급자(iss) 확인 : 
    ID Token이 올바른 OpenID Provider(예: https://accounts.google.com)에서 발급된 것인지 확인.
    잘못된 iss 값을 가진 토큰을 차단할 수 있음.
  - ✅ 2. 클라이언트 대상(aud) 확인 : 해당 ID Token이 우리 서버(클라이언트 ID)용으로 발급된 것인지 확인. 공격자가 다른 서비스용 ID Token을 우리 서버에서 사용하려는 시도를 방지.
  - ✅ 3. 유효기간(exp) 확인 : ID Token이 만료되었는지 확인하여 공격자가 오래된 토큰을 재사용하는 것을 방지.
- JWT 서명을 검증하면 변조된 토큰을 사용할 수 없으므로, OAuth 2.0보다 안전하다.
- OAuth 2.0의 Access Token은 자체적으로 검증이 어렵지만, OIDC의 ID Token은 자체 검증이 가능하다.

#### 💡 OAuth 2.0과 OIDC 보안 차이

| | OAuth 2.0 (OAuth Login) | OIDC (OIDC Login) |
|----------------|----------------|----------------|
| 사용자 정보 보장 | `/userinfo` 응답을 신뢰해야 함 | ID Token 자체 검증 가능 |
| 위변조 방지 | ❌ Access Token 자체 검증 불가능 | ✅ ID Token 서명 검증 가능 |
| 탈취 대응 | Access Token 탈취 시 위험 | ID Token 없이 로그인 불가 |

---

### ✅ 장점3. Access Token과 ID Token의 역할 분리
OAuth 2.0에서는 Access Token만 제공되므로, API 인증과 사용자 인증의 경계가 모호하다.
하지만 OIDC에서는 ID Token은 사용자 인증에만 사용하고, Access Token은 API 접근을 위한 용도로 사용할 수 있다.

#### 💡 OAuth 2.0 vs OIDC 토큰 역할 비교

| | OAuth 2.0 | OIDC |
|----------------|----------------|----------------|
| 사용자 인증 | ❌ 직접 제공하지 않음 | ✅ ID Token 제공 |
| API 인증 | ✅ Access Token 사용 | ✅ Access Token 사용 |

📌 OIDC를 사용하면 인증(Authentication)과 인가(Authorization)를 명확하게 분리할 수 있어 보안성이 높아진다.

📌 OAuth 2.0에서는 Access Token이 유출되면 사용자 정보까지 노출될 위험이 있지만, OIDC에서는 ID Token 없이 Access Token만으로는 사용자 정보를 인증할 수 없다.

---

## 🎯 결론
✅ OAuth 2.0을 사용하더라도, `/userinfo` API를 활용하여 사용자 정보를 검증하고 서버에서 자체 JWT를 발급하는 방식을 적용하면 보안적으로 문제가 없다.

✅ 하지만, OIDC를 사용하면 ID Token을 통해 사용자 신원을 직접 검증할 수 있으므로 보안성이 더욱 강화된다.

✅ OIDC를 사용하면 `/userinfo` API를 호출하지 않아도 되므로 네트워크 요청이 줄어들고 성능이 향상된다. **Code Grant 기준 33% 감소**

✅ OAuth 2.0과 달리 OIDC는 ID Token을 통해 인증(Authentication)과 인가(Authorization)을 분리할 수 있어 더 안전하다.

💡 즉, OAuth 2.0도 올바르게 사용하면 보안적으로 괜찮지만, OIDC를 활용하면 인증 과정이 더 강력하고 안전해진다.

💡 가능하다면 OIDC를 지원하는 플랫폼에서는 OIDC를 사용하는 것이 권장된다. 🚀

OIDC를 적용하면 확장성 측면에서도 장점이 있지만, 그 내용을 포함에 어떻게 개발했는지 등의 내용은 다음 포스트에 작성하려고 한다!

