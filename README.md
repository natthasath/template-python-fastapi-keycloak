# 🎉 Template Python FastAPI Keycloak

Keycloak is an open-source identity and access management solution providing Single Sign-On (SSO), user federation, identity brokering, and social login. It supports OAuth 2.0, OpenID Connect, and SAML protocols, with customizable authentication and user management.

![version](https://img.shields.io/badge/version-1.0-blue)
![rating](https://img.shields.io/badge/rating-★★★★★-yellow)
![uptime](https://img.shields.io/badge/uptime-100%25-brightgreen)

### 🚀 Setup

```shell
echo API_KEY | sha256sum
```

| Reason                                 | Refresh Token | Access Token |
|----------------------------------------|--------------|--------------|
| Used to authenticate user sessions     | ✅ Yes       | ❌ No        |
| Has a short lifespan (short-lived)     | ❌ No        | ✅ Yes       |
| Can be used to revoke all tokens       | ✅ Yes       | ❌ No        |
| Prevents Token Reuse Attack            | ✅ Yes       | ❌ No        |

### 🏆 Run

- [http://localhost:8000/docs](http://localhost:8000/docs)
- [http://localhost:8000/subapi/docs](http://localhost:8000/subapi/docs)

```shell
docker-compose up -d
```
