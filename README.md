# YipyipExAuth

YipyipExAuth is an opinionated session manager for Elixir based on stateless access- and stateful refresh (Phoenix) tokens aimed at browser- and native clients that communicate with an Elixir API.

#### Problems solved

This package attempts to solve the following issues:

- tokens in LocalStorage are less secure than cookies, given that CSRF can be protected against quite well
- cookies are limited to 4kB
- native clients don't like cookies and just want to use tokens
- stateless tokens are nice for performance but without tracking any server-side sessions, it is impossible to force a logout

#### Problems NOT (attempted to be) solved

This package aims to be (and remain) small. It depends only on Phoenix. Also, we like our flexibility. The following things are left up to the application:

- user management, registration, password change, confirmation emails etc
- authentication mechanisms like passwords, one-time passwords, etc
- authorization infrastructure like definining roles etc
- CSRF-protection

This package DOES lay the groundwork for you to add those things.

## The long version

A great many solutions exist for generating tokens to use in API authentication. Not many of these implementations really concern themselves with the security of said tokens in a browser contex; the tokens are sent on their way for the client to deal with. Especially the practice of storing authentication tokens in LocalStorage where they are vulnerable to cross-site scripting (XSS) attack vectors is something that this package tries to tackle. At the same time, cookies have their own drawbacks as well; they max out at 4KB and are vulnerable to cross-site request forgery (CSRF). On the other hand, native clients don't want to deal with cookies, they just want to shove a bearer token into the `authorization` header and be done with it.

This package is an attempt to have the cake and eat it at the same time, by splitting authentication tokens in two parts. Phoenix tokens (and JWT's) consist of three parts, basically `header.payload.signature`. The first two parts are not valid without the signature, and the signature is impossible to generate from the first two parts without the underlying signing key thanks to CryptographyTM. YipyipExAuth allows clients to specify at the creation of a session if they want to receive the signature part of their tokens in a secure, HTTP-only strictly-same-site cookie, or simply as part of the the whole token. Browser clients should use the former, native clients the latter. In case of a successful XSS breach of the web application only the token payloads will be exposed. This idea is inspired by [this](https://medium.com/lightrail/getting-token-authentication-right-in-a-stateless-single-page-application-57d0c6474e3) excellent Medium article by Peter Locke (although there are some differences in implementation).

Additionally, YipyipExAuth tries to strike a balance between statelessness and security, by using stateless short-lived access tokens and stateful refresh tokens. A server-side session store is maintained (and can be implemented in whatever DB system you like; genserver, Redis, Postgres or Mnesia can all be used by implementing a simple behaviour). Every time the tokens are refreshed, this database is queried. Depending on your access token TTL, this could be once every half an hour per client. By the time you outgrow a simple Redis cluster, you can hire a team of engineers to scale further.


## How to use

### Installation

The package can be installed by adding `yipyip_ex_auth` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:yipyip_ex_auth, "~> 0.1.0-alpha.2"}
  ]
end
```

### Documentation

Documentation can be found at [https://hexdocs.pm/yipyip_ex_auth](https://hexdocs.pm/yipyip_ex_auth).

