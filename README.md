# YipyipExAuth

YipyipExAuth is an opinionated session manager for Elixir based on stateless access- and stateful refresh (Phoenix) tokens aimed at browser- and native clients that communicate with an Elixir API.

## Table of contents

<!-- TOC -->

- [YipyipExAuth](#YipyipExAuth)
  - [Table of contents](#table-of-contents)
  - [What the package does](#what-the-package-does)
    - [Problems solved](#problems-solved)
    - [Problems NOT (attempted to be) solved](#problems-not-attempted-to-be-solved)
  - [The slightly longer story](#the-slightly-longer-story)
  - [How to use](#how-to-use)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [Setting up a session store](#setting-up-a-session-store)
    - [Protecting routes](#protecting-routes)
    - [Creating and refreshing sessions](#creating-and-refreshing-sessions)
  - [Documentation](#documentation)
  - [Nods](#nods)

<!-- /TOC -->

## What the package does

### Problems solved

This package attempts to solve the following issues:

- tokens in LocalStorage are less secure than cookies, given that CSRF can be protected against quite well
- cookies are limited to 4kB
- native clients don't like cookies and just want to use tokens
- stateless tokens are nice for performance but without tracking any server-side sessions, it is impossible to force a logout

### Problems NOT (attempted to be) solved

This package aims to be (and remain) small. It depends only on Phoenix. Also, we like our flexibility. The following things are left up to the application:

- user management, registration, password change, confirmation emails etc
- authentication mechanisms like passwords, one-time passwords, etc
- authorization mechanisms like definining roles etc
- CSRF-protection

This package DOES lay the groundwork for you to add those things.

## The slightly longer story

A great many solutions exist for generating tokens to use in API authentication. Not many of these implementations really concern themselves with the security of said tokens in a browser contex; the tokens are sent on their way for the client to deal with. Especially the practice of storing authentication tokens in LocalStorage where they are vulnerable to cross-site scripting (XSS) attack vectors is something that this package tries to tackle. At the same time, cookies have their own drawbacks as well; they max out at 4KB and are vulnerable to cross-site request forgery (CSRF). On top of that native clients don't want to deal with cookies, they just want to shove a bearer token into the `authorization` header and be done with it.

This package is an attempt to have our cake and eat it at the same time, by splitting authentication tokens in two parts. Phoenix tokens (and JWT's) consist of three parts, basically `header.payload.signature`. The first two parts are not valid without the signature, and the signature is impossible to generate from the first two parts without the underlying signing key thanks to CryptographyTM. YipyipExAuth allows clients to specify at the creation of a session if they want to receive the signature part of their tokens in a secure, HTTP-only strictly-same-site cookie, or simply as part of the the whole token. Browser clients should use the former, native clients the latter. In case of a successful XSS breach of the web application only the token payloads will be exposed.

Additionally, YipyipExAuth tries to strike a balance between statelessness and security, by using stateless short-lived access tokens and stateful refresh tokens. A server-side session store is maintained (and can be implemented in whatever DB system you like; genserver, Redis, Postgres or Mnesia can all be used by implementing a simple behaviour). Every time the tokens are refreshed, this database is queried. Depending on your access token TTL, this could be once every half an hour per client. By the time you outgrow a simple Redis cluster, you can hire a team of engineers to scale further.

## How to use

Getting up and running consists of 5 steps: installation, configuration, setting up a session store, protecting your routes and handing out tokens.

### Installation

The package can be installed by adding `yipyip_ex_auth` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:yipyip_ex_auth, "0.0.0+development"}
  ]
end
```

### Configuration

Configuration has been made easy using a config helper struct `YipyipExAuth.Config`, which has a function `from_enum/1` that verifies that your config is complete and valid, raising on missing fields. You can create this struct at runtime or compile time or change it dynamically however you please, but bear in mind that you might run into problems if you use different values for different parts of `YipyipExAuth`. The main reason to use multiple sets of configuration is that you can support different auth requirements in this way. You could, for example, create a never-expiring session for ordinary users and create a short-lived session for application admins.

```elixir
# all other configuration uses sane defaults
# the following sets up sessions that last forever as long as they are used at least once a month
@my_config YipyipExAuth.Config.from_enum(session_ttl: nil, refresh_token_ttl: 30 * 24 * 60 * 60, session_store_module: MySessionStoreModule)

# you can also directly pass in your application environment
@my_config Application.compile_env(:my_phoenix_app, :yipyip_ex_auth) |> YipyipExAuth.Config.from_enum()
```

### Setting up a session store

A session store can be created using multiple state stores, be it a database or a GenServer. All you have to do is implement a simple behaviour which you can find in `YipyipExAuth.SessionStore`. We've also provided a reference Redis-based implementation there that we find easy to work with and deploy.

### Protecting routes

In the router of your Phoenix application, create pipelines to protect routes with either access- or refresh tokens, using `YipyipExAuth.Plugs.ProcessAccessToken` and `YipyipExAuth.Plugs.ProcessRefreshToken`, plus a custom plug to send auth errors back to the client. In this case, it's just been added to the router itself, which is not very tidy but demonstrates the basic idea.

```elixir
defmodule MyPhoenixAppWeb.Router do
  use MyPhoenixAppWeb, :router

  @config Application.compile_env(:my_phoenix_app, :yipyip_ex_auth)
          |> YipyipExAuth.Config.from_enum()

  pipeline :valid_access_token do
    plug YipyipExAuth.Plugs.ProcessAccessToken, @config
    plug :only_authenticated
  end

  pipeline :valid_refresh_token do
    plug YipyipExAuth.Plugs.ProcessRefreshToken, @config
    plug :only_authenticated
  end


  @doc """
  Reject unauthenticated requests
  """
  def only_authenticated(%{assigns: %{current_user_id: _}} = conn, _opts), do: conn

  def only_authenticated(conn, _opts) do
    auth_error = YipyipExAuth.Utils.get_auth_error(conn)
    conn |> Plug.Conn.send_resp(401, auth_error) |> halt()
  end
end
```

Then you should protect your refresh route with the refresh pipeline and standard authenticated-only routes with the access token pipeline (among which is the delete session / logout endpoint). The login endpoint should be kept unprotected, naturally.

```elixir
scope "/" do
  pipe_through [:api]

  post "/current_session", CurrentSessionController, :create
end

scope "/" do
  pipe_through [:api ,:valid_access_token]

  resources "/articles", ArticleController, only: [:index, :show]
  delete "/current_session", CurrentSessionController, :delete
end

scope "/" do
  pipe_through [:api ,:valid_refresh_token]

  # optionally limit the refresh cookie path to this path using `Config.refresh_cookie_opts`
  post "/current_session/refresh", CurrentSessionController, :refresh
end
```

And that's it.

### Creating and refreshing sessions

Create a session controller with at least login, logout and refresh routes.

```elixir
defmodule MyPhoenixAppWeb.CurrentSessionController do
  @moduledoc """
  REST controller for the current session.

  For details on how sessions work, please refer to `YipyipExAuth`.
  """
  use MyPhoenixAppWeb, :controller

  alias YipyipExAuth.Plugs, as: YipyipPlugs
  alias YipyipExAuth.Utils
  alias MyPhoenixApp.{User, Users}

  @config Application.compile_env(:my_phoenix_app, :yipyip_ex_auth)
          |> YipyipExAuth.Config.from_enum()

  @doc """
  Create a new session / login. Returns the user, session and access- and refresh tokens.

  If "token_signature_transport" is set to "bearer", the tokens returned in the response body
  will include the signatures needed to verify their integrity.
  If it is set to "cookie", those signatures will be returned as cookies.

  Returns:
    - 201 Created and session and tokens and maybe cookie
    - 400 Bad Request and errors if request body is malformed
    - 401 Unauthorized and errors if the request could not be authenticated or the user was not found
    - 500 Internal Server Error and errors if an unforeseen error occurred
  """
  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, %{
        "email" => email,
        "password" => password,
        "token_signature_transport" => signature_transport
      })
      when signature_transport in ~w(bearer cookie) do
    with {:ok, user} <- Users.get_by(email: email) |> Users.verify_password(password) do
      # you can do extra checks here, like checking if the user is banned, for example

      conn
      |> Utils.set_user_id(user.id)
      |> Utils.set_token_signature_transport(signature_transport)
      # you can add extra payload to the tokens
      |> YipyipPlugs.upsert_session(@config, extra_access_payload: %{roles: user.roles})
      |> put_status(201)
      |> send_token_response(user)
    else
      _error -> send_resp(conn, 401, "user not found or wrong password")
    end
  end

  @doc """
  Delete current session / logout.
  Requires authentication.

  Will remove the server-side session and instructs browser clients to drop
  the token signature cookies set by `YipyipExAuth`.
  Note that this cannot be enforced from the server side -
  clients are responsible for correct disposal of authentication tokens themselves.

  Returns:
    - 204 No Content
    - 401 Unauthorized and errors if the request could not be authenticated
    - 500 Internal Server Error and errors if an unforeseen error occurred
  """
  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, _params) do
    conn
    |> YipyipPlugs.delete_session(@config)
    |> send_resp(204, "")
  end

  @doc """
  Refresh an existing session.
  Requires authentication in the form of a single-use refresh token.

  Returns:
    - 200 OK and session and tokens and maybe cookie
    - 401 Unauthorized and errors if the request could not be authenticated
    - 500 Internal Server Error and errors if an unforeseen error occurred
  """
  @spec refresh(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def refresh(%{assigns: %{current_user_id: user_id}} = conn, _params) do
    with %User{} = user <- Users.get_by(id: user_id) do
      # here you can do extra checks again
      # for example if the user has been banned since the previous refresh

      conn
      # there's no need to set user_id or token signature transport again
      # but all extra payload - access, refresh and session - has to be passed in again
      |> YipyipPlugs.upsert_session(@config, extra_access_payload: %{roles: user.roles})
      |> send_token_response(user)
    else
      _error -> send_resp(conn, 401, "user not found or inactive")
    end
  end

  ############
  # Privates #
  ############

  defp send_token_response(conn, user) do
    session = Utils.get_session(conn)
    tokens = Utils.get_tokens(conn)
    render(conn, "tokens.json", tokens: tokens, session: session, user: user)
  end
end
```

## Documentation

Documentation can be found at [https://hexdocs.pm/yipyip_ex_auth](https://hexdocs.pm/yipyip_ex_auth).

## Nods

The idea of splitting of the token signature is inspired by [this](https://medium.com/lightrail/getting-token-authentication-right-in-a-stateless-single-page-application-57d0c6474e3) excellent Medium article by Peter Locke.

The ideas of passing around a config parameter, splitting token processing and error handling, depending on as little as possible, separating the persistent session store and general token handling were inspired by [Pow](https://github.com/danschultzer/pow) by Dan Schultzer, which is an excellent alternative if you don't want to solve the problems named under [problems not attempted to be solved](#problems-not-attempted-to-be-solved), or for working with Phoenix templates.
