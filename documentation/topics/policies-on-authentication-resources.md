<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Policies on Authenticated Resources

Typically, we want to lock down our `User` resource pretty heavily, which, in Ash, involves writing policies. However, AshAuthentication will be calling actions on your user/token resources. To make this more convenient, all actions run with `AshAuthentication` will set a special context. Additionally a check is provided that will check if that context has been set: `AshAuthentication.Checks.AshAuthenticationInteraction`. Using this you can write a simple bypass policy on your user/token resources like so:

```elixir
policies do
  bypass always() do
    authorize_if AshAuthentication.Checks.AshAuthenticationInteraction
  end

  # or, pick your poison

  bypass AshAuthentication.Checks.AshAuthenticationInteraction do
    authorize_if always()
  end
end
```

## The blanket bypass disables your own policies on strategy actions

A bypass which passes authorizes the request and skips every policy after it.
`AshAuthenticationInteraction` is true for *everything* the library calls,
which includes the actions its strategies generate — `sign_in_with_password`,
`register_with_password`, `sign_in_with_otp`, `request_otp` and the rest.

So with the blanket bypass above, a policy you write on one of those actions
never runs:

```elixir
policies do
  bypass AshAuthentication.Checks.AshAuthenticationInteraction do
    authorize_if always()
  end

  # Never reached when the strategy calls the action, which is every time it is
  # called over `POST /auth/user/password/sign_in`.
  policy action(:sign_in_with_password) do
    forbid_if MyApp.Checks.SignInSuspended
    authorize_if always()
  end
end
```

This matters because some of those routes cannot be unmounted. `sign_in_with_token`
requires `sign_in_enabled?`, so a resource which wants sign-in tokens also has a
live `POST /auth/<subject>/password/sign_in`, and any rule an application wants
to put in front of the credential check has to survive that entrance.

## Narrowing the bypass

A bypass which *fails* does not forbid the request — authorization simply moves
on to the next policy. So the bypass can decline the actions you mean to police
yourself, and everything else keeps working as before:

```elixir
policies do
  bypass AshAuthentication.Checks.AshAuthenticationInteraction do
    # Policed below instead. Every other library interaction — resolving a
    # session, exchanging a sign-in token, revoking one — still passes here.
    forbid_if action(:sign_in_with_password)
    authorize_if always()
  end

  policy action(:sign_in_with_password) do
    forbid_if MyApp.Checks.SignInSuspended
    authorize_if always()
  end
end
```

Two things to keep in mind for the action you have taken out of the bypass:

  * **It runs with no actor.** Signing in is how an actor comes into being, so
    any policy which also applies to it — a general `policy action_type(:read)`,
    for instance — has to admit an actorless caller, or the sign-in will match
    no records and fail as though the password were wrong.

  * **Read policies filter by default.** A failing expression check on a read
    action narrows the query rather than raising, so the strategy reports
    "Query returned no users" and the caller sees the same generic
    authentication failure a wrong password produces. That is usually what you
    want; use `access_type :strict` if you would rather it raise.

## Doing it with a policy rather than a preparation

It is tempting to put such a rule in a preparation on the sign-in action
instead. A policy is the better place for two reasons: it is enforced on every
entrance to the action rather than on the ones which remember to go through
your wrapper, and `Ash.can?/3` can ask it, so a UI can hide the password field
using the same rule that refuses the request.
