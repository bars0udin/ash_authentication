# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.BcryptProviderTest do
  @moduledoc false
  use ExUnit.Case, async: true
  import AshAuthentication.BcryptProvider
  doctest AshAuthentication.BcryptProvider

  describe "valid?/2" do
    test "a record with no stored hash cannot be matched by any input" do
      refute valid?("Marty McFly", nil)
    end
  end
end
