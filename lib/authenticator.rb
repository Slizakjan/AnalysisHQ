require 'bcrypt'
require_relative 'database'
require_relative 'session_manager'

module Authenticator
  MAX_FAILED_ATTEMPTS = 5

  # ----------------------
  # Vlastní výjimky
  # ----------------------
  class UserExistsError < StandardError; end
  class InvalidCredentialsError < StandardError; end
  class AccountLockedError < StandardError; end
  class MissingApiKeyError < StandardError; end

  # ----------------------
  # Hashování hesla
  # ----------------------
  def self.hash_password(password)
    BCrypt::Password.create(password)
  end

  # ----------------------
  # Registrace
  # ----------------------
  def self.register(username, password)
    password_hash = hash_password(password)
    role = Database.user_count == 0 ? "admin" : "unverified"

    begin
      Database.create_user(username, password_hash, role)
    rescue PG::UniqueViolation
      raise UserExistsError, "Username already exists!"
    end

    { id: Database.get_user_by_username(username)[:id], role: role }
  end

  # ----------------------
  # Login uživatele
  # ----------------------
  def self.login(username, password)
    user = Database.get_user_by_username(username)
    raise InvalidCredentialsError, "Invalid username or password" unless user
    raise AccountLockedError, "Account is locked" if user[:locked]

    unless BCrypt::Password.new(user[:password_hash]) == password
      # increment and re-fetch user so we know the updated failed_attempts count
      Database.increment_failed_attempts(user[:id])
      user = Database.get_user_by_username(username)
      lock_if_exceeded(user[:id], user[:failed_attempts])
      raise InvalidCredentialsError, "Invalid username or password"
    end

    Database.reset_failed_attempts(user[:id])
    Database.update_last_login(user[:id])

    token = SessionManager.create_session(user[:id], user[:role])
    { status: "ok", token: token, role: user[:role] }
  end

  # ----------------------
  # API login
  # ----------------------
  def self.api_login(api_key)
    raise MissingApiKeyError, "Missing API key" unless api_key

    user = Database.get_user_by_api_key(api_key)
    raise InvalidCredentialsError, "Invalid API key" unless user
    raise AccountLockedError, "Account is locked" if user[:locked]

    token = SessionManager.create_session(user[:id], user[:role])
    { status: "ok", token: token, role: user[:role] }
  end

  # ----------------------
  # Logout
  # ----------------------
  def self.logout(token)
    SessionManager.delete_session(token)
    { status: "ok" }
  end

  # ----------------------
  # Soukromé metody
  # ----------------------
  private

  def self.lock_if_exceeded(user_id, fails)
    Database.lock_user(user_id) if fails && (fails >= MAX_FAILED_ATTEMPTS)
  end
end