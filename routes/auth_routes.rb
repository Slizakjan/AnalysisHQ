require 'sinatra/base'
require 'json'
require_relative '../lib/authenticator'
require_relative '../lib/session_manager'

class AuthRoutes < Sinatra::Base
  before do
    content_type :json
  end

  # ----------------------
  # Registrace
  # ----------------------
  post '/register' do
    data = JSON.parse(request.body.read)
    username = data['username']
    password = data['password']

    begin
      user = Authenticator.register(username, password)
      { status: "ok", role: user[:role] }.to_json
    rescue Authenticator::UserExistsError
      status 409
      { status: "error", message: "Username already exists!" }.to_json
    rescue => e
      status 500
      { status: "error", message: "Server error: #{e.message}" }.to_json
    end
  end

  # ----------------------
  # Login
  # ----------------------
  post '/login' do
    data = JSON.parse(request.body.read)
    username = data['username']
    password = data['password']

    begin
      result = Authenticator.login(username, password)

      # nastavení šifrované cookie
      response.set_cookie(
        'session',
        value: result[:token],
        path: '/',
        httponly: true,
        secure: ENV['RACK_ENV'] == 'production'
      )

      { status: "ok", role: result[:role] }.to_json
    rescue Authenticator::InvalidCredentialsError
      status 401
      { status: "error", message: "Invalid username or password" }.to_json
    rescue Authenticator::AccountLockedError
      status 403
      { status: "error", message: "Account is locked due to failed attempts" }.to_json
    rescue => e
      status 500
      { status: "error", message: "Server error: #{e.message}" }.to_json
    end
  end

  # ----------------------
  # Logout
  # ----------------------
  post '/logout' do
    response.delete_cookie('session', path: '/')
    { status: "ok", message: "Logged out successfully" }.to_json
  end

  get '/logout' do
    response.delete_cookie('session', path: '/')
    { status: "ok", message: "Logged out successfully" }.to_json
  end
end
