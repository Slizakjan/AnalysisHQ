require 'sinatra'
require 'pg'
require 'bcrypt'
require 'json'
require 'securerandom'
require 'dotenv/load'

# Připojení k PostgreSQL přes ENV proměnné (nastavíš na Render)
DB = PG.connect(
  host: ENV['DB_HOST'],
  dbname: ENV['DB_NAME'],
  user: ENV['DB_USER'],
  password: ENV['DB_PASSWORD']
)

# Přidání hodnot
set :public_folder, 'public'  # složka s index.html
set :static, true             # povolit statické soubory

# ----------------------
# Pomocné funkce
# ----------------------

def hash_password(password)
  BCrypt::Password.create(password)
end

def verify_password(hash, password)
  BCrypt::Password.new(hash) == password
end

def hash_api_key(key)
  BCrypt::Password.create(key)
end

# Middleware pro získání aktuálního uživatele podle API key
def current_user
  api_key = request.env["HTTP_AUTHORIZATION"]&.split(" ")&.last
  return nil unless api_key
  result = DB.exec("SELECT * FROM users")
  user = result.find { |u| BCrypt::Password.new(u['api_key_hash']) == api_key }
  user
end

# Middleware pro autorizaci
def authorize!(allowed_roles)
  user = current_user
  halt 401, { error: "Unauthorized" }.to_json unless user
  halt 403, { error: "Forbidden" }.to_json unless allowed_roles.include?(user['role'])
end

# ----------------------
# Endpoints
# ----------------------

# Status endpoint
get '/status' do
  content_type :json
  { status: "AnalysisHQ API is online ✅" }.to_json
end

# ----------------------
# Registrace
# ----------------------
post '/register' do
  content_type :json
  data = JSON.parse(request.body.read)

  username = data['username']
  password = data['password']

  password_hash = hash_password(password)
  api_key_hash = nil  # API key zatím prázdný, uživatel si ho nastaví později

  # Určení role – první uživatel = admin
  role = 'unverified'
  begin
    result = DB.exec("SELECT COUNT(*) FROM users")
    role = 'admin' if result[0]['count'].to_i == 0

    DB.exec_params(
      "INSERT INTO users (username, password_hash, role, api_key_hash) VALUES ($1, $2, $3, $4)",
      [username, password_hash, role, api_key_hash]
    )

    { status: "ok", api_key: "", role: role }.to_json
  rescue PG::UniqueViolation
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
  content_type :json
  data = JSON.parse(request.body.read)

  username = data['username']
  password = data['password']

  result = DB.exec_params("SELECT * FROM users WHERE username=$1", [username])
  halt 401, { error: "Invalid credentials" }.to_json if result.ntuples == 0

  user = result[0]
  if verify_password(user['password_hash'], password)
    { status: "ok", role: user['role'], api_key: user['api_key_hash'] }.to_json
  else
    halt 401, { error: "Invalid credentials" }.to_json
  end
end

get '/' do
  send_file File.join(settings.public_folder, 'index.html')
end

# ----------------------
# Dashboard – dostupný pro přihlášené
# ----------------------
get '/dashboard' do
  authorize!(["user", "manager", "admin"])  # jen ověření rolí
  send_file File.join(settings.public_folder, 'dashboard.html')
end
