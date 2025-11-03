require 'sinatra'
require 'sinatra/json'
require 'pg'
require 'dotenv/load'
require 'erb'

# ====== Nastavení Sinatra ======
set :public_folder, 'public'
set :static, true
set :bind, '0.0.0.0'

# ====== Database připojení ======
required_env_vars = %w[DB_HOST DB_NAME DB_USER DB_PASSWORD]
missing_vars = required_env_vars.select { |var| ENV[var].nil? || ENV[var].empty? }

if missing_vars.any?
  puts "Missing required environment variables: #{missing_vars.join(', ')}"
  DB = nil
else
  begin
    DB = PG.connect(
      host: ENV['DB_HOST'],
      dbname: ENV['DB_NAME'],
      user: ENV['DB_USER'],
      password: ENV['DB_PASSWORD']
    )
  rescue PG::Error => e
    puts "Database connection failed: #{e.message}"
    DB = nil
  end
end

# ====== Load Helpers & Middleware ======
require_relative './lib/database'
require_relative './lib/session_manager'
require_relative './lib/authenticator'
require_relative './lib/permissions'

# ====== Routes ======
require_relative './routes/auth_routes'
require_relative './routes/user_routes'
require_relative './routes/api_routes'

use AuthRoutes
use UserRoutes
use ApiRoutes

# ====== Default endpoints ======
get '/' do
  send_file File.join(settings.root, 'public/index.html')
end

get '/status' do
  json status: "Backend is running 💻🔥"
end
