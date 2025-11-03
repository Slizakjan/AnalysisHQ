require 'json'
require 'openssl'
require 'base64'
require 'digest'  # added

module SessionManager
  SECRET_KEY = ENV['SESSION_SECRET'] || 'nějaké_tajné_heslo_pro_server'
  ALGORITHM = 'aes-256-gcm'
  IV_LEN = 12
  AUTH_TAG_LEN = 16

  # Vytvoří šifrovanou session pro cookie
  def self.create_session(user_id, role)
    data = { id: user_id, role: role }
    encrypt(data)
  end

  # Získá data session z cookie
  def self.get_session(cookie_value)
    decrypt(cookie_value)
  end

  # Logout = stačí smazat cookie na klientovi
  def self.delete_session(_cookie_value)
    # žádná akce na serveru
    true
  end

  private

  def self.encrypt(data)
    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.encrypt
    key = Digest::SHA256.digest(SECRET_KEY)
    cipher.key = key
    iv = cipher.random_iv
    cipher.iv = iv

    encrypted = cipher.update(data.to_json) + cipher.final
    auth_tag = cipher.auth_tag

    Base64.urlsafe_encode64(iv + auth_tag + encrypted)
  end

  def self.decrypt(encoded)
    return nil unless encoded
    decoded = Base64.urlsafe_decode64(encoded)
    iv = decoded[0, IV_LEN]
    auth_tag = decoded[IV_LEN, AUTH_TAG_LEN]
    encrypted = decoded[IV_LEN + AUTH_TAG_LEN..-1]

    cipher = OpenSSL::Cipher.new(ALGORITHM)
    cipher.decrypt
    cipher.key = Digest::SHA256.digest(SECRET_KEY)
    cipher.iv = iv
    cipher.auth_tag = auth_tag

    JSON.parse(cipher.update(encrypted) + cipher.final, symbolize_names: true)
  rescue => e
    puts "Session decryption error: #{e.message}"
    nil
  end

end
