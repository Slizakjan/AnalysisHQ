require_relative 'session_manager'

module Permissions
  def self.authorize!(session_data, allowed_roles)
    role = session_data[:role] || session_data["role"]
    return forbidden unless allowed_roles.include?(role)
    session_data
  end

  private

  def self.unauthorized(message)
    halt 401, { status: "error", message: message }.to_json
  end

  def self.forbidden
    halt 403, { status: "error", message: "Forbidden" }.to_json
  end
end
