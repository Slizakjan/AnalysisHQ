require 'sinatra/base'
require 'json'
require_relative '../lib/permissions'
require_relative '../lib/session_manager'

class ApiRoutes < Sinatra::Base
  before do
    response.headers['Access-Control-Allow-Origin'] = '*' # nebo konkrétní URL
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, API_KEY_HASH'
    content_type :json
  end

  options '*' do
    200
  end

  helpers do
    # Vrací aktuálního uživatele podle session tokenu
    def current_user
      cookie_value = request.cookies["session"]
      session = SessionManager.get_session(cookie_value)
      halt 401, { status: "error", message: "Unauthorized" }.to_json unless session
      session
    end

    # Konstanta, která povolí přístup i bez API klíče
    ALLOW_EVERYONE = true   # TODO: delete this temp. feature
    
    # Vrací uživatele podle API klíče
    def api_user
      if ALLOW_EVERYONE
        # fallback uživatel pro allow_everyone
        return { id: nil, role: "guest" }
      end
    
      api_key_hash = request.env["HTTP_API_KEY_HASH"] || request.env["HTTP_API_KEY"]
      halt 401, { status: "error", message: "Missing API key" }.to_json unless api_key_hash
    
      user = Database.get_user_by_api_key(api_key_hash)
      halt 403, { status: "error", message: "Invalid API key or access denied" }.to_json unless user
      halt 403, { status: "error", message: "Account is locked" }.to_json if user[:locked]
      halt 403, { status: "error", message: "Unverified account" }.to_json if user[:role] == "unverified"
    
      user
    end
  end

  # ----------------------
  # Endpoint pro logování akcí (vyžaduje API klíč)
  # ----------------------
  post '/api/log' do
    content_type :json

    # --- Získání uživatele přes API klíč, fallback pokud ALLOW_EVERYONE ---
    begin
      user = api_user  # metoda, která vyhazuje Sinatra::Halt pokud API key neexistuje
    rescue Sinatra::Halt => e
      if ALLOW_EVERYONE
        # fallback uživatel pro testování bez klíče
        user = { id: nil, role: "guest", api_key_hash: "guest" }
      else
        raise e
      end
    end

    # --- Parsování JSON payload ---
    begin
      # Z headeru
      api_key_hash = request.env["HTTP_API_KEY_HASH"]

      # Z těla
      data = JSON.parse(request.body.read)
      test_name   = data["test_name"]
      test_id     = data["test_id"]
      answer_id   = data["answer_id"]
      action      = data["action"]
      metadata    = data["metadata"] || {}

      question    = data["question"]
      options     = data["answers"] || []
      type        = data["type"] || "radio"
      correct     = data["correct_answer"]
    rescue JSON::ParserError
      halt 400, { status: "error", message: "Invalid JSON" }.to_json
    end

    # --- Povinná validace ---
    if !question || question.strip.empty?
      halt 400, { status: "error", message: "Missing 'question'" }.to_json
    end

    if ["radio", "checkbox"].include?(type) && (!options.is_a?(Array) || options.empty?)
      halt 400, { status: "error", message: "Closed question must include 'answers' array" }.to_json
    end

    # --- Uložení do question_bank ---
    begin
      Database.insert_question(
        user_id: user[:id],
        test_id: test_id,
        answer_id: answer_id,
        question: question,
        options: options,
        type: type,
        correct_answer: correct,
        exam_name: test_name
      )
    rescue PG::Error => e
      halt 500, { status: "error", message: "DB error inserting question: #{e.message}" }.to_json
    end

    # --- Uložení logu ---
    clean_metadata = metadata.dup
    clean_metadata.delete("question")
    clean_metadata.delete("answers")

    begin
      Database.insert_log(
        api_key_hash || user[:api_key_hash],  # prefer header, fallback pokud nil
        test_id,
        answer_id,
        action,
        clean_metadata
      )
    rescue PG::Error => e
      halt 500, { status: "error", message: "DB error inserting log: #{e.message}" }.to_json
    end

    { status: "ok", message: "Log saved successfully" }.to_json
  end

  # ----------------------
  # Endpoint pro hledání odpovědi podle test_id a answer_id
  # ----------------------
  post '/api/search' do
    user = api_user

    begin
      data = JSON.parse(request.body.read)
      test_id   = data["test_id"]
      answer_id = data["answer_id"]
      halt 400, { status: "error", message: "Missing test_id or answer_id" }.to_json unless test_id && answer_id
    rescue JSON::ParserError
      halt 400, { status: "error", message: "Invalid JSON" }.to_json
    end

    begin
      question = Database.get_question_by_id(test_id, answer_id)
      if question
        { status: "ok", answer: question[:correct_answer] || "No correct answer stored" }.to_json
      else
        { status: "not_found", message: "No record found" }.to_json
      end
    rescue PG::Error => e
      halt 500, { status: "error", message: "Database error: #{e.message}" }.to_json
    end
  end

  # ----------------------
  # Endpoint pro aktualizaci správné odpovědi u otázky
  # ----------------------
  post '/api/exam/:test_id/:answer_id/answer_update' do
    user = current_user
    Permissions.authorize!(user, ["admin", "manager"]) # jen pro admin/manager

    test_id = params[:test_id]
    answer_id = params[:answer_id]

    # Načtení dat z requestu
    begin
      data = JSON.parse(request.body.read)
      new_answer = data["answer"]&.strip
    rescue JSON::ParserError
      halt 400, { status: "error", message: "Invalid JSON" }.to_json
    end

    halt 400, { status: "error", message: "Missing 'answer'" }.to_json if new_answer.nil? || new_answer.empty?

    # Kontrola, že otázka existuje
    question_row = Database.get_question_by_id(test_id, answer_id)
    halt 404, { status: "error", message: "Question not found" }.to_json unless question_row

    # Aktualizace správné odpovědi
    begin
      Database.update_question_answer(
        test_id: test_id,
        answer_id: answer_id,
        correct_answer: new_answer
      )
    rescue PG::Error => e
      halt 500, { status: "error", message: "Database error: #{e.message}" }.to_json
    end

    content_type :json
    { status: "ok", message: "Answer updated successfully" }.to_json
  end


  # ----------------------
  # Admin-only endpoint
  # ----------------------
  post '/api/admin-task' do
    user = current_user
    Permissions.authorize!(user[:role], ["admin"])

    {
      status: "ok",
      message: "Admin task executed successfully!"
    }.to_json
  end
end
