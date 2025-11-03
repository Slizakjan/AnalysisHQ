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

    # Vrací uživatele podle API klíče
    def api_user
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
    user = api_user  # ✅ ověří API klíč, roli i lock status

    begin
      data = JSON.parse(request.body.read)
      test_name   = data["test_name"]
      test_id   = data["test_id"]
      answer_id = data["answer_id"]
      action    = data["action"]
      metadata  = data["metadata"] || {}

      question  = data["question"]
      answers   = data["answers"]
    rescue JSON::ParserError
      halt 400, { status: "error", message: "Invalid JSON" }.to_json
    end

    # ✅ Povinná validace question a answers
    is_closed = !["short", "descriptive"].include?(data["type"])

    if !question || (is_closed && (!answers || !answers.is_a?(Array) || answers.empty?))
      halt 400, { status: "error", message: "Both 'question' and 'answers' must be provided for closed questions" }.to_json
    end


    # === Vložení do question_bank ===
    begin
      Database.insert_question(
        user_id: user[:id],
        test_id: test_id,
        answer_id: answer_id,
        question_json: { question: question },
        answer_json: answers,
        exam_name: test_name,
      )
    rescue PG::Error => e
      halt 500, { status: "error", message: "DB error inserting question: #{e.message}" }.to_json
    end

    # === Vložení do api_answer_logs ===
    clean_metadata = metadata.dup
    clean_metadata.delete("question")
    clean_metadata.delete("answers")

    begin
      Database.insert_log(
        user[:api_key_hash],
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
  # Endpoint pro párování API klíče k uživateli (vyžaduje aktivní session)
  # ----------------------
  post '/api/pair_user' do
    user = current_user  # vyžaduje aktivní session

    halt 403, { status: "error", message: "Account is locked" }.to_json if user[:locked]

    allowed_roles = ["user", "manager", "admin"]
    halt 403, { status: "error", message: "Insufficient role" }.to_json unless allowed_roles.include?(user[:role])

    header_api_key = request.env["HTTP_API_KEY_HASH"] || request.env["HTTP_API_KEY"]

    begin
      data = JSON.parse(request.body.read)
      api_key_hash = data["api_key_hash"]
      action       = data["action"] || "add"
    rescue JSON::ParserError
      halt 400, { status: "error", message: "Invalid JSON" }.to_json
    end

    if header_api_key != api_key_hash
      halt 400, { status: "error", message: "Header and body API key mismatch" }.to_json
    end

    unless action == "add"
      halt 400, { status: "error", message: "Unsupported action" }.to_json
    end

    begin
      Database.pair_user_api_key(user[:id], api_key_hash)
    rescue PG::Error => e
      halt 500, { status: "error", message: "Database error: #{e.message}" }.to_json
    end

    { status: "ok", message: "API key paired successfully" }.to_json
  end

  # ----------------------
  # Endpoint pro hledání odpovědi podle test_id a answer_id
  # ----------------------
  post '/api/search' do
    user = api_user  # ✅ ověří API klíč, roli i lock status

    begin
      data = JSON.parse(request.body.read)
      test_id   = data["test_id"]
      answer_id = data["answer_id"]

      halt 400, { status: "error", message: "Missing test_id or answer_id" }.to_json unless test_id && answer_id
    rescue JSON::ParserError
      halt 400, { status: "error", message: "Invalid JSON" }.to_json
    end

    begin
      result = DB.exec_params(
        "SELECT question_json FROM question_bank WHERE test_id = $1 AND answer_id = $2 LIMIT 1",
        [test_id, answer_id]
      )

      if result.any?
        question_data = result[0]["question_json"]
        parsed = JSON.parse(question_data) rescue {}

        answer_text = parsed["answer"] || "No answer stored"

        content_type :json
        { status: "ok", answer: answer_text }.to_json
      else
        content_type :json
        { status: "not_found", message: "No answer found for this test_id and answer_id" }.to_json
      end
    rescue PG::Error => e
      halt 500, { status: "error", message: "Database error: #{e.message}" }.to_json
    end
  end


  # ----------------------
  # Endpoint pro aktualizaci odpovědi u otázky
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

    # Načtení stávající question_json z databáze
    question_row = Database.get_question_by_id(test_id, answer_id)
    halt 404, { status: "error", message: "Question not found" }.to_json unless question_row

    # Parsování JSON na hash
    question_json = {}
    if question_row[:question_json].is_a?(String)
      begin
        question_json = JSON.parse(question_row[:question_json])
      rescue JSON::ParserError
        question_json = {}
      end
    elsif question_row[:question_json].is_a?(Hash)
      question_json = question_row[:question_json]
    end

    # Uložení nové odpovědi
    question_json["answer"] = new_answer

    # Update do databáze (převedeno zpět na JSON string)
    begin
      Database.update_question_answer(
        test_id: test_id,
        answer_id: answer_id,
        question_json: JSON.generate(question_json)
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
