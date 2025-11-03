require 'sinatra/base'
require 'json'
require_relative '../lib/permissions'
require_relative '../lib/session_manager'
require_relative '../lib/date_helper'

class UserRoutes < Sinatra::Base
  set :views, File.expand_path('../protected', __dir__)  # ERB šablony
  helpers DateHelper

  before do
    content_type :json
  end

  helpers do
    def current_user
      cookie_value = request.cookies["session"]
      session = SessionManager.get_session(cookie_value)
      halt 401, { status: "error", message: "Unauthorized" }.to_json unless session
      session
    end
  end

  get '/profile' do
    user = current_user
    {
      status: "ok",
      user: {
        id: user[:id] || user["id"],
        role: user[:role] || user["role"]
      }
    }.to_json
  end

  get '/dashboard' do
    user = current_user
    Permissions.authorize!(user, ["user", "manager", "admin"])

    @tests = Database.get_test_overview # musíš vytvořit v database.rb

    content_type 'text/html'
    erb :dashboard
  end

  get '/dashboard/:test_id' do
    user = current_user
    Permissions.authorize!(user, ["user", "manager", "admin"])

    test_id = params[:test_id]
    
    # získáme test a jeho otázky
    @test = Database.get_test_by_id(test_id) # vytvořit v database.rb
    @questions = Database.get_questions_for_test(test_id) # vytvořit v database.rb

    content_type 'text/html'
    erb :dashboard_test
  end

  get '/exam' do
    user = current_user
    Permissions.authorize!(user, ["user", "manager", "admin"])

    @tests = Database.get_all_tests

    content_type 'text/html'
    erb :exam_index
  end

  # routes/exam_routes.rb
  get '/exam/:test_id' do
    user = current_user
    # povolené role: user, manager, admin
    Permissions.authorize!(user, ["user", "manager", "admin"])

    test_id = params[:test_id]

    # Získání testu a otázek z databáze
    @test = Database.get_test_by_id(test_id)            # Hash s detailem testu
    @questions = Database.get_questions_for_test(test_id) # Pole hashů otázek

    if @test.nil?
      status 404
      return "Test nenalezen"
    end

    content_type 'text/html'
    erb :exam_detail # název tvého ERB souboru s Tailwind designem
  end

  get '/exam/:test_id/:answer_id' do
    @user = current_user
    Permissions.authorize!(@user, ["user", "manager", "admin"])

    test_id = params[:test_id]
    answer_id = params[:answer_id]

    @logs = Database.get_logs_for_question(test_id, answer_id)

    @test = Database.get_test_by_id(test_id)
    @questions = Database.get_questions_for_test(test_id)

    @question = @questions.find { |q| q[:answer_id] == answer_id }
    halt 404, "Otázka nenalezena" if @question.nil?

    # Parsování answer_json pro seznam možností
    @question[:answers] = begin
      case @question[:answer_json]
      when String
        JSON.parse(@question[:answer_json])
      when Array
        @question[:answer_json]
      else
        []
      end
    rescue JSON::ParserError
      []
    end

    # Parsování question_json pro správnou odpověď
    correct_answer = begin
      parsed_question_json = case @question[:question_json]
                            when String
                              JSON.parse(@question[:question_json])
                            when Hash
                              @question[:question_json]
                            else
                              {}
                            end
      # Může být jedna odpověď nebo pole více správných odpovědí
      ans = parsed_question_json['answer']
      case ans
      when String
        [ans.strip]
      when Array
        ans.map(&:to_s).map(&:strip)
      else
        []
      end
    rescue JSON::ParserError
      []
    end

    @question[:answer] = correct_answer # vždy array, i když jen jedna odpověď

    # Navigace mezi otázkami
    current_index = @questions.index(@question)
    @question_index = current_index
    @questions_count = @questions.size
    @prev_question_id = current_index > 0 ? @questions[current_index - 1][:answer_id] : nil
    @next_question_id = current_index < @questions.size - 1 ? @questions[current_index + 1][:answer_id] : nil

    content_type 'text/html'
    erb :exam_question
  end

end
