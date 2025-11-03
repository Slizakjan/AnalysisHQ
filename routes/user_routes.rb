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

    # ----------------------
    # Seznam všech testů
    # ----------------------
    get '/exam' do
      user = current_user
      Permissions.authorize!(user, ["user", "manager", "admin"])

      @tests = Database.get_all_tests

      content_type 'text/html'
      erb :exam_index
    end

    # ----------------------
    # Detail konkrétního testu
    # ----------------------
    get '/exam/:test_id' do
      user = current_user
      Permissions.authorize!(user, ["user", "manager", "admin"])

      test_id = params[:test_id]

      @test = Database.get_test_by_id(test_id)
      @questions = Database.get_questions_for_test(test_id)

      if @test.nil?
        status 404
        return "Test nenalezen"
      end

      content_type 'text/html'
      erb :exam_detail
    end

    # ----------------------
    # Detail konkrétní otázky
    # ----------------------
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

      # --- Nové názvy sloupců ---
      # `options` = JSONB (seznam možných odpovědí)
      # `question` = TEXT (text otázky)
      # `correct_answer` = TEXT (správná odpověď)
      # `type` = typ otázky (radio, checkbox, short, descriptive)

      # Získání seznamu odpovědí z JSONB `options`
      @question[:answers] = begin
        case @question[:options]
        when String
          JSON.parse(@question[:options])
        when Array
          @question[:options]
        else
          []
        end
      rescue JSON::ParserError
        []
      end

      # Správná odpověď – vždy pole (i pro single)
      correct_answer = case @question[:correct_answer]
                      when String
                        [@question[:correct_answer].strip]
                      when Array
                        @question[:correct_answer].map(&:strip)
                      else
                        []
                      end
      @question[:answer] = correct_answer

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
