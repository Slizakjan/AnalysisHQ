module Database
  # ----------------------
  # Testy
  # ----------------------

  # Vrátí přehled všech testů (pro /exam)
  def self.get_all_tests
    result = DB.exec(
      "SELECT 
         test_id, 
         exam_name, 
         COUNT(*) AS question_count,
         MAX(created_at) AS last_added_at
       FROM question_bank
       GROUP BY test_id, exam_name
       ORDER BY last_added_at DESC"
    )

    result.map do |row|
      {
        test_id: row['test_id'],
        exam_name: row['exam_name'],
        question_count: row['question_count'].to_i,
        last_added_at: row['last_added_at']
      }
    end
  end

  # Vrací přehled všech testů pro dashboard
  def self.get_test_overview
    result = DB.exec(
      "SELECT test_id, exam_name, COUNT(*) AS question_count
       FROM question_bank
       GROUP BY test_id, exam_name
       ORDER BY exam_name"
    )

    result.map do |row|
      {
        test_id: row['test_id'],
        exam_name: row['exam_name'],
        question_count: row['question_count'].to_i
      }
    end
  end

  # Vrací detail testu podle test_id
  def self.get_test_by_id(test_id)
    result = DB.exec_params(
      "SELECT test_id, exam_name, COUNT(*) AS question_count
       FROM question_bank
       WHERE test_id = $1
       GROUP BY test_id, exam_name
       LIMIT 1",
      [test_id]
    )

    return nil if result.ntuples == 0

    row = result[0]
    {
      test_id: row['test_id'],
      exam_name: row['exam_name'],
      question_count: row['question_count'].to_i
    }
  end

  # ----------------------
  # Otázky
  # ----------------------

  # Vrací všechny otázky pro daný test
  def self.get_questions_for_test(test_id)
    result = DB.exec_params("SELECT * FROM question_bank WHERE test_id = $1 ORDER BY created_at", [test_id])
    
    result.map do |row|
      {
        answer_id: row['answer_id'],
        test_id: row['test_id'],
        exam_name: row['exam_name'],
        question: row['question'] || "",
        options: row['options'] ? JSON.parse(row['options']) : [],
        correct_answer: row['correct_answer'],
        type: row['type'] || 'radio'
      }
    end
  end

  # Vrací jednu otázku podle test_id a answer_id
  def self.get_question_by_id(test_id, answer_id)
    result = DB.exec_params(
      "SELECT * FROM question_bank
       WHERE test_id = $1 AND answer_id = $2 LIMIT 1",
      [test_id, answer_id]
    )
    return nil if result.ntuples == 0

    row = result[0]
    {
      answer_id: row['answer_id'],
      test_id: row['test_id'],
      exam_name: row['exam_name'],
      question: row['question'] || "",
      options: row['options'] ? JSON.parse(row['options']) : [],
      correct_answer: row['correct_answer'],
      type: row['type'] || 'radio'
    }
  end

  # Aktualizuje otázku
  def self.update_question_answer(test_id:, answer_id:, question:, options:, correct_answer:, type:)
    DB.exec_params(
      "UPDATE question_bank
       SET question = $1,
           options = $2::jsonb,
           correct_answer = $3,
           type = $4
       WHERE test_id = $5 AND answer_id = $6",
      [question, JSON.dump(options), correct_answer, type, test_id, answer_id]
    )
  end

  # Vloží novou otázku
  def self.insert_question(user_id:, test_id:, answer_id:, question:, options:, correct_answer:, type: 'radio', exam_name: "")
    raise ArgumentError, "question must be a string" unless question.is_a?(String)
    raise ArgumentError, "options must be an array or hash" unless options.is_a?(Array) || options.is_a?(Hash)

    # Kontrola duplicity
    existing = DB.exec_params("SELECT 1 FROM question_bank WHERE answer_id = $1 LIMIT 1", [answer_id])
    return if existing.any? # pokud existuje, ignoruj vložení

    DB.exec_params(
      <<~SQL,
        INSERT INTO question_bank (user_id, test_id, answer_id, question, options, correct_answer, type, exam_name, created_at)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, NOW())
      SQL
      [user_id, test_id, answer_id, question, JSON.dump(options), correct_answer, type, exam_name]
    )
  end

  # ----------------------
  # Logy
  # ----------------------

  def self.get_logs_for_question(test_id, answer_id)
    result = DB.exec_params(
      "SELECT api_key_hash, action, metadata, created_at
       FROM api_answer_logs
       WHERE test_id = $1 AND answer_id = $2
       ORDER BY created_at ASC",
      [test_id, answer_id]
    )
    result.map do |row|
      {
        api_key_hash: row["api_key_hash"],
        action: row["action"],
        metadata: row["metadata"] ? JSON.parse(row["metadata"]) : {},
        created_at: Time.parse(row["created_at"])
      }
    end
  end

  def self.insert_log(api_key_hash, test_id, answer_id, action, metadata = {})
    raise ArgumentError, "Missing required parameters" if [api_key_hash, test_id, answer_id, action].any?(&:nil?)

    DB.exec_params(
      "INSERT INTO api_answer_logs (api_key_hash, test_id, answer_id, action, metadata, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())",
      [api_key_hash, test_id, answer_id, action, JSON.dump(metadata)]
    )
  rescue PG::Error => e
    puts "[DB ERROR] Failed to insert log: #{e.message}"
    raise
  end

  # ----------------------
  # Uživatelé
  # ----------------------

  def self.find_user_by_username(username)
    result = DB.exec_params("SELECT * FROM users WHERE username = $1 LIMIT 1", [username])
    return nil if result.ntuples < 1
    user_record_to_hash(result[0])
  end

  def self.find_user_by_id(id)
    result = DB.exec_params("SELECT * FROM users WHERE id = $1 LIMIT 1", [id])
    return nil if result.ntuples < 1
    user_record_to_hash(result[0])
  end

  def self.get_user_by_api_key(api_key)
    return nil unless api_key
    result = DB.exec_params("SELECT * FROM users WHERE api_key_hash = $1 LIMIT 1", [api_key])
    return nil if result.ntuples < 1
    user_record_to_hash(result[0])
  end

  def self.create_user(username, password_hash, role)
    result = DB.exec_params(
      "INSERT INTO users (username, password_hash, role)
       VALUES ($1, $2, $3) RETURNING *",
      [username, password_hash, role]
    )
    user_record_to_hash(result[0])
  end

  def self.set_api_key_hash(user_id, api_hash)
    DB.exec_params("UPDATE users SET api_key_hash = $1 WHERE id = $2", [api_hash, user_id])
  end

  def self.update_last_login(id)
    DB.exec_params("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [id])
  end

  def self.increase_failed_attempts(id)
    DB.exec_params("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = $1", [id])
  end

  def self.reset_failed_attempts(id)
    DB.exec_params("UPDATE users SET failed_attempts = 0 WHERE id = $1", [id])
  end

  def self.lock_account(id)
    DB.exec_params("UPDATE users SET locked = TRUE WHERE id = $1", [id])
  end

  # ----------------------
  # Aliasy pro Authenticator
  # ----------------------
  def self.get_user_by_username(username)
    find_user_by_username(username)
  end

  def self.get_user_by_id(id)
    find_user_by_id(id)
  end

  def self.increment_failed_attempts(id)
    increase_failed_attempts(id)
  end

  def self.lock_user(id)
    lock_account(id)
  end

  def self.user_count
    result = DB.exec("SELECT COUNT(*) FROM users")
    result[0]['count'].to_i
  end

  def self.pair_user_api_key(user_id, api_key_hash)
    set_api_key_hash(user_id, api_key_hash)
  end

  # ----------------------
  # Pomocné metody
  # ----------------------
  private

  def self.user_record_to_hash(user)
    {
      id: user['id'].to_i,
      username: user['username'],
      password_hash: user['password_hash'],
      role: user['role'],
      api_key_hash: user['api_key_hash'],
      failed_attempts: user['failed_attempts'].to_i,
      locked: user['locked'] == 't' || user['locked'] == true,
      last_login: user['last_login'],
      created_at: user['created_at']
    }
  end
end
