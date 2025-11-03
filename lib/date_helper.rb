module DateHelper
  def format_date(timestamp)
    return "-" if timestamp.nil? || timestamp.empty?
    Time.parse(timestamp.to_s).strftime("%d.%m.%Y %H:%M")
  rescue ArgumentError
    timestamp.to_s
  end
end
