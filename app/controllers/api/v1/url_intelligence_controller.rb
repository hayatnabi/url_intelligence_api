require 'open-uri'
# require 'read-time'

class Api::V1::UrlIntelligenceController < ApplicationController
  def analyze
    url = params[:url]

    unless url.present? && url.match?(/\A#{URI::DEFAULT_PARSER.make_regexp(%w[http https])}\z/)
      return render json: { error: 'Invalid or missing URL' }, status: :bad_request
    end

    begin
      html = URI.open(url, "User-Agent" => "RailsBot/1.0").read
      doc = Nokogiri::HTML(html)

      metadata = {
        title: doc.at('title')&.text,
        description: doc.at('meta[name="description"]')&.[]('content'),
        og_title: doc.at('meta[property="og:title"]')&.[]('content'),
        og_description: doc.at('meta[property="og:description"]')&.[]('content')
      }

      language = CLD3::NNetLanguageIdentifier.new.find_language(html)&.language
      # reading_time = Readtime::ReadTime.new(html).minutes

      phishing_indicators = detect_phishing(url, html)

      # render json: {
      #   metadata: metadata,
      #   language: language,
      #   estimated_reading_time: "#{reading_time} min",
      #   phishing_indicators: phishing_indicators
      # }

      render json: {
        metadata: metadata,
        language: language,
        phishing_indicators: phishing_indicators
      }
    rescue => e
      render json: { error: "Failed to analyze URL: #{e.message}" }, status: :internal_server_error
    end
  end

  private

  def detect_phishing(url, html)
    bad_keywords = %w[login paypal banking confirm account verify password reset]
    score = bad_keywords.count { |kw| html.include?(kw) }

    suspicious = URI.parse(url).host.include?('-') || url.include?('@') || score > 3

    {
      suspicious: suspicious,
      score: score,
      flagged_keywords: bad_keywords.select { |kw| html.include?(kw) }
    }
  end
end
