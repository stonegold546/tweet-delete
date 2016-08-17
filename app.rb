require 'sinatra'
require 'config_env'
require 'rack/ssl-enforcer'
require 'httparty'
require 'slim'
require 'slim/include'
require 'json'
require 'tilt/kramdown'
require 'rbnacl/libsodium'
require 'base64'
require 'cgi'
require 'csv'
require 'yaml'

configure :development, :test do
  ConfigEnv.init("#{__dir__}/config/config_env.rb")
end

OAUTH_AUTH = 'https://api.twitter.com/oauth/authorize'
REQUEST_TOKEN = 'https://api.twitter.com/oauth/request_token'
ACCESS_TOKEN = 'https://api.twitter.com/oauth/access_token'
MAX_ID = '550332124134273024'
KEYBASE = '746773976282599424'

# Web App to delete old tweets
class DeleteTweetApp < Sinatra::Base
  enable :logging

  configure :development do
    set :root, 'http://127.0.0.1:9292/'
  end

  set :views, File.expand_path('../views', __FILE__)

  configure :production do
    use Rack::SslEnforcer
    set :session_secret, ENV['MSG_KEY']
    set :root, 'https://tweet-delete.herokuapp.com/'
  end

  configure do
    use Rack::Session::Pool, secret: settings.session_secret
  end

  def nonce
    secret_box = RbNaCl::SecretBox.new(Base64.urlsafe_decode64(ENV['TW_KEY']))
    nonce = RbNaCl::Random.random_bytes(secret_box.nonce_bytes)
    Base64.urlsafe_encode64 nonce
  end

  def base_headers(hash)
    time = Time.now.to_i
    { 'oauth_nonce' => nonce, 'oauth_version' => '1.0',
      'oauth_callback' => "#{settings.root}oauth_callback",
      'oauth_signature_method' => 'HMAC-SHA1', 'oauth_timestamp' => "#{time}",
      'oauth_consumer_key' => ENV['CONSUMER_KEY'] }.merge(hash)
  end

  def percent_encode(value)
    CGI.escape value
  end

  def sha_1(string, token_key = '')
    digest = OpenSSL::Digest.new('sha1')
    key = "#{ENV['CONSUMER_SECRET']}&#{token_key}"
    result = OpenSSL::HMAC.digest(digest, key, string)
    Base64.encode64 result
  end

  def build_header(hash)
    base = base_headers(hash)
    base.keys.sort.map do |key|
      [percent_encode(key.to_s), percent_encode(base[key])]
    end
  end

  def signature(method, hash, token_key = '')
    built_header = build_header(hash)
    result = percent_encode(built_header.map { |e| e.join('=') }.join('&'))
    method = method.map { |e| percent_encode e }.join('&')
    result = "#{method}&#{result}"
    result = sha_1(result, token_key)
    built_header << ['oauth_signature', percent_encode(result)]
    built_header
  end

  def header(method, hash, token_key = '')
    sign_results = signature(method, hash, token_key)
    data = sign_results.map do |key, value|
      "#{key}=\"#{value}\""
    end.join(', ')
    { 'authorization' => "OAuth #{data}" }
  end

  get '/' do
    header_fields = ['POST', REQUEST_TOKEN]
    header_data = header(header_fields, {})
    q = HTTParty.post REQUEST_TOKEN, headers: header_data
    result = q.body.split('&').map { |e| e.split('=') }.to_h
    session[:oauth_token] = result['oauth_token']
    session[:oauth_token_secret] = result['oauth_token_secret']
    slim :index, locals: { oauth_auth: OAUTH_AUTH,
                           oauth_token: result['oauth_token'] }
  end

  get '/oauth_callback/?' do
    decider = session[:oauth_token].hash - params['oauth_token'].hash
    if decider == 0
      oauth_token = params['oauth_token']
      header_fields = [
        'POST', "#{ACCESS_TOKEN}?oauth_verifier=#{params['oauth_verifier']}"
      ]
      header_data = header(
        header_fields, { 'oauth_token' => oauth_token }, oauth_token
      )
      q = HTTParty
          .post "#{ACCESS_TOKEN}?oauth_verifier=#{params['oauth_verifier']}",
                headers: header_data
      result = q.body.split('&').map { |e| e.split('=') }.to_h
      session[:oauth_token] = result['oauth_token']
      session[:oauth_token_secret] = result['oauth_token_secret']
      session[:user_id] = result['user_id']
      @logged_in = true
      redirect '/delete_tweets'
    end
  end

  get '/delete_tweets/?' do
    slim :delete
  end

  def tweet_url(id)
    "https://api.twitter.com/1.1/statuses/destroy/#{id}.json"
  end

  post '/delete_tweets/?' do
    tweet_ids = CSV.foreach(params['id_file']).map { |row| row[0] }
    tweet_ids = tweet_ids.select { |e| e.to_i < params['max_tweet_id'].to_i }
    done = YAML.load_file('tweets.yml')
    done_tweets = []
    done ? done_tweets = done : done = []
    tweet_ids -= done
    oauth_token = session[:oauth_token]
    oauth_token_secret = session[:oauth_token_secret]
    tweet_ids.each do |id|
      next if id == KEYBASE
      begin
        url = tweet_url(id)
        header_data = header(
          ['POST', url], { 'oauth_token' => oauth_token }, oauth_token_secret)
        q = HTTParty.post url, headers: header_data
        done_tweets << id
        f = File.new('tweets.yml', 'w+')
        f.write(done_tweets.to_yaml)
        f.close
        print id + ': ' + q.code.to_s + "\t"
      rescue
        puts "\nTEST!\n\n"
        sleep 30
        redo
      end
      # puts q.headers.inspect + "\n"
      # sleep 03
    end
  end
end
