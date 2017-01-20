require "yufu/version"
require 'openssl'
require 'jwt'

module Yufu
  class YufuAuth
    class ClaimInvalid < StandardError; end

    AUTH_URL = 'https://idp.yufuid.com/sso/v1/consume'
    REQUIRED_CLAIMS_FIELD = ['sub', 'iat', 'exp']
    EXPIRATION_SECS = 10 * 60
    ALG = 'RS256'

    def idp=(idp)
      @idp = idp
    end

    def tenent=(tenent)
      @tenent = tenent
    end

    def private_key_path=(private_key_path)
      @private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))
    end

    def public_key_path=(public_key_path)
      @public_key = OpenSSL::PKey::RSA.new(File.read(public_key_path))
    end

    def generateIDPRedirectUrl(payload)
      headers = {
        kid: @idp,
      }
      payload[:aud] = AUTH_URL
      payload[:iss] = @idp
      payload[:tnt] = @tenent
      payload[:iat] = Time.now.to_i
      payload[:exp] = Time.now.to_i + EXPIRATION_SECS

      idp_token = JWT.encode(payload, @private_key, ALG, headers)
      url = AUTH_URL + '?idp_token=' + idp_token
      url
    end

    def verify(token)
      @decoded ||= ::JWT.decode(token, @public_key)
      (REQUIRED_CLAIMS_FIELD || []).each do |field|
        raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded[0].key?(field.to_s)
      end
      raise ClaimInvalid.new("Token has expired.") if Time.now.to_i < @decoded["iat"] || Time.now.to_i > @decoded['exp']
      
      @decoded
    end

    def getSubject
      @decoded[0]['sub'] 
    end

    def getClaims
      @decoded[0]
    end
  end
end
