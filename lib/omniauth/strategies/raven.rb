require 'omniauth'

module OmniAuth

	def self.raven_pubkey
		@raven_pubkey ||= File.read File.expand_path(File.dirname(__FILE__))+'pubkey2.pem'
	end

	def self.raven_keyno
		@raven_keyno = 2
	end

    module Strategies

	class Raven
	    include OmniAuth::Strategy
	    
	    args [:app_key, :app_secret]

	    option :fields, [:name, :email]
	    option :uid_field, :email

	    option :raven_opt, {
	        :url => 'https://raven.cam.ac.uk/auth/authenticate.html',
	        :version => '1',
	        :desc => 'DTG Gitlab',
	        :msg => 'you are required to authenticate with Raven to access Gitlab',
	        :iact => '', # 'yes' to force auth, 'no' to succeed only if no interraction needs to take place
	        :aauth => '',
	        :fail => 'no',
	        :max_skew => 90 #seconds
      	}
	    
	    def request_phase

			params = session['request_id'] = rand( 999999 ).to_s

	    	auth_url = options[:raven_opt][:url] + 
	    			   "?ver="    + uriescape(options[:raven_opt][:version]) +
	    			   ";url="    + uriescape(callback_url) +
	    			   ";desc="   + uriescape(options[:raven_opt][:desc]) +
	    			   ";msg="    + uriescape(options[:raven_opt][:msg]) +
	    			   ";iact="   + uriescape(options[:raven_opt][:iact]) +
	    			   ";aauth="  + uriescape(options[:raven_opt][:aauth]) +
	    			   ";params=" + uriescape(params) +
	    			   ";fail="   + uriescape(options[:raven_opt][:fail])

			return redirect auth_url
	    end

	    def callback_phase

	    	return fail!("null_response") if request.params['WLS-Response'] == ""
		
			wls_response = request.params['WLS-Response'].to_s
			ver, status, msg, issue, id, url, principal, auth, sso, life, params, kid, sig = wls_response.split('!')

			#Check the protocol version
			return fail!("invalid_protocol_version") unless ver == options[:raven_opt][:version]
			
			#Check the url
			return fail!("mismatched urls", Exception.new("url: " + url + " vs callback: " + callback_url) ) unless url == callback_url.split('?').first
		
			#Check the time skew
			issuetime = timeforRFC3339( issue )
			skew = issuetime - Time.now
			return fail!("time_skew") unless skew.abs < options[:raven_opt][:max_skew]

			#Optionally check that interaction with the user took place
			return fail!(:invalid_response, Exception.new("No raven interaction took place, but it was requested") ) if ( options[:raven_opt][:iact] == 'yes' &&  auth == "" )
			
			#Optionally check that this response matches a request
			if @match_response_and_request
				response_id = unescape( params )
				request_id = session['request_id']
				return fail!("mismatched_response", Exception.new("req_id:" + request_id + " vs resp_id:" + response_id) ) unless request_id == response_id
			end
			
			#If we got here, and status is 200, then yield the principal
			if status == '200'
				#Check that the Key Id is one we currently accept
				publickey = OmniAuth.raven_pubkey
				return fail!("invalid_keyno") unless kid == OmniAuth.raven_keyno
				
				#Check the signature
				length_to_drop = -(sig.length + kid.length + 3)
				signedbit = wls_response[ 0 .. length_to_drop]
				return fail!("mismatched_signature") unless publickey.verify( OpenSSL::Digest::SHA1.new, Base64.decode64(sig.tr('-._','+/=')), signedbit)	

				# Return the status
				@name = principal
				@email = principal+"@cam.ac.uk"

				super
			else
				#And return the error code if it is something else.
				return fail!(:invalid_credentials, Exception.new("Raven status:" + status) )
			end
			
	    end

	    uid  { @email }
	    info { 
	    	{:name  => @name,
	    	 :email => @email}
	    }

	    private 

	    def timeforRFC3339( rfc3339 )
			year = rfc3339[ 0..3 ].to_i
			month = rfc3339[ 4..5 ].to_i
			day = rfc3339[ 6..7 ].to_i
			hour = rfc3339[ 9..10 ].to_i
			minute = rfc3339[ 11..12 ].to_i
			second = rfc3339[ 13..14 ].to_i
			return Time.gm( year, month, day, hour, minute, second)
		end

		def uriescape(string)
		  string.gsub(/([^ a-zA-Z0-9_.-]+)/) do
		    '%' + $1.unpack('H2' * $1.bytesize).join('%').upcase
		  end.tr(' ', '+')
		end

		def unescape(string)
		  str=string.tr('+', ' ').force_encoding(Encoding::ASCII_8BIT).gsub(/((?:%[0-9a-fA-F]{2})+)/) do
		    [$1.delete('%')].pack('H*')
		  end.force_encoding(Encoding::ASCII_8BIT)
		  str.valid_encoding? ? str : str.force_encoding(string.encoding)
		end
	end
    end
end