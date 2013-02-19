require 'omniauth'

module OmniAuth
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
	        :msg => 'You are required to authenticate with Raven to access Gitlab',
	        :iact => '0',
	        :aauth => '',
	        :fail => 'No',
	        :max_skew => 90 #seconds
      	}
	    
	    def request_phase

			params = session['request_id'] = rand( 999999 ).to_s

	    	auth_url = options[:raven_opt][:url] << 
	    			   "?ver="    << uriescape(options[:raven_opt][:version]) <<
	    			   ";url="    << uriescape(callback_url) <<
	    			   ";desc="   << uriescape(options[:raven_opt][:desc]) <<
	    			   ";msg="    << uriescape(options[:raven_opt][:msg]) <<
	    			   ";iact="   << uriescape(options[:raven_opt][:iact]) <<
	    			   ";aauth="  << uriescape(options[:raven_opt][:aauth]) <<
	    			   ";params=" << uriescape(params) <<
	    			   ";fail="   << uriescape(options[:raven_opt][:fail])

			return redirect auth_url
	    end

	    def callback_phase

	    	return fail!(:invalid_response) if request.params['WLS-Response'] == ""
		
			wls_response = request.params['WLS-Response'].to_s
			ver, status, msg, issue, id, url, principal, auth, sso, life, params, kid, sig = wls_response.split('!')

			return fail!(:invalid_credentials) if status != "200"

			@name = principal
			@email = principal+"@cam.ac.uk"

			super

	    end

	    uid  { @email }
	    info { 
	    	options[:fields][:name] = @name
	    	options[:fields][:email] = @email
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
	end
    end
end