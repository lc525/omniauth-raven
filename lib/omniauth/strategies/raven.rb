require 'omniauth/core'
require 'cgi'

module OmniAuth
    module Strategies

    # Two new methods are added to the Standard CGI class.
	class CGI 
		# Perhaps not a great place for this, but rfc3339 is an internet standard ....
		# Takes a string with a time encoded according to rfc3339 and returns a Time object.
		def timeforRFC3339( rfc3339 )
			year = rfc3339[ 0..3 ].to_i
			month = rfc3339[ 4..5 ].to_i
			day = rfc3339[ 6..7 ].to_i
			hour = rfc3339[ 9..10 ].to_i
			minute = rfc3339[ 11..12 ].to_i
			second = rfc3339[ 13..14 ].to_i
			return Time.gm( year, month, day, hour, minute, second)
		end
	end


	class Raven
	    include OmniAuth::Strategy
	    
	    option :fields, [:name, :email]
	    option :uid_field, :email

	    option :raven_opt, {
	        :url => 'https://raven.cam.ac.uk/auth/authenticate.html',
	        :version => '1',
	        :desc => 'DTG Gitlab',
	        :msg => 'You are required to authenticate with Raven to access Gitlab',
	        :iact => '0',
	        :aauth => ,
	        :fail => 'No',
	        :max_skew => 90 #seconds
      	}
	    
	    def request_phase

			params = session['request_id'] = rand( 999999 ).to_s

	    	auth_url = options[:raven_opt][:url] << 
	    			   "?ver="    << CGI.escape(options[:raven_opt][:version]) <<
	    			   ";url="    << CGI.escape(callback_path) <<
	    			   ";desc="   << CGI.escape(options[:raven_opt][:desc]) <<
	    			   ";msg="    << CGI.escape(options[:raven_opt][:msg]) <<
	    			   ";iact="   << CGI.escape(options[:raven_opt][:iact]) <<
	    			   ";aauth="  << CGI.escape(options[:raven_opt][:aauth]) <<
	    			   ";params=" << CGI.escape(params) <<
	    			   ";fail="   << CGI.escape(options[:raven_opt][:fail])

			return redirect auth_url
	    end
	end
    end
end