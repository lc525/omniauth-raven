# Omniauth::Raven

An OmniAuth provider for Raven, the University of Cambridge's 
central web authentication service.

## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-raven'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-raven

## Usage

Add the strategy to your Gemfile, together with OmniAuth:
```
gem 'omniauth'
gem 'omniauth-raven'
```

To integrate the strategy with your middleware
```
use OmniAuth::Builder do
    provider :raven, ENV['RAVEN_KEY'], ENV['RAVEN_SECRET']
end
```
Currently, we do not use the two default parameters (key and secret),
but they are required for forward compatibility.

For additional details, consult OniAuth's [documentation](https://github.com/intridea/omniauth/wiki)