require "rack/authorize/version"


require "rack/authorize/ability"
require "rack/authorize/rule"
require "rack/authorize/authorizer"
module Rack
  module Authorize
    def self.new(app, scopes = {}, &block)
      Authorizer.new(app, scopes, &block)
    end
  end
end
