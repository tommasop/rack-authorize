require "rack/authorize/version"


require "rack/authorize/ability"
require "rack/authorize/rule"
require "rack/authorize/authorizer"
module Rack
  module Authorize
    def self.new(app, opts={}, &block)
      Authorizer.new(app, opts, &block)
    end
  end
end
