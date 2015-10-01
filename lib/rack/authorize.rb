require "rack/authorize/version"


require "rack/authorize/ability"
require "rack/authorize/rule"
require "rack/authorize/authorizer"
module Rack
  module Authorize
    def self.new(app, excludes = nil, &block)
      Authorizer.new(app, excludes, &block)
    end
  end
end
