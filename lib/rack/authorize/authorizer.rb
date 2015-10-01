module Rack::Authorize
  class Authorizer
    def initialize(app, &block)
      @app = app
      @block = block
      # Is the env in which jwt token scopes can
      # be found.
    end

    def call(env)
      method = env["REQUEST_METHOD"]
      path = env["PATH_INFO"]
      # The JWT payload is saved in rack.jwt.session the scopes key is scopes
      scopes = env["rack.jwt.session"]["scopes"] || nil 
      return [403, {}, ["Access Forbidden"]] unless @block.call(method, path, scopes)
      @app.call(env)
    end
  end
end
