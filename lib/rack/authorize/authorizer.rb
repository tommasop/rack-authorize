module Rack::Authorize
  class Authorizer
    def initialize(app, opts = {}, &block)
      @app = app
      @no_auth_routes = opts[:exclude] || nil
      @block = block
    end

    def call(env)
      if authorizable_route?(env)
        method = env["REQUEST_METHOD"]
        path = env["PATH_INFO"]
        # The JWT payload is saved in rack.jwt.session the scopes key is scopes
        scopes = env.fetch("rack.jwt.session", {})[:scopes] 
        return [403, {}, ["Access Forbidden"]] unless @block.call(method, path, scopes)
      end
      @app.call(env)
    end

    private


    def authorizable_route?(env)
      if @no_auth_routes.length > 0
        !@no_auth_routes.find { |route| route =~ env['PATH_INFO'] }
      end
    end
  end
end
