module Rack::Authorize
  class Authorizer
    def initialize(app, opts = {}, &block)
      @app = app
      @no_auth_routes = opts[:excludes] || {}
      @auth_definition = opts[:auth_definition] || "scopes"
      @block = block
    end

    def call(env)
      #puts env
      if authorizable_route?(env)
        method = env["REQUEST_METHOD"]
        path = env["PATH_INFO"]
        # The JWT payload is saved in rack.jwt.session the scopes key is scopes
        #puts "----------------------------"
        #puts env
        #puts "----------------------------"
        scopes = Oj.load(env.fetch("rack.jwt.session", {})[@auth_definition])
        return [403, {}, ["Access Forbidden"]] unless @block.call(method, path, scopes)
      end
      @app.call(env)
    end

    private

    def authorizable_route?(env)
      if @no_auth_routes.length > 0
        !@no_auth_routes.find do |route| 
          if route =~ /\*/
            env['PATH_INFO'] =~ /#{route.chomp("*")}/
          else
            route =~ /#{env['PATH_INFO']}/ 
          end
        end
      end
    end
  end
end
