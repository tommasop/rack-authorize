module Rack::Authorize
  class Authorizer
    def initialize(app, opts = {}, &block)
      @app = app
      @no_auth_routes = opts[:excludes] || {}
      @auth_definition = opts[:auth_definition] || "scopes"
      @block = block
    end
    
    def call(env)
      dup._call(env)
    end

    def _call(env)
      #puts env
      if authorizable_route?(env)
        method = env["REQUEST_METHOD"]
        path = env["PATH_INFO"]
        # The JWT payload is saved in rack.jwt.session the scopes key is scopes
        #puts "----------------------------"
        #puts env
        #puts "----------------------------"
        if Object.constants.include?(:Rails)
          jwt_session_data = env.fetch('rack.session', {}).fetch("jwt_token", {})
        else
          jwt_session_data = env.fetch("rack.jwt.session", {})
        end
        if jwt_session_data.is_a? String
          jwt_session_data = Oj.load(jwt_session_data)
          scopes = jwt_session_data.fetch(@auth_definition.to_sym, {})
        else
          scopes = Oj.load(jwt_session_data[@auth_definition])
        end
        if Object.constants.include?(:Rails)
          env["rack_session"]["jwt_authorized"] = @block.call(method, path, scopes)
        else
          return [403, {}, ["Access Forbidden"]] unless @block.call(method, path, scopes)
        end
      end
      @app.call(env)
    end

    private

    def authorizable_route?(env)
      if @no_auth_routes.length > 0
        !@no_auth_routes.find do |route| 
          # This checks if the excluded route has a trailing *
          # if it does it checks the path with the route as
          # its regexp thus checking a partial match
          if route =~ /\*$/
            env['PATH_INFO'] =~ /#{route.chomp("*")}/
          # Otherwise it checks the route with the path
          # as its regexp thus checking a complete match
          else
            route =~ /#{env['PATH_INFO']}/ 
          end
        end
      end
    end
  end
end
