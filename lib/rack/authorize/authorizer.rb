module Rack::Authorize
  class Authorizer
    def initialize(app, opts = {}, &block)
      raise 'Service Name must be provided' if opts[:service_name].nil?
      @app = app
      @no_auth_routes = opts[:excludes] || {}
      @service_name = opts[:service_name]
      @block = block
    end
    
    def call(env)
      if authorizable_route?(env)
        method = env["REQUEST_METHOD"]
        path = env["PATH_INFO"]
        current_server = env["SERVER_NAME"]
        # The JWT payload is saved in rack.jwt.session the scopes key is scopes
        puts "----------------------------"
        puts env
        puts "----------------------------"
        jwt_session_data = Oj.load(env.fetch("rack.jwt.session", "{}"))
        if jwt_session_data.empty?
          return [403, {}, ["Access Forbidden"]]
        else
          service_role = jwt_session_data[:services].detect{|serv| serv[:url].include?(current_server) && serv[:name] == @service_name }[:role] 
        end
        return [403, {}, ["Access Forbidden"]] unless @block.call(method, path, service_role)
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
