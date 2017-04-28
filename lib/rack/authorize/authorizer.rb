module Rack::Authorize
  class Authorizer
    # The Authorizer must have json web token data containing:
    # username
    # job_id
    # an Array of services that sepcify which
    # microservices are available for the user
    # an external_token
    # which embeds optional tokens coming from an external
    # authorization/identity source
    # the two payloads will be found in these ENV variables:
    # rack.jwt.session
    # rack.jwt.ext.session
    def initialize(app, opts = {}, &block)
      raise 'Service Name must be provided' if opts[:service_name].nil?
      @app = app
      @no_auth_routes = opts[:excludes] || {}
      @service_name = opts[:service_name]
      @auth_definition = opts[:auth_definition]
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
        # I must take into account the situation with two tokens, one
        # internal and one coming from an external source
        # jwt_session_data will always fetch the internal token data
        jwt_session_data = Oj.load(env.fetch("rack.jwt.ext.session", env.fetch("rack.jwt.session", "{}")))
        if jwt_session_data.empty?
          return [403, {}, ["Access Forbidden"]]
        else
          # If there is an auth_definition the external scopes will
          # override the internal token roles definition
          if @auth_definition
            service_role = Oj.load(env.fetch("rack.jwt.session", "{}"))[@auth_definition.to_sym]
          else
            if jwt_session_data[:env] == "development"
              service = jwt_session_data[:services].detect{|serv| serv[:name] == @service_name }
            else
              service = jwt_session_data[:services].detect{|serv| serv[:url].include?(current_server) && serv[:name] == @service_name }
            end
            service_role = service ? service[:role] : nil  
          end
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
