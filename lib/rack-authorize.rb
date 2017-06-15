require "oj"
require "loga"
require "rack/authorize"

# Loga initialization based on previous
# configuration if existing or rescue error
# to provide new configuration
begin 
  Loga.configuration.service_name = "RACK_AUTHORIZE"
  Loga.logger.formatter = Loga.configuration.send(:assign_formatter)
rescue Loga::ConfigurationError
  Loga.configure(
    filter_parameters: [:password],
    level: ENV["LOG_LEVEL"] || "DEBUG",
    format: :gelf,
    service_name: "RACK_AUTHORIZE",
    tags: [:uuid]
  )
end
