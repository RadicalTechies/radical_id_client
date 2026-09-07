Gem::Specification.new do |spec|
  spec.name = "radical_id_client"
  spec.version = "0.1.0"
  spec.summary = "Scoped Radical ID API client and optional Rails administration"
  spec.authors = [ "Radical Tech Team" ]
  spec.license = "AGPL-3.0-only"
  spec.homepage = "https://github.com/RadicalTechies/radical_id_client"
  spec.required_ruby_version = ">= 3.3"
  spec.files = Dir["lib/**/*", "app/**/*", "config/**/*", "README.md", "LICENSE"]
  spec.add_dependency "net-http", ">= 0.4"
end
