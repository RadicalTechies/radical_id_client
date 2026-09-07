RadicalIdClient::Rails::Engine.routes.draw do
  root "admin#index"
  post "lookup", to: "admin#lookup"
  post "provision", to: "admin#provision"
  post "impersonate", to: "admin#impersonate"
  delete "stop", to: "admin#stop"
end
