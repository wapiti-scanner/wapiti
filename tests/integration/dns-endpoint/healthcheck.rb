require 'socket'

dns_server_ip = 'localhost'
dns_server_port = 53

begin
  Socket.tcp(dns_server_ip, dns_server_port, connect_timeout: 3) {}
  exit 0 # DNS server is reachable
rescue
  exit 1 # DNS server is not reachable
end
