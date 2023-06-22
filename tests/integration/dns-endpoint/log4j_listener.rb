#!/usr/bin/env ruby
require 'rubydns'
require 'sqlite3'

INTERFACES = [
	[:udp, "0.0.0.0", 53],
	[:tcp, "0.0.0.0", 53],
]

File.delete("dns-entries.db") if File.exist?("dns-entries.db")
db = SQLite3::Database.new "dns-entries.db"

# Create a database
rows = db.execute <<-SQL
  create table entries (
    name varchar(128),
    val int
  );
  create index index_name ON entries(name);
SQL

IN = Resolv::DNS::Resource::IN

# Use upstream DNS for name resolution.
UPSTREAM = RubyDNS::Resolver.new([[:udp, "8.8.8.8", 53], [:tcp, "8.8.8.8", 53]])

# Start the RubyDNS server
RubyDNS::run_server(INTERFACES) do
	match(/(.+)\.l/, IN::TXT) do |transaction, match_data|
		name = match_data[1]
		puts "Nouvel enregistrement : #{name}"
		db.execute("INSERT INTO entries (name, val) VALUES (?, ?)", [name, 1])
		transaction.respond!("true")
	end

	match(/(.+)\.c/, IN::TXT) do |transaction, match_data|
		name = match_data[1]
		puts "Lecture de : #{name}"
		entries = db.get_first_row("SELECT * FROM entries WHERE name=?", name)
		if entries && (entries[1] == 1) # Check if the entry is here and if the value is set at 1
			transaction.respond!("true")
		else
			transaction.respond!("false")
		end
	end

	# Default DNS handler
	otherwise do |transaction|
		transaction.fail!(:NXDomain)
		#db.execute("INSERT INTO entries (name, val) VALUES (?, ?)", )
	end
end
