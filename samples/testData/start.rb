#load "./init.rb"
print "++++++ running start.rb\n"
require "zlib"
require "app/start2.rb"
require "app/start2"
load "app/dir1/dir1_scr.rb"
load "data/bc1.rb"
# check GEM_HOME 
# see http://www.skorks.com/2009/08/digging-into-a-ruby-installation-require-vs-load/
print "HOME  = " + ENV["HOME"] + "\n";
if ENV["GEM_HOME"] != nil
	print "GEM_HOME  = " + ENV["GEM_HOME"] + "\n";
end
if ENV["RUBYPATH"] != nil
	print "RUBYPATH  = " + ENV["RUBYPATH"] + "\n";
end
puts "Ruby search path:"
puts $:

Dir.glob("subdir/**/*") do |d|
	puts "\tsub: " + d;
end

fh= File.new "file.txt", "w" 
fh.syswrite "Hello World!\r\n" 
fh.close


