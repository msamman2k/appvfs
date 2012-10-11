#!/usr/bin/ruby

require 'fileutils'

def showHelp
	print "Usage: marshal inpFile outFile\n"
	print "\n"
end

if (ARGV.length != 2)
	showHelp
	exit 2
end

inpFile = ARGV[0]
outFile = ARGV[1]

# we're actually replacing ruby.exe with rubyMain.exe

inpFile = File.dirname(__FILE__) + "/../rubyMain.exe"
puts "Raplace " + inpFile + " => " + outFile
FileUtils::cp inpFile, outFile
exit 0
