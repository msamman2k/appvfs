#!/usr/bin/ruby

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

puts "Marshaling " + inpFile + " => " + outFile
code = RubyVM::InstructionSequence.compile_file inpFile
str = Marshal.dump(code.to_a)
File.open(outFile, 'wb') {|f| f.write(str) }
exit 0
