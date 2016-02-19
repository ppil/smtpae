#!/usr/bin/python
#
# SMTP attachment extractor v1.3
# Peter Pilarski
import sys
import os
from email import message_from_string
from re import sub as re_sub
from getopt import getopt, GetoptError
from subprocess import call
outDIR="./attachments" # Default output DIR
flowDIR="./SMTP_flows" # Default flow DIR
flagM=0 # bool: Message header, text, html
verbose=1 # bool: Use STDOUT?
debug=0 # bool: If you're havin' execution problems, I feel bad for you son...
class App:
	def usage(self):
		print """SMTP attachment extractor

Usage:
	-f <file>, --file <file>
		Specify .pcap file to read from.

	-s <DIR>, --smtp <DIR>
		Specify DIR containing already-extracted SMTP flows. \n\t\t(Ignored if .pcap is given)

	-d <DIR>, --dir <DIR>
		Specify DIR to save contents into. \n\t\t(Optional. Default = ./attachments)

	-m
		Extract message header, text, and HTML.

	-q
		Quiet, don't send anything to STDOUT.

	-h, --help
		Wait, what?
	"""
	
	def main(self):
		pcap = self.readArgs()# Read CLI args
		if pcap: self.readPcap(pcap)# Extract SMTP flows
		self.readFlows()# Parse flows, extract things
		
	def readArgs(self):
		global outDIR, debug, flagM, flowDIR, verbose
		if debug: print "Parsing args..."
		pcap = None
		try:
			opts, args = getopt(sys.argv[1:], 'hqmf:d:s:', ['file=','dir=','smtp=','help'])
		except GetoptError as err:
			print str(err)
			self.usage()
			sys.exit(2)
		for o, a in opts:
			if debug: print o, a
			if o in ("-f", "--file"):# .pcap
				if os.path.isfile(a):
					if debug: print ".pcap: ",os.path.realpath(a)
					pcap = os.path.realpath(a)
				else:
					print "Error: %s is not a valid file!" % a
					self.usage()
					sys.exit(1)
			elif o in ("-d", "--dir"):# Output DIR
				if debug: print "outDIR: ",os.path.realpath(a)
				outDIR=os.path.realpath(a)
			elif o in ("-s", "--smtp"):# SMTP flow DIR
				if debug: print "flowDIR: ",os.path.realpath(a)
				flowDIR=os.path.realpath(a)
			elif o == "-m":# Message header/text/html
				flagM=1
			elif o == "-q":# Quiet
				verbose=0
			elif o in ("-h", "--help"):# Help
				self.usage()
				sys.exit(1)
		# Require that user specifies a .pcap or flow DIR
		if (("-f" not in sys.argv[1:]) and ("--file" not in sys.argv[1:]))\
		and (("-s" not in sys.argv[1:]) and ("--smtp" not in sys.argv[1:])):
			print "Error: no .pcap file or flow DIR specified!"
			self.usage()
			sys.exit(1)
		return pcap

	def readPcap(self, pcapFile):
		# Execute tcpflow to read pcap and extract SMTP flows
		# Make flow subdir if not already made
		if os.path.isdir("./flowz") == False: os.mkdir("./flowz", 0755)
		if debug: print "Executing tcpflow..."
		# cd into it and extract SMTP flows
		call("cd ./flowz; /usr/bin/tcpflow -r %s 'tcp port 587 or tcp port 25 or tcp port 2525'" % pcapFile, shell=True)

	def readFlows(self):
		global outDIR, debug, verbose, flowDIR
		flowList = os.listdir(flowDIR)
		smtpData = None
		if debug: print "Reading flows from %s..." % flowDIR
		for flow in flowList:
			if flow.split('/')[-1]=="report.xml":continue# Ignore this file
			if debug or verbose: print "Current flow:", flow
			with open(os.path.join(flowDIR, flow), 'r') as inFlow:
				# Support SMTP (HELO) and Extended SMTP (EHLO)
				if inFlow.readline().split(' ')[0] in ("EHLO", "HELO"):
					if debug: print "Opened file"; count=1
					while True:
						if debug: count+=1; print "In a while...", count-1;
						line = inFlow.readline()
						# Look for message contents (after DATA command)
						if line.rstrip() == "DATA":
							if debug: print "Found DATA at line ", count
							# Read the rest of the file into variable
							smtpData = inFlow.read()
							break
				else:
					inFlow.read()# Disregard this file, read until EOF
			if smtpData:
				self.getMesg(smtpData)
			smtpData = None # Free for next loop

	def getMesg(self, smtpData):
		global outDIR, verbose, flagM
		if flagM:# Get header/text/html?
			msg = message_from_string(smtpData)
			# Use regex to clean up timestamp for pathname
			msgDIR = os.path.join(outDIR, re_sub('[:,-]','',msg.get("date").replace(' ','_')))
			if debug: print "msgDIR: ", msgDIR
			if os.path.isdir(msgDIR) == False: os.makedirs(msgDIR, 0755)
			fh = open(os.path.join(msgDIR, "header"),'w')
			# For each header item
			for i in msg.items():
				if debug: print("%s: %s" % (i[0], i[1]))
				# Write field and value
				fh.write("%s: %s\n" % (i[0], i[1]))
			fh.close()
			for part in msg.walk():
				# Open these files to append just in case there's more than one of this content type. Don't overwrite!

				#RFC6838 & http://www.iana.org/assignments/media-types/media-types.xhtml
				if (part.get_content_type() == "text/plain"):
					if debug or verbose: print "\tSaving text... "
					if debug: print part.get_payload(decode=True)
					fh = open(os.path.join(msgDIR, "message_text"),'a')
					fh.write(part.get_payload(decode=True))
					fh.close()
				elif (part.get_content_type() == "text/html"):
					if debug or verbose: print "\tSaving HTML... "
					if debug: print part.get_payload(decode=True)
					fh = open(os.path.join(msgDIR, "message_HTML"),'a')
					fh.write(part.get_payload(decode=True))
					fh.close()
		else:
			msgDIR = outDIR
		self.getAttach(smtpData, msgDIR)# Get attachments now
		
	def getAttach(self, smtpData, outDIR):
		global debug, verbose
		#https://docs.python.org/2/library/email.message.html
		msg = message_from_string(smtpData)
		for part in msg.walk():
			#~ if (part.get_content_maintype() in ("application", "image", "audio", "video"):
			if part.get("Content-Disposition") and part.get("Content-Disposition").split(';')[0] == "attachment":
				if debug or verbose: print "\tSaving attachment: ", part.get_filename()
				if os.path.isdir(outDIR) == False: os.mkdir(outDIR, 0755)
				fh = open(os.path.join(outDIR, part.get_filename()), 'wb')
				fh.write(part.get_payload(decode=True))
				fh.close()

App().main()
