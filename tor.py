#!/usr/bin/env python

import requests
import xml.etree.ElementTree as ET
import time
import syslog

# These variable will need to be set:
# URL to access the management interface of the firewall:
fw_url = "https://fw.vpnagogo.com"

#API Key for the account you want to use to manage the dynamic address object:
fw_key = ''

#If you do not use TLS Client Authentication, you will ned to remove th fw_cert variable, plus all references to it throughout the code.
#Path and filename for the certificate file that will be used to authenticate with TLS on the management interface:
fw_cert = '/var/www/includes/client_cert.pem'

#Name of the address object you want to use:
address_object = "TOR_Exit_Nodes"

def DAG_Exists(fw_url,fw_key,fw_cert,address_object):
	url = fw_url + '/api?type=op&cmd=<show><object><dynamic-address-group><all></all></dynamic-address-group></object></show>&key=' + fw_key
	fw_results=requests.get(url, cert=fw_cert)
	if fw_results.status_code == 200:
		foundit = 0
		root = ET.fromstring(fw_results.text)
		for entry in root.findall("./result/dyn-addr-grp/entry"):
			name = entry.find('group-name')
			if name.text == address_object:
				foundit = 1

	if foundit == 1:
		return 1
	else:
		return 0

def DAG_Create(fw_url,fw_key,fw_cert,address_object):

	xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='" + address_object + "']/dynamic"
	element = "<filter>" + address_object + "</filter>"
	url = fw_url + "/api?" + "&type=config&action=set&xpath=" + xpath + "&element=" + element + "&key=" + fw_key

	fw_results=requests.get(url, cert=fw_cert)
	if fw_results.status_code == 200:
		root = ET.fromstring(fw_results.text)
		if root.attrib['status'] == "success":
			return 1
		else:
			return 0
	else:
		return 0

def DAG_Get(fw_url,fw_key,fw_cert,address_object):
	output = []
	cmd = "<show><object><dynamic-address-group><name>" + address_object + "</name></dynamic-address-group></object></show>"
	url = fw_url + "/api/?type=op&cmd=" + cmd + "&key=" + fw_key
	fw_results=requests.get(url, cert=fw_cert)
	if fw_results.status_code == 200:
		root = ET.fromstring(fw_results.text)
		for entry in root.findall("./result/dyn-addr-grp/entry"):
			name = entry.find('group-name')
			members = entry.findall('member-list/entry')
			if name.text == address_object:
				for member in members:
					output.append(member.find('.').attrib['name'])
	return output

def FW_Commit(fw_url,fw_key,fw_cert):
	url = fw_url + "/api/?type=commit&cmd=<commit></commit>&key=" + fw_key
	fw_results=requests.get(url, cert=fw_cert)
	if fw_results.status_code == 200:
		root = ET.fromstring(fw_results.text)
                if root.attrib['status'] == "success":
			print "Committing policy"
			return str(root.find("./result/job").text)
		else:
			return 0
	else:
		return 0

def FW_Job(fw_url,fw_key,fw_cert,fw_job):
	finished = 0
	
	while (finished < 1):
		time.sleep(2)
		url = fw_url + "/api/?type=op&cmd=<show><jobs><id>" + str(fw_job) + "</id></jobs></show>&key=" + fw_key
		fw_results=requests.get(url, cert=fw_cert)
		if fw_results.status_code == 200:
			root = ET.fromstring(fw_results.text)
			if root.attrib['status'] == "success":
                        	if root.find("./result/job/status").text == "FIN":
					finished = 1
					print "Policy commit complete"
				else:
					print root.find("./result/job/progress").text + "% Complete"

def TOR_Get():
	output = []
	big_string = ''
	tor_results = requests.get("https://check.torproject.org/exit-addresses")
	if tor_results.status_code == 200:
		for result in tor_results:
			big_string = big_string + result
	big_string = big_string.replace('\n', ' ').replace('\r', '')
	fields = big_string.strip().split()
	for index in range(0, len(fields)):
		if fields[index] =='ExitAddress':
			output.append(fields[index + 1])
	return output

def FW_XML(dag_del,dag_add,address_object):
	if (len(dag_del) > 0) or (len(dag_add) > 0):
		xmlout = "<uid-message>\n"
		xmlout = xmlout + "\t<version>1.0</version>\n"
		xmlout = xmlout + "\t<type>update</type>\n"
		xmlout = xmlout + "\t<payload>\n"
		if len(dag_add) > 0:
			xmlout = xmlout + "\t\t<register>\n"
			for entry in dag_add:
				xmlout = xmlout + '\t\t\t<entry ip="' + entry + '">\n'
				xmlout = xmlout + "\t\t\t\t<tag>\n"
				xmlout = xmlout + '\t\t\t\t\t<member>' + address_object + '</member>\n'
				xmlout = xmlout + "\t\t\t\t</tag>\n"
				xmlout = xmlout + "\t\t\t</entry>\n"
			xmlout = xmlout + "\t\t</register>\n"
		if len(dag_del) > 0:
			xmlout = xmlout + "\t\t<unregister>\n"
			for entry in dag_del:
			        xmlout = xmlout + '\t\t\t<entry ip="' + entry + '">\n'
				xmlout = xmlout + "\t\t\t\t<tag>\n"
				xmlout = xmlout + '\t\t\t\t\t<member>' + address_object + '</member>\n'
				xmlout = xmlout + "\t\t\t\t</tag>\n"
				xmlout = xmlout + "\t\t\t</entry>\n"
			xmlout = xmlout + "\t\t</unregister>\n"
		xmlout = xmlout + "\t</payload>\n"
		xmlout = xmlout + "</uid-message>"
		return xmlout
	else:
		return 0

def FW_Update(fw_url,fw_key,fw_cert,fw_xml):
	url = fw_url + "/api/?type=user-id&key=" + fw_key
	files = {'file': ('tor.xml', fw_xml, 'application/xml')}
	fw_results=requests.post(url, cert=fw_cert, files=files)
	if fw_results.status_code == 200:
		root = ET.fromstring(fw_results.text)
		if root.attrib['status'] == "success":
			syslog.syslog("Address group updated successfully")
			return 1
		else:
			syslog.syslog(fw_results.text)
			return 0


#Main Program
if DAG_Exists(fw_url,fw_key,fw_cert,address_object) == 0:
	print address_object + " does not exist"

	dag_create = DAG_Create(fw_url,fw_key,fw_cert,address_object)
	if dag_create == 1:
		print address_object + " created successfully"
		fw_job = FW_Commit(fw_url,fw_key,fw_cert)
		if (fw_job > 0):
			FW_Job(fw_url,fw_key,fw_cert,fw_job)
			print "Waiting for 30 seconds.\n"
			time.sleep(30)
	else:
		print "Error attempting to create " + address_object

#Get dynamic addres group member IPs
dag_members = DAG_Get(fw_url,fw_key,fw_cert,address_object)

#Get current list of TOR exit nodes
tor_nodes = TOR_Get()

#Generate list of IPs that are in the dynamic address group but no longer listed as an exit node(deletes)
dag_del = list(set(dag_members) - set(tor_nodes))

#Generate list of IPs that are listed as exit nodes that are not in the dynamic address group (adds)
dag_add = list(set(tor_nodes) - set(dag_members))

#Generate the XML to update the dynamic address group
fw_xml = FW_XML(dag_del, dag_add, address_object)

#Push the update to the firewall
if fw_xml <> 0:
	fw_update = FW_Update(fw_url,fw_key,fw_cert,fw_xml)
else:
	syslog.syslog("No update needed for " + address_object)

