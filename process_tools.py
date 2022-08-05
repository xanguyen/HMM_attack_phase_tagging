import requests
import geocoder

NONE = 0
LOW = 1
MEDIUM = 2
HIGH = 3

### You can modify the following lines to adapt to your needs ###

retcount = 0 #this is just a counter that we would not need if we pay for ipapi
low_triggering_countries = ["United States", "Israel"]
medium_triggering_countries = ["Turkey", "Brazil"]
high_triggering_countries = ["China", "Russia", "Ukraine", "Taiwan", "India"]

HIGH_src_blacklist_IPs = []
MEDIUM_src_blacklist_IPs = []
LOW_src_blacklist_IPs = []

HIGH_dest_blacklist_IPs = []
MEDIUM_dest_blacklist_IPs = []
LOW_dest_blacklist_IPs = []

### the company ipv4 prefix ###
company_prefix = ["42.219."]

### authorized communications between different IP of the company ###
allowed_communications = {
	'42.219.159.118' :  {'42.219.154.123', '42.219.154.189', '42.219.154.156', '42.219.154.100', '42.219.154.108', '42.219.154.116', '42.219.155.10', '42.219.152.254', '42.219.154.133'},
	'42.219.96.179' :  {'42.219.159.95'},
	'42.219.226.74' :  {'42.219.159.194', '42.219.154.135', '42.219.154.128', '42.219.154.98', '42.219.153.7', '42.219.145.202', '42.219.153.62', '42.219.158.165', '42.219.154.131', '42.219.158.190', '42.219.145.18', '42.219.158.179', '42.219.159.106', '42.219.154.101', '42.219.152.249'},
	'42.219.41.119' :  {'42.219.153.89', '42.219.159.194', '42.219.153.7', '42.219.152.249'},
	'42.219.248.230' :  {'42.219.154.123', '42.219.153.21', '42.219.153.128', '42.219.153.147'},
	'42.219.206.141' :  {'42.219.153.8', '42.219.153.216', '42.219.153.43', '42.219.153.150', '42.219.153.35', '42.219.153.17', '42.219.153.79', '42.219.153.45'},
	'42.219.128.119' :  {'42.219.151.22'},
	'42.219.251.100' :  {'42.219.153.168'},
	'42.219.43.64' :  {'42.219.159.118'},
	'42.219.243.60' :  {'42.219.159.118'},
	'42.219.188.222' :  {'42.219.152.126', '42.219.154.100', '42.219.154.98', '42.219.155.102', '42.219.153.7', '42.219.154.105', '42.219.158.178', '42.219.154.101', '42.219.153.44', '42.219.158.191', '42.219.158.179', '42.219.153.252', '42.219.154.123', '42.219.154.142', '42.219.145.202', '42.219.153.62', '42.219.154.130', '42.219.155.103', '42.219.152.249', '42.219.154.109', '42.219.154.121', '42.219.154.108', '42.219.153.156', '42.219.154.149', '42.219.154.122', '42.219.155.106', '42.219.158.190', '42.219.145.18', '42.219.155.100'},
	'42.219.41.116' :  {'42.219.159.194', '42.219.153.7', '42.219.152.249'},
	'42.219.238.183' :  {'42.219.158.161'},
	'42.219.255.114' :  {'42.219.154.114'},
	'42.219.41.118' :  {'42.219.153.7'},
	'42.219.223.133' :  {'42.219.159.95'},
	'42.219.250.144' :  {'42.219.158.161'},
	'42.219.43.212' :  {'42.219.158.226'},
	'42.219.225.17' :  {'42.219.159.194', '42.219.154.129', '42.219.153.7', '42.219.153.62', '42.219.158.190', '42.219.158.178', '42.219.159.106', '42.219.152.249'},
	'42.219.248.186' :  {'42.219.155.56', '42.219.159.181'},
	'42.219.246.181' :  {'42.219.159.194', '42.219.153.7', '42.219.152.249'},
	'42.219.179.145' :  {'42.219.152.126', '42.219.154.100', '42.219.155.102', '42.219.153.7', '42.219.154.105', '42.219.158.178', '42.219.153.44', '42.219.158.191', '42.219.153.26', '42.219.158.179', '42.219.153.252', '42.219.154.123', '42.219.145.202', '42.219.153.62', '42.219.154.130', '42.219.155.103', '42.219.152.249', '42.219.154.109', '42.219.154.108', '42.219.153.156', '42.219.154.122', '42.219.154.116', '42.219.155.106', '42.219.158.190', '42.219.145.18', '42.219.155.100'},
	'42.219.251.249' :  {'42.219.154.114', '42.219.158.161'},
	'42.219.226.169' :  {'42.219.159.194', '42.219.154.128', '42.219.153.7', '42.219.153.26', '42.219.153.62', '42.219.154.116', '42.219.158.190', '42.219.152.249'},
	'42.219.248.29' :  {'42.219.154.132'},
	'42.219.128.221' :  {'42.219.159.95'},
	'42.219.255.105' :  {'42.219.153.128', '42.219.153.147'},
	'42.219.253.79' :  {'42.219.154.129'},
	'42.219.19.152' :  {'42.219.159.85', '42.219.159.86', '42.219.153.149'},
	'42.219.243.94' :  {'42.219.154.108', '42.219.155.56'},
	'42.219.1.79' :  {'42.219.153.7'},
	'42.219.0.176' :  {'42.219.153.62'},
	'42.219.41.100' :  {'42.219.157.10', '42.219.153.7', '42.219.159.181'},
	'42.219.248.152' :  {'42.219.154.182'},
	'42.219.250.132' :  {'42.219.153.128', '42.219.153.147'},
	'42.219.253.100' :  {'42.219.153.120'},
	'42.219.246.183' :  {'42.219.154.128', '42.219.153.7', '42.219.153.62', '42.219.155.106', '42.219.154.119', '42.219.155.100'},
	'42.219.240.16' :  {'42.219.153.128'},
	'42.219.226.126' :  {'42.219.158.161', '42.219.153.62', '42.219.158.190'},
	'42.219.250.157' :  {'42.219.158.218'},
	'42.219.96.160' :  {'42.219.159.95'},
	'42.219.104.14' :  {'42.219.153.7'},
	'42.219.249.10' :  {'42.219.159.95'},
	'42.219.251.35' :  {'42.219.153.7', '42.219.153.62'},
	'42.219.159.95' :  {'42.219.149.41', '42.219.215.87', '42.219.249.89', '42.219.199.96', '42.219.216.217', '42.219.148.155', '42.219.121.27', '42.219.41.56', '42.219.250.2', '42.219.140.140', '42.219.128.215', '42.219.125.68', '42.219.50.184', '42.219.43.42', '42.219.183.76', '42.219.64.190', '42.219.98.46', '42.219.72.201', '42.219.118.204', '42.219.71.100', '42.219.53.69', '42.219.49.51', '42.219.34.95', '42.219.104.90', '42.219.241.2', '42.219.177.6', '42.219.84.83', '42.219.238.52', '42.219.118.136', '42.219.115.208', '42.219.12.135', '42.219.88.68', '42.219.29.86', '42.219.22.215', '42.219.110.192', '42.219.100.241', '42.219.54.130', '42.219.58.175', '42.219.159.95', '42.219.244.233', '42.219.215.70', '42.219.49.0', '42.219.243.3', '42.219.187.22', '42.219.5.64', '42.219.232.49'},
	'42.219.66.146' :  {'42.219.159.95'},
	'42.219.254.220' :  {'42.219.154.132'},
	'42.219.248.243' :  {'42.219.159.95'},
	'42.219.153.164' :  {'42.219.153.164'},
	'42.219.255.191' :  {'42.219.159.118'},
	'42.219.226.85' :  {'42.219.159.95'},
	'42.219.240.81' :  {'42.219.153.248'},
	'42.219.248.192' :  {'42.219.159.95'},
	'42.219.250.29' :  {'42.219.153.168'},
	'42.219.190.243' :  {'42.219.159.95'},
	'42.219.242.64' :  {'42.219.158.190'},
	'42.219.252.215' :  {'42.219.159.95'},
	'42.219.222.134' :  {'42.219.159.95'},
	'42.219.242.169' :  {'42.219.159.95'},
	'42.219.234.152' :  {'42.219.155.119'},
	'42.219.250.9' :  {'42.219.153.168'},
	'42.219.250.44' :  {'42.219.153.168'},
	'42.219.43.186' :  {'42.219.159.86'},
	'42.219.90.225' :  {'42.219.159.95'},
	'42.219.248.196' :  {'42.219.154.132'},
	'42.219.64.176' :  {'42.219.159.95'},
	'42.219.180.201' :  {'42.219.157.145'},
	'42.219.242.188' :  {'42.219.159.95'},
	'42.219.161.25' :  {'42.219.159.85'},
	'42.219.222.247' :  {'42.219.159.95'},
	'42.219.223.255' :  {'42.219.159.95'},
	'42.219.204.178' :  {'42.219.159.194', '42.219.153.7', '42.219.145.202', '42.219.153.62', '42.219.158.190', '42.219.145.18', '42.219.152.249'},
	'42.219.250.32' :  {'42.219.154.130'},
	'42.219.204.161' :  {'42.219.159.194', '42.219.153.7', '42.219.153.62', '42.219.152.249'},
	'42.219.250.161' :  {'42.219.153.79', '42.219.158.161', '42.219.153.17'},
	'42.219.65.106' :  {'42.219.159.95'},
	'42.219.223.173' :  {'42.219.159.95'},
	'42.219.231.41' :  {'42.219.159.95'},
	'42.219.241.68' :  {'42.219.154.107', '42.219.153.62'},
	'42.219.234.13' :  {'42.219.159.85'},
	'42.219.229.64' :  {'42.219.159.95'},
	'42.219.233.89' :  {'42.219.157.97', '42.219.159.195'},
	'42.219.206.118' :  {'42.219.159.194'},
	'42.219.128.22' :  {'42.219.152.249'},
	'42.219.136.22' :  {'42.219.152.249'},
	'42.219.223.69' :  {'42.219.152.249'},
	'42.219.19.164' :  {'42.219.152.249'},
	'42.219.19.165' :  {'42.219.152.249'},
	'42.219.167.49' :  {'42.219.159.95'},
	'42.219.248.145' :  {'42.219.159.95'},
	'42.219.254.244' :  {'42.219.159.95'},
	'42.219.95.144' :  {'42.219.159.95'},
	'42.219.184.192' :  {'42.219.159.95'},
	'42.219.191.85' :  {'42.219.159.95'},
	'42.219.224.68' :  {'42.219.153.7', '42.219.153.62', '42.219.152.249'},
	'42.219.176.92' :  {'42.219.153.7'},
	'42.219.43.11' :  {'42.219.159.95'},
	'42.219.159.186' :  {'42.219.159.159'},
	'42.219.159.221' :  {'42.219.159.154', '42.219.159.152', '42.219.159.158'},
	'42.219.159.76' :  {'42.219.159.154', '42.219.159.152', '42.219.159.158'},
	'42.219.159.220' :  {'42.219.159.152'},
	'42.219.159.199' :  {'42.219.157.241', '42.219.157.225', '42.219.159.152', '42.219.157.230', '42.219.159.158', '42.219.159.154', '42.219.157.249'},
	'42.219.159.182' :  {'42.219.152.248', '42.219.154.115', '42.219.156.210', '42.219.159.195', '42.219.154.122', '42.219.154.114', '42.219.156.211', '42.219.159.221', '42.219.159.76', '42.219.153.89', '42.219.153.155', '42.219.159.199'},
	'42.219.159.171' :  {'42.219.159.194', '42.219.152.249'},
	'42.219.159.170' :  {'42.219.157.8', '42.219.153.212', '42.219.159.194', '42.219.157.10', '42.219.159.87', '42.219.153.199', '42.219.159.91', '42.219.157.27', '42.219.155.59', '42.219.159.94', '42.219.157.22', '42.219.152.255', '42.219.153.236', '42.219.153.162', '42.219.153.41', '42.219.157.24', '42.219.157.12', '42.219.159.86', '42.219.153.169', '42.219.157.6'},
	'42.219.159.195' :  {'42.219.159.154', '42.219.159.152', '42.219.159.158'},
	'42.219.158.190' :  {'42.219.255.202', '42.219.179.145'},
	'42.219.153.21' :  {'42.219.248.230'},
	'42.219.159.86' :  {'42.219.43.186', '42.219.19.152'},
	'42.219.153.7' :  {'42.219.188.222', '42.219.41.119', '42.219.41.116', '42.219.179.145'},
	'42.219.153.62' :  {'42.219.188.222', '42.219.179.145', '42.219.223.86'},
	'42.219.154.123' :  {'42.219.188.222', '42.219.248.230', '42.219.179.145'},
	'42.219.154.100' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.153.12' :  {'42.219.153.12'},
	'42.219.154.105' :  {'42.219.188.222'},
	'42.219.152.249' :  {'42.219.246.181', '42.219.179.145', '42.219.41.119', '42.219.41.116', '42.219.188.222'},
	'42.219.159.194' :  {'42.219.246.181', '42.219.41.119', '42.219.41.116'},
	'42.219.154.109' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.153.44' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.154.116' :  {'42.219.179.145'},
	'42.219.153.128' :  {'42.219.248.230'},
	'42.219.153.147' :  {'42.219.248.230'},
	'42.219.249.89' :  {'42.219.159.95'},
	'42.219.145.18' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.145.202' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.153.156' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.251.86' :  {'42.219.154.108'},
	'42.219.154.108' :  {'42.219.179.145', '42.219.251.86'},
	'42.219.158.178' :  {'42.219.225.17', '42.219.179.145'},
	'42.219.159.141' :  {'42.219.159.152'},
	'42.219.155.103' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.155.100' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.255.202' :  {'42.219.158.190'},
	'42.219.250.2' :  {'42.219.159.95'},
	'42.219.177.6' :  {'42.219.159.95'},
	'42.219.153.252' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.158.191' :  {'42.219.188.222'},
	'42.219.154.101' :  {'42.219.188.222'},
	'42.219.158.179' :  {'42.219.188.222', '42.219.179.145'},
	'42.219.159.140' :  {'42.219.159.152'},
	'42.219.158.165' :  {'42.219.223.86'},
	'42.219.223.86' :  {'42.219.158.165', '42.219.153.62'},
	'42.219.153.45' :  {'42.219.206.141'},
	'42.219.153.17' :  {'42.219.206.141'},
	'42.219.153.35' :  {'42.219.206.141'}
}

### Protocols standard ports ###
tcpports = ['80', '443', '20', '21', '22', '23', '25', '43', '53', '81', '91', '110', '135','137', '138', '139', '143', '161', '162', '179', '389', '445', '502', '587', '636', '989', '990', '993', '995']
udpports = ['0', '17', '19', '53', '67', '68', '69', '111', '123', '137', '138', '139', '161', '162', '443', '389', '500', '520', '636']
icmp_entry_ports = ['769', '771', '778'] # ports that were previously used by malicous ICMP packets

"""
little function to increment a value in a dict, or add it to the dict if it is not in yet
"""
def add_to_dict(thedict, thekey):
    if thekey in thedict:
        thedict[thekey] += 1
    else:
        thedict[thekey] = 1


"""
return an array with a cumulative probability-like represantation of a dict()
"""
def cumul_dist_array(dict_data, start, end, num_tot, step=15, decimal=0):
	ans = [0]*step
	ans[step-1] = 1.0
	scale = [""] * step
	scale[0] = "<="+str(start)
	scale[step-1] = str(end) + "<"

	for k in dict_data:
		if k <= start:
			ans[0] += dict_data[k]
	ans[0] = ans[0] / num_tot

	previous = start

	for i in range(1,(step-1)):
		if decimal == 0:
			scale[i] = str(int(previous)) +" - " + str(int((start + i*(end-start)/(step-2))))
		else:
			scale[i] = str(round(previous, decimal)) +" - " + str(round((start + i*(end-start)/(step-2)), decimal))
		for k in dict_data:
			if k > previous and k <= (start + i*(end-start)/(step-2)):
				ans[i] += dict_data[k]

		ans[i] = ans[i-1] + (ans[i] / num_tot)
		previous = start + i*(end-start)/(step-2)

	return ans, scale

"""
print the IP address in a file if it has more than a certain pourcentage of communication blacklisted. 
"""
def blacklist_IP_saving(ip_dict, srcOrdest):
	if ip_dict['blacklist'] >= 0.95 * ip_dict['total_com']:
		f = open("HIGH_"+srcOrdest+"_IPs.txt", 'a')
		f.write(ip_dict['IP']+"\n")
		f.close()
	elif ip_dict['blacklist'] >= 0.65 * ip_dict['total_com']:
		f = open("MEDIUM_"+srcOrdest+"_IPs.txt", 'a')
		f.write(ip_dict['IP']+"\n")
		f.close()
	elif ip_dict['blacklist'] >= 0.3 * ip_dict['total_com']:
		f = open("LOW_"+srcOrdest+"_IPs.txt", 'a')
		f.write(ip_dict['IP']+"\n")
		f.close()

"""
load the blacklisted IPs from the blacklist_file into the array blacklist_IPs
"""
def load_src_blacklist_IPs():
	global HIGH_src_blacklist_IPs, MEDIUM_src_blacklist_IPs, LOW_srct_blacklist_IPs
	f = open("HIGH_src_IPs.txt", 'r')
	HIGH_src_blacklist_IPs = f.read().split("\n")[:-1] #removes the last blank line
	f.close()
	f = open("MEDIUM_src_IPs.txt", 'r')
	MEDIUM_src_blacklist_IPs = f.read().split("\n")[:-1] #removes the last blank line
	f.close()
	f = open("LOW_src_IPs.txt", 'r')
	LOW_src_blacklist_IPs = f.read().split("\n")[:-1] #removes the last blank line
	f.close()

"""
@return: a trigger if the IP address is a src blacklist IP
"""
def is_blacklisted_src_IP(ip_address):
	if ip_address in HIGH_src_blacklist_IPs:
		return HIGH
	elif ip_address in MEDIUM_src_blacklist_IPs:
		return MEDIUM
	elif ip_address in LOW_src_blacklist_IPs:
		return LOW
	else:
		return NONE


def load_dest_blacklist_IPs():
	global HIGH_dest_blacklist_IPs, MEDIUM_dest_blacklist_IPs, LOW_dest_blacklist_IPs
	f = open("HIGH_dest_IPs.txt", 'r')
	HIGH_dest_blacklist_IPs = f.read().split("\n")[:-1] #removes the last blank line
	f.close()
	f = open("MEDIUM_dest_IPs.txt", 'r')
	MEDIUM_dest_blacklist_IPs = f.read().split("\n")[:-1] #removes the last blank line
	f.close()
	f = open("LOW_dest_IPs.txt", 'r')
	LOW_dest_blacklist_IPs = f.read().split("\n")[:-1] #removes the last blank line
	f.close()


"""
@return: a trigger if the IP address is a dest blacklist IP
"""
def is_blacklisted_dest_IP(ip_address):
	if ip_address in HIGH_dest_blacklist_IPs:
		return HIGH
	elif ip_address in MEDIUM_dest_blacklist_IPs:
		return MEDIUM
	elif ip_address in LOW_dest_blacklist_IPs:
		return LOW
	else:
		return NONE

"""
@return: the country location of an ip address
"""
def get_ip_location(ip_address):
	country = requests.get("https://api.iplocation.net/?cmd=ip-country&ip="+ip_address).json()
	#print(country["country_name"])
	return country["country_name"]
	"""
	global retcount
	country = None
	if retcount < 10000:
		info = geocoder.ipinfo(ip_address)
		return info.country
	else:
		country = requests.get("https://api.iplocation.net/?cmd=ip-country&ip="+ip_address).text
		print(country)
	ipApi_key = 'pTR231XSunsTnf4n7iPSCIED4wKxvQnVGkxblCCUHsQfIT8UxP'
	if retcount < 11500:
		ipApi_key = ''
	elif retcount > 13000:
		return None
	country = requests.get(f'https://ipapi.co/{ip_address}/country/' + ipApi_key).text
	try:
		count = 0
		while(len(country) > 5):
			if count > 20:
				print("20+")
				break
			country = requests.get(f'https://ipapi.co/{ip_address}/country/' + ipApi_key).text
			count += 1
	except:
		pass

	#print(country)
	return country
	"""
	
"""
Checks the location of an IP address, returns an appropriate trigger
@return: LOW if country in low_triggering_countries
		 MEDIUM if country in medium_triggering_countries
		 HIGH if country in high_triggering_countries
		 NONE otherwise
"""
def location_trigger(ip_address):
	country = get_ip_location(ip_address)

	if country in low_triggering_countries:
		return LOW
	elif country in medium_triggering_countries:
		return MEDIUM
	elif country in high_triggering_countries:
		return HIGH
	else:
		return NONE 

"""
Checks if an internal communication between two IPs is allowed or return a trigger
@return: NONE if yes
		 MEDIUM if not in the allowed communication of this source IP address
		 MEDIUM if this source IP has no allowed communications but there are other source IP 
		 	that are allowed to communicate with the destination IP
		 HIGH if not in the allowed communication of this source IP address neither for others
"""
def internal_communication_trigger(src_ip, dst_ip):
	if not(is_company_IP(src_ip) and is_company_IP(dst_ip)):
		return NONE
	if src_ip in allowed_communications:
		if dst_ip in allowed_communications[src_ip]:
			return NONE
		else:
			return MEDIUM
	else:
		for IPs in allowed_communications:
			if dst_ip in IPs:
				return MEDIUM
		return HIGH


"""
@return True if the IP address has one of the company prefix
		False otherwise
"""
def is_company_IP(ip_address):
	for prefix in company_prefix:
		if ip_address.startswith(prefix):
			return True

	return False

"""
#return a LOW/MEDIUM/HIGH trigger depending on the port-protocol duo
"""
def port_protocol_trigger(event_sequence):
	ret = NONE
	for event in event_sequence:
		port = event[5]
		protocol = event[6]
		if int(port) < 1024:
			if protocol == 'UDP':
				if port not in udpports:
					return MEDIUM
			elif protocol == 'TCP':
				if port not in tcpports:
					return MEDIUM
			elif protocol == 'ICMP':
				if port in icmp_entry_ports:
					ret = max(ret, LOW)

			#else:NONE other protocols have never been blacklist yet in the dataset

		else: #most of the attack (78%) are on ports lower than 1024
			ret = max(ret, NONE)

	return ret


"""
@return: HIGH/MEDIUM/LOW based on the likeliness of the srcIP to be port-scanning
"""
def port_scanning_flag(event_sequence):
	if not is_company_IP(event_sequence[0][5]):
		return NONE
		
	total_com = len(event_sequence)

	if total_com < 50:
		return NONE

	used_ports = set()
	total_com_duration = 0.0

	for event in event_sequence:
		used_ports.add(event[5])
		total_com_duration += float(event[1])

	if len(used_ports) == total_com:
		return HIGH
	elif len(used_ports) >= 0.90 * total_com:
		return MEDIUM
	elif len(used_ports) >= 0.5 * total_com:
		return LOW
	else:
		return NONE
"""
@return: HIGH if on of the event of the sequence num_bytes > 10 * mean(protocol_bytes), >100 for ICMP
		 MEDIUM if all payloads have num_bytes < 100 for TCP & UDP
		 NONE otherwise
"""
def is_big_payload(event_sequence):
	max_payload = NONE
	for event in event_sequence:
		if event[6] == 'UDP':
			if int(event[11]) > 103*10:
				return HIGH
			elif int(event[11]) < 100:
				max_payload = LOW

		elif event[6] == 'TCP':
			if int(event[11]) > 890*10:
				return HIGH
			elif int(event[11]) < 100:
				max_payload = LOW

		elif event[6] == 'ICMP':
			if int(event[11]) > 100:
				return HIGH

	return max_payload
