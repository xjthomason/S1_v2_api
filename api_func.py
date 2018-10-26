import requests, datetime, time, json

import csv_reader, email_google, threats_func

today = datetime.date.today()

token_file = open("S1_token.txt", 'r')
myToken = 'APIToken ' + token_file.read()
head = {'Authorization': myToken}

#API calls
applications = requests.get("https://usea1-avx.sentinelone.net/web/api/v2.0/application-inventory", headers=head)
#TODO run against a list of unapproved publishers/apps
agents = requests.get("https://usea1-avx.sentinelone.net/web/api/v2.0/agents", headers=head)
#threats = requests.get("https://avx.sentinelone.net/web/api/v1.6/threats?limit=5000", headers=head)
threats_1 = requests.get("https://usea1-avx.sentinelone.net/web/api/v2.0/threats?limit=5000&mitigation_status=1", headers=head)
threats_2 = requests.get("https://usea1-avx.sentinelone.net/web/api/v2.0/threats?limit=5000&mitigation_status=0", headers=head)
threats_b = requests.get("https://usea1-avx.sentinelone.net/web/api/v2.0/threats?limit=5000&mitigation_status=2", headers=head)
threats_3 = requests.get("https://usea1-avx.sentinelone.net/web/api/v2.0/threats?limit=5000&mitigation_status=3", headers=head)
#TODO actions on threats
#TODO reports on threats that haven't been addressed
device_pull = "https://usea1-avx.sentinelone.net/web/api/v2.0/agents/"
add_group_ether = "https://usea1-avx.sentinelone.net/web/api/v2.0/groups/5b645a9c73758c2a87442c38/add-agents?computer_name__like="
#TODO run query on device id based on return from threat call


def app_inventory():
	
	#create an array of application data to filter publishers and applciation names
	apps = []
	list = []
	list = applications.json()
	
	cont = True
	
	while cont:
		try:
			opt = input("""Enter '1' to pull entire application inventory\nEnter '2' to pull applications for specific host\nEnter '3' for list of applications without a publisher: """)
	
			if opt == '1':
				#entire application inventory
				print("\n\nCOMING SOON!\n")
				return
			elif opt == '2':
				#applications for specified host
				agent_list = []
				call = []
				call = agents.json()
				
				#pull agents to retrieve hostnames and user info
				hostname = input("Enter hostname: ")
				if hostname != None:
					for x in range(0,7500):
						try:
							agent_list.append((u'{0}, {1}, {2}'.format(call[x]['network_information']['computer_name'],
																  call[x]['id'],
																  call[x]['last_logged_in_user_name']
																  )))
						except Exception as e:
							break
				else:
					print("No hostname entered...")
					continue
					
				for x in range(0,len(agent_list)):
					if hostname == agent_list[x].rsplit(',', 2)[0]:
						#print(agent_list[x].rsplit(',', 2)[1])
						S1_id = agent_list[x].rsplit(',', 2)[1].lstrip(' ')
						#print(device_pull+S1_id+"/applications")
						agent_apps = []
						agent_apps = requests.get(device_pull+S1_id+"/applications", headers=head).json()
						#print(agent_apps[0])
						agent_apps_list = []
						try:
							for x in range(0,len(agent_apps)):
								agent_apps_list.append((u'{0}, {1}, {2}, {3}, {4}, {5}'.format(agent_apps[x]['publisher'].replace(',',' '),
																								 agent_apps[x]['name'],
																								 agent_apps[x]['signed'],
																								 agent_apps[x]['installed_date'],
																								 agent_apps[x]['version'],
																								 agent_apps[x]['size']
																								 )))
						except Exception as e:
							print(e)
						time.sleep(5)
						filename = csv_reader.appCSV(agent_apps_list, 2, hostname)
						#print(agent_list[x])
					else:
						continue
				
			elif opt == '3':
					#applications with no publisher
				for x in list['applications']:
					try:
						if x['publisher'] == '':
							apps.append((u'{0}, {1}, {2}, {3}, {4}, {5}'.format(x['count'],
																	'NO PUBLISHER',
																	x['name'],
																	x['signed'],
																	x['version'],
																	x['size']
																	)))
					except:
						continue
			cont = False
						
		except Exception as e:
			print(e)
			cont = False
		
	
	if apps == []:
		print("File with host apps created!")
	elif opt == 3:
		filename = csv_reader.appCSV(apps, 1)
		print("File with no publishers created!")
	elif opt == 1:
		filename = csv_reader.appCSV(apps, 1)
		print("File with all apps created!")
	else:
		print("No file created!")
	#print(len(list['applications']))
	
		#email a copy to an address
	e = input("Email a copy to someone (Y/N)?: ")
	if e == 'Y' or e == 'y':
		address = input("Enter an email address: ")
		email_google.send_email(address, filename)
	elif e == 'N' or e == 'n':
		return
	else:
		return
	

def agents_inventory():
	
	try:
		d = int(input("Enter created date range(in days), leave blank if you want all assets: "))
	except:
		d = 0
	week_ago = today - datetime.timedelta(days=d)
	
	#create array of data pulled from S1 and email to interested parties
	agents_S1 = []
	list = []
	list = agents.json()
	
	if d == 0:
		for x in range(0,7500):
			try:
				agents_S1.append((u'{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}'.format(list[x]['network_information']['computer_name'],
															list[x]['software_information']['os_name'],
															list[x]['software_information']['os_revision'],
															list[x]['network_status'],
															list[x]['network_information']['domain'],
															list[x]['group_id'],
															list[x]['network_information']['interfaces'][0]['inet'][0],
															list[x]['last_logged_in_user_name'],
															list[x]['meta_data']['created_at'].split('T')[0]
															)))
			except Exception as e:
				break
	elif d > 0:
		for x in range(0,7500):
			try:
				if list[x]['meta_data']['created_at'] >= str(week_ago):
					agents_S1.append((u'{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}'.format(list[x]['network_information']['computer_name'],
																list[x]['software_information']['os_name'],
																list[x]['software_information']['os_revision'],
																list[x]['network_status'],
																list[x]['network_information']['domain'],
																list[x]['group_id'],
																list[x]['network_information']['interfaces'][0]['inet'][0],
																list[x]['last_logged_in_user_name'],
																list[x]['meta_data']['created_at'].split('T')[0]
																)))
				else:
					continue
			except Exception as e:
				break
	else:
		print("Invalid...")
		
	a = input("Move agents to Ethertronics group (Y/N)?: ")
	if a == 'Y' or a == 'y':
		for x in range(0,300):
			try:
				if agents_S1[x].split(',')[5].lstrip(' ') == '5a737c6a61e35524b8fed5ee':
					add_ether = requests.put(add_group_ether + agents_S1[x].split(',')[0], headers=head)
					print(agents_S1[x].split(',')[0] + " Successfully added!")
			except:
				continue
	elif a == 'N' or a == 'n':
		print('Okay...')
	else:
		return
	
	print("Creating .csv for all agents in this instance created %d days ago..." % d)
	filename = csv_reader.agentCSV(agents_S1)
	
	#email a copy to an address
	e = input("Email a copy to someone (Y/N)?: ")
	if e == 'Y' or e == 'y':
		address = input("Enter an email address: ")
		email_google.send_email(address, filename)
	elif e == 'N' or e == 'n':
		print('Okay...')
	else:
		return


def threats_pull():
	
	try:
		d = int(input("Enter threat date range(in days), leave blank if you want it to error out: "))
	except:
		d = 0
	week_ago = today - datetime.timedelta(days=d)
	#print(week_ago)
	
	#TODO write VirusTotal function to pivot threat hash with automatic search in VirusTotal db
	threat_list = []
	#list = []
	#list = threats.json()
	
	#list of all threats
	#with open('threat_data.txt', 'w') as outfile:
		#json.dump(list, outfile)
		#outfile.close()
	
	ask = input("Active or Mitigated or Suspicious? (a/m/s): ")
	if ask == 'a':
		list1 = []
		list1 = threats_1.json()
		for x in range(0, len(list1)):
			try:
				if (
					list1[x]['meta_data']['created_at'] <= str(week_ago)
					and list1[x]['resolved'] == False
					and list1[x]['mitigation_status'] == 1
					#and list1[x]['from_scan'] == True
					#and 'Debug' in list[x]['file_id']['path']
					):
					asset = requests.get(device_pull+list1[x]['agent'], headers=head).json()
					#if asset['network_information']['computer_name'] == 'MAN-LAP-005':
					#if asset['network_information']['computer_name'] == 'col-ltp-100926':
					#if asset['network_information']['computer_name'] == 'HKG-DIS-CHWPCW7':
					#if asset['network_information']['computer_name'] == 'CDC-tony-lt':
						#print("Looking for threats specific to %s..." % asset['network_information']['computer_name'])
					threat_list.append((u'{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}'.format(asset['network_information']['computer_name'],
																			list1[x]['id'],#threat id to pivot and POST automatic status change to S1
																			list1[x]['mitigation_status'],
																			list1[x]['resolved'],
																			list1[x]['username'],
																			list1[x]['from_scan'],
																			list1[x]['engine_data'][0]['engine'],
																			list1[x]['file_id']['display_name'],
																			list1[x]['file_id']['path'],
																			list1[x]['file_id']['content_hash'],
																			list1[x]['meta_data']['created_at'].split('T')[0]
																			)))
					print("Computer name: %s" % asset['network_information']['computer_name'])
					print("Date: %s" % list1[x]['meta_data']['created_at'])
					print("Computer online?: %s" % asset['is_active'])
					print("Threat name: %s" % list1[x]['file_id']['display_name'])
					print("Path: %s" % list1[x]['file_id']['path'])
					print("Created at: %s" % list1[x]['meta_data']['created_at'])
					print("Threat id: %s" % list1[x]['id'])
					#raw_input("Enter to continue...")
					#q = input("Do you want to resolve/quarantine/skip this threat: %s? (r\q\s)" % list1[x]['id'])
					#if q == 'q':
						#threats_func.quaran(list1[x]['id'])
					#elif q == 'r':
						#threats_func.resolve(list1[x]['id'])
					#else:
						#continue
			except Exception as e:
				print(e)
				continue
	elif ask == 'm':
		list2 = []
		list2 = threats_2.json()
		listb = []
		listb = threats_b.json()
		print("Here are the MITIGATED threats...")
		time.sleep(2)
		for x in range(0,len(list2)):
			try:
				if (
					list2[x]['meta_data']['created_at'] >= str(week_ago)
					and list2[x]['resolved'] == False
					and list2[x]['mitigation_status'] == 0
					#and 'pdf.exe' not in list[x]['file_id']['display_name'] #or list[x]['mitigation_status'] == 2
					):
						asset = requests.get(device_pull+list2[x]['agent'], headers=head).json()
					#if asset['network_information']['computer_name'] == 'col-ltp-100926':
						threat_list.append((u'{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}'.format(asset['network_information']['computer_name'],
																	list2[x]['id'],#threat id to pivot and POST automatic status change to S1
																	list2[x]['mitigation_status'],
																	list2[x]['resolved'],
																	list2[x]['username'],
																	list2[x]['from_scan'],
																	list2[x]['engine_data'][0]['engine'],
																	list2[x]['file_id']['display_name'],
																	list2[x]['file_id']['path'],
																	list2[x]['file_id']['content_hash'],
																	list2[x]['meta_data']['created_at'].split('T')[0]
																	)))
						print("Computer name: %s" % asset['network_information']['computer_name'])
						print("Threat name: %s" % list2[x]['file_id']['display_name'])
			except: 
				continue
		print("Here are the BLOCKED	threats...")
		time.sleep(2)
		for x in range(0,len(listb)):
			try:
				if (
				  	listb[x]['meta_data']['created_at'] >= str(week_ago)
					and listb[x]['resolved'] == False
					and listb[x]['mitigation_status'] == 2
				   ):
						asset = requests.get(device_pull+listb[x]['agent'], headers=head).json()
						#if asset['network_information']['computer_name'] == 'col-ltp-100926':
						threat_list.append((u'{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}'.format(asset['network_information']['computer_name'],
																	listb[x]['id'],#threat id to pivot and POST automatic status change to S1
																	listb[x]['mitigation_status'],
																	listb[x]['resolved'],
																	listb[x]['username'],
																	listb[x]['from_scan'],
																	listb[x]['engine_data'][0]['engine'],
																	listb[x]['file_id']['display_name'],
																	listb[x]['file_id']['path'],
																	listb[x]['file_id']['content_hash'],
																	listb[x]['meta_data']['created_at'].split('T')[0]
																	)))
						print("Computer name: %s" % asset['network_information']['computer_name'])
						print("Threat name: %s" % listb[x]['file_id']['display_name'])
			except:
				continue
	elif ask == 's':
		list3 = []
		list3 = threats_3.json()
		for x in range(0,len(list3)):
			try:
				if (
					list3[x]['meta_data']['created_at'] >= str(week_ago)
					and list3[x]['resolved'] == False
					and list3[x]['mitigation_status'] == 3
					#and 'Debug' in list[x]['file_id']['path']
					#and 'pdf.exe' not in list[x]['file_id']['display_name'] #or list[x]['mitigation_status'] == 2
					):
					asset = requests.get(device_pull+list3[x]['agent'], headers=head).json()
					#if asset['network_information']['computer_name'] == 'MAN-LAP-005':
					#	print("Looking for threats specific to %s..." % asset['network_information']['computer_name'])
					threat_list.append((u'{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}'.format(asset['network_information']['computer_name'],
																	list3[x]['id'],#threat id to pivot and POST automatic status change to S1
																	list3[x]['mitigation_status'],
																	list3[x]['resolved'],
																	list3[x]['username'],
																	list3[x]['from_scan'],
																	list3[x]['engine_data'][0]['engine'],
																	list3[x]['file_id']['display_name'],
																	list3[x]['file_id']['path'],
																	list3[x]['file_id']['content_hash'],
																	list3[x]['meta_data']['created_at'].split('T')[0]
																		)))
					print("Computer name: %s" % asset['network_information']['computer_name'])
					print("Threat name: %s" % list3[x]['file_id']['display_name'])
					print("Path: %s" % list3[x]['file_id']['path'])
					mitigate = input(r"Do you want to resolve this threat %s? (Y\N)" % list3[x]['file_id']['display_name'])
					if mitigate == 'Y' or mitigate == 'y':
						threats_func.resolve(list3[x]['id'])
					elif mitigate == 'N' or mitigate == 'n':
						print("okay...")
					else:
						print("what?")
			except Exception as e:
				print(e)
				continue	
	mitigate = input(r"Do you want to resolve these %s threats? (Y\N)" % len(threat_list))
	if mitigate == 'Y' or mitigate == 'y':
		for t in threat_list:
			#print(t.split(',')[3].lstrip(' '))
			if t.split(',')[3].lstrip(' ') == 'False':
				#threats_func.resolve(t.split(',')[1])
				threats_func.resolve(t.split(',')[1])
			else:
				print("Threat already resolved...")
				continue
	elif mitigate == 'N' or mitigate == 'n':
		print("okay...")
	else:
		print("what?")
	#print(list)
	#print(threat_list)
	input("Press Enter to Continue...")
	#csv_reader.threatCSV(threat_list)

def manual_query():
	
	examples = """
	https://avx.sentinelone.net/___________\n\n
	
	You are going to need to enter the API query manually, if you do not know the format for\n
	your query, please visit https://avx.sentinelone.net/apidoc to learn more.\n\n
	"""
	print(examples)
	query = input("Enter your query: ")
	
	manual = requests.get("https://avx.sentinelone.net/" + query, headers = head)
	
	print(manual.json())
	print(len(manual.json()))
	
	time.sleep(15)

def deepviz():
	
	#deep_viz = requests.get("")
	agent_dict = {}
	list = []
	list = agents.json()
	
	for x in range(len(list)):
		
		asset = requests.get(device_pull+list[x]['id'], headers=head).json()['network_information']['computer_name']
		agent_dict[asset] = list[x]['uuid']
		#print(list[x])

	print(agent_dict)

#deepviz()
