import requests, datetime, time, json, pytz
from tzlocal import get_localzone

import csv_reader, email_google

today = datetime.date.today()
week_ago = today - datetime.timedelta(days=1)
local_tz = get_localzone()

token_file = open("S1_token.txt", 'r')
myToken = 'APIToken ' + token_file.read()
head = {'Authorization': myToken}
threats = []
threats = requests.get("https://avx.sentinelone.net/web/api/v1.6/threats?limit=5000", headers=head).json()

device_pull = "https://avx.sentinelone.net/web/api/v1.6/agents/"

def utc_to_local(utc_dt):
	local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
	return local_tz.normalize(local_dt)

def threat_search(hash):
	
	for x in range(len(threats)):
		#print(threats[x])
		if hash in threats[x]['file_id']['content_hash']:
			#print(threats[x]['file_id']['display_name'])
			return threats[x]['file_id']['display_name']

def user_info():
	
	users = requests.get("https://avx.sentinelone.net/web/api/v1.6/users", headers=head)
	user_response = users.json()
	print(len(user_response))
	
	for x in range(0, len(user_response)):
		
		print(user_response[x]['full_name'])
	
	#print(user_response)

def user_actions():
	list_user_actions = []
	errors = 0

	# Get User Info from S1
	users = requests.get("https://avx.sentinelone.net/web/api/v1.6/users", headers=head)
	user_response = users.json()
	# Get Activity Types
	act_list = requests.get("https://avx.sentinelone.net/web/api/v1.6/activities/types", headers=head)
	act_list_resp = act_list.json()

	# Build Activities Dict
	act_dict = {}
	for x in range(0, 200):
		try:
			act_dict[act_list_resp[x]['id']] = act_list_resp[x]['action']
		except:
			continue

    # Build User Dict
	user_dict = {}
	for x in range(0, 75):
		try:
			user_dict[user_response[x]['id']] = user_response[x]['username']
		except:
			continue

	# Activities List
	activities = requests.get("https://avx.sentinelone.net/web/api/v1.6/activities?limit=5000", headers=head)
	activities_list = activities.json()

	for x in range(0, 5000):
		try:
			if (activities_list[x]['meta_data']['created_at'] >= str(week_ago)
				and activities_list[x]['user_id'] is not None):
				user = user_dict[activities_list[x]['user_id']]
				act_time = activities_list[x]['meta_data']['created_at']
				dt_obj = datetime.datetime.strptime(act_time, '%Y-%m-%dT%H:%M:%S.%fZ')
				dt_obj_tz = utc_to_local(dt_obj)
				asset = requests.get(device_pull+activities_list[x]['agent_id'], headers=head).json()
				#if (asset['network_information']['computer_name'] == 'col-ltp-100926'
				#	and 'Threat' not in act_dict[activities_list[x]['activity_type']]):
					#print(asset['network_information']['computer_name'])
					#print(dt_obj_tz)
				list_user_actions.append((r'{0}, {1}, {2}, {3}'.format(user_dict[activities_list[x]['user_id']],
																			act_dict[activities_list[x]['activity_type']],
																			activities_list[x]['description'],
																			dt_obj_tz
																			)))
		except ValueError:
			try:
				user = user_dict[activities_list[x]['user_id']]
				act_time = activities_list[x]['meta_data']['created_at']
				dt_obj = datetime.datetime.strptime(act_time, '%Y-%m-%dT%H:%M:%SZ')
				dt_obj_tz = utc_to_local(dt_obj)
				asset = requests.get(device_pull+activities_list[x]['agent_id'], headers=head).json()
				#if (asset['network_information']['computer_name'] == 'col-ltp-100926'
				#	and 'Threat' not in act_dict[activities_list[x]['activity_type']]):
					#print(asset['network_information']['computer_name'])
					#print(dt_obj_tz)
				list_user_actions.append((r'{0}, {1}, {2}, {3}'.format(user_dict[activities_list[x]['user_id']],
																			act_dict[activities_list[x]['activity_type']],
																			activities_list[x]['description'],
																			dt_obj_tz
																			)))
			except:
				print("Inception")
				errors += 1
				continue
		except TypeError:
			#print("how do I handle this?")
			#try:
			user = user_dict[activities_list[x]['user_id']]
			act_time = activities_list[x]['meta_data']['created_at']
			dt_obj = datetime.datetime.strptime(act_time, '%Y-%m-%dT%H:%M:%S.%fZ')
			dt_obj_tz = utc_to_local(dt_obj)
			
			if activities_list[x]['agent_id'] is not None:
			    #and asset['network_information']['computer_name'] == 'col-ltp-100926'
			    #and 'Threat' not in act_dict[activities_list[x]['activity_type']]):
				asset = requests.get(device_pull+activities_list[x]['agent_id'], headers=head).json()
				#print(asset['network_information']['computer_name'])
				#print(dt_obj_tz)
				list_user_actions.append((r'{0}, {1}, {2}, {3}'.format(user_dict[activities_list[x]['user_id']],
																		act_dict[activities_list[x]['activity_type']],
																		activities_list[x]['description'],
																		dt_obj_tz
																		)))
			else:
				#if act_dict[activities_list[x]['activity_type']] == 'User Added White Hash':
				if activities_list[x]['hash'] is not None:
					act_time = activities_list[x]['meta_data']['created_at']
					dt_obj = datetime.datetime.strptime(act_time, '%Y-%m-%dT%H:%M:%S.%fZ')
					dt_obj_tz = utc_to_local(dt_obj)
					list_user_actions.append((r'{0}, {1}, {2}, {3}'.format(user_dict[activities_list[x]['user_id']],
																			act_dict[activities_list[x]['activity_type']],
																			threat_search(activities_list[x]['hash']),
																			dt_obj_tz
																			)))
				else:
					act_time = activities_list[x]['meta_data']['created_at']
					dt_obj = datetime.datetime.strptime(act_time, '%Y-%m-%dT%H:%M:%S.%fZ')
					dt_obj_tz = utc_to_local(dt_obj)
					list_user_actions.append((r'{0}, {1}, {2}, {3}'.format(user_dict[activities_list[x]['user_id']],
														act_dict[activities_list[x]['activity_type']],
														activities_list[x]['description'],
														dt_obj_tz
														)))
					#print(user_dict[activities_list[x]['user_id']])
					#print(dt_obj)
					#print(threat_search(activities_list[x]['hash']))
						
			#except Exception as e:
				#print(e)
				##print(activities_list[x]['agent_id'])
				#errors += 1
				#continue
			continue
	csv_reader.userCSV(list_user_actions)
	#print(list_user_actions)
	print("Error count: %d" % errors)

	#for x in list_user_actions:
	#print(x)
	# return

#user_actions()
user_info()
