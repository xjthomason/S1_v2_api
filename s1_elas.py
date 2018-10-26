import requests, os, json

def send_it(list):

	for x in range(0, len(list)):
		
		#print(list[x])
		r = requests.post("http://127.0.0.1:9200/_bulk?pretty", data=list[x], headers="Content-Type: application/json")
		

	return

list = []
file = 'response.json'

json_data = open(file).read()
list = json.loads(json_data)
	
#print(list)
send_it(list)
#print(len(list))
