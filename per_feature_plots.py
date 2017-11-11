import json
import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from matplotlib.font_manager import FontProperties
import matplotlib.patches as mpatches

# the number of iterations performed by the benchmarker
ITERATIONS = int(sys.argv[1])

# the IP of the Android device used in the test of each app
DEVICE_IP =  {'Dropbox': '192.168.1.5', 'Gmail': '192.168.1.5', 'Evernote': '192.168.1.2', 'Facebook': '192.168.1.5', 'Twitter': '192.168.1.2'}

# the colors for the bars representing each app
COLORS = {'Dropbox': ('crimson', 'coral'), 'Gmail': ('gray', 'darkgray'), 'Evernote': ('darkgreen', 'lime'), 'Facebook': ('darkblue', 'mediumslateblue'), 'Twitter': ('saddlebrown', 'peru')}

# the list of the features considered: for each feature we provide the title and the label of the y-axis of the related graph
FEATURES = {'Avg In Pack': ['Average Size of Incoming Packets', 'Size (bytes)'], 'Avg Out Pack': ['Average Size of Outgoing Packets', 'Size (bytes)'], 'Avg All Pack': ['Average Size of All Packets', 'Size (bytes)'], 'Tot In Size': ['Total Size of Incoming Packets', 'Size (bytes)'], 'Tot Out Size': ['Total Size of Outgoing Packets', 'Size (bytes)'], 'Tot Size': ['Total Size of All Packets', 'Size (bytes)'], 'Num In Packs': ['Number of Incoming Packets', 'Number of packets'], 'Num Out Packs': ['Number of Outgoing Packets', 'Number of packets'], 'Num Tot Packs': ['Number of Packets', 'Number of packets'], 'Num Unique Sizes': ['Number of Packets with Unique length', 'Number of packets'], 'Action Duration': ['Duration of the action', 'Duration (seconds)']}

# the path to the folder containing the bash scripts simulating the user actions (the path is relative to the python script)
SCRIPTS_FOLDER = "UserActions/"

# the path to the folder containing the .csv files containing the network traffic captured (the path is relative to the python script)
IN_FOLDER = "Traces/"

# the path to folder where the plots have to be stored (the path is relative to the python script, which is the same as the benchmarker)
OUT_FOLDER = "Plots/"

# get the list of apps
APPS = [name for name in os.listdir(SCRIPTS_FOLDER)] 

# get the list of user actions for the given app
# @app: the name of the app
# @returns: the list with the list of scripts

def get_user_actions(app):
	global SCRIPTS_FOLDER
	return [name[:-3] for name in os.listdir(SCRIPTS_FOLDER + app)]

# extract the value of the given feature during a single iteration of the script:
# @feature: the feature to be evaluated
# @file_path: the path to the csv file being parsed
# @data: the structure where the extracted data have to be put
# @ip: the IP address of the device

def process_csv(feature, file_path, data, ip):
	
	# read the csv into a DataFrame object; use \t as separator
	df = pd.read_csv(file_path, sep = '\t')
	
	# replace the "." in the columns with a "_" for some columns
	df.rename(columns = {'ip.dst': 'ip_dst'}, inplace = True)
	df.rename(columns = {'ip.src': 'ip_src'}, inplace = True)

	# get the key from the filename of the script	
	split_script_name = file_path.split("/")[2].split(".")[0].split("_")
	key = ""
	for element in split_script_name[:-1]:
		key += element + "_"
	
	# compute the function corresponding to the requested feature
	if feature == 'Avg In Pack':
		# get the average size of incoming packets
		data[key[:-1]].append(df.query('ip_dst==@ip')['frame.len'].mean())
		return
	
	if feature == 'Avg Out Pack':
		# get the average size of outgoing packets
		data[key[:-1]].append(df.query('ip_src==@ip')['frame.len'].mean())
		return
	
	if feature == 'Avg All Pack':
		# get the average size of all packets
		data[key[:-1]].append(df['frame.len'].mean())
		return

	if feature == 'Tot In Size':
		# get the total size of incoming packets
		data[key[:-1]].append(df.query('ip_dst==@ip')['frame.len'].sum())
		return

	if feature == 'Tot Out Size':
		# get the total size of outgoing packets
		data[key[:-1]].append(df.query('ip_src==@ip')['frame.len'].sum())
		return

	if feature == 'Tot Size':
		# get the total size of all packets
		data[key[:-1]].append(df['frame.len'].sum())
		return

	if feature == 'Num In Packs':
		# get the number of incoming packets
		data[key[:-1]].append(df.query('ip_dst==@ip')['frame.number'].count())
		return

	if feature == 'Num Out Packs':
		# get the number of outgoing packets
		data[key[:-1]].append(df.query('ip_src==@ip')['frame.number'].count())
		return

	if feature == 'Num Tot Packs':
		# get the number of all packets
		data[key[:-1]].append(df['frame.number'].count())
		return
		
	if feature == 'Num Unique Sizes':
		# get the number of packets with unique size
		_, counters = np.unique(df['frame.len'], return_counts=True)
		unique_lengths = 0
		for count in counters:
			if count == 1:
				unique_lengths += 1
		data[key[:-1]].append(unique_lengths)
		return

	if feature == 'Action Duration':
		# get the duration of the action
		if df['_ws.col.Time'].count() > 0:
                	data[key[:-1]].append(df['_ws.col.Time'].iloc[-1] - df['_ws.col.Time'].iloc[0])
        	else:
                	data[key[:-1]].append(0)
		return

# plot the graph related to the feature for each user action of the given app
# @app: the name of the app
# @feature: the feature to be plotted

def plot_graphs_app(app, feature):
	global ITERATIONS
	global DEVICE_IP
	
	# the dictionary containing aggregated data from all the iterations under the default network. It has:
	# - one key for each of the script, i.e. each user action
	# - the entry for each key is a list containing the values of the feature measured for each iteration of the user action
	data_default = defaultdict(list)

	# an equivalent data structure keeps track of the corresponding values of the features measured under the Tor network
	data_tor = defaultdict(list)
	
	# get the user actions of the current app
	user_actions = get_user_actions(app)

	# for each user action, read the corresponding .csv files, one per iteration, read the value of the feature, do the average and 
	# plot the graph
	for user_action in user_actions:

		# read the two .csv files corresponding to the user action (one produced under the default network and one produced under 
		# the Tor network) and parse them to fill the above dictionaries

		for iteration in range(ITERATIONS):

			# the relative path to the csv gathered during the current iteration under the default network
			csv_file = IN_FOLDER + app + "/" + user_action + "_" + str(iteration) + ".csv"
	
			# parse the csv file
			process_csv(feature, csv_file, data_default, DEVICE_IP[app])
		
			# the relative path to the csv gathered during the current iteration under the Tor network
			csv_file = IN_FOLDER + app + "/" + user_action + "_tor_" + str(iteration) + ".csv"
	
			# parse the csv file
			process_csv(feature, csv_file, data_tor, DEVICE_IP[app])

	# the dictionary with the aggregated values of the feature. It has a key for each of the above user actions and the corresponding 
	# value is a list with two elements:
	# 1- the average value over all the iterations of the user action under the default network
	# 2- the average value over all the iterations of the user action under the Tor network

	aggregated_data = defaultdict(list)

	# create a DataFrame out of the dictionary with values of the feature in order to compute their average values more easily
	default_df = pd.DataFrame(data_default)
	tor_df = pd.DataFrame(data_tor)
	
	# the indexes are represented by the user actions without the "app prefix"
	for user_action in user_actions:
		
		split_name = user_action.split("_")
		key = ""
		for element in split_name[1:]:
			key += element + "_"
		aggregated_data[key[:-1]].append(default_df[user_action].mean())
		aggregated_data[key[:-1]].append(tor_df[user_action + "_tor"].mean())


	# the DataFrame for the user actions of the current app:
	# -one row for each user action
	# -one column for the aggregated value of the feature under the default network, one for the value collected under the Tor network

	df = pd.DataFrame(aggregated_data, index=[app + "_default", app + "_tor"]).transpose()
	return df
	#fig, ax = plt.subplots()
	#ax.set_title('App: ' + app)
	#ax.set_ylabel('Size (bytes)')
	#df.plot(kind = 'bar', ax = ax, rot = 45)
	#fig.savefig(OUT_FOLDER + app + "_tot_size.pdf", bbox_inches='tight')


# plot the graphs for each feature

for feature in FEATURES:
	fig, axes = plt.subplots(1, 5, sharey = True)
	data_frames = list()
	legends = list()
	i = 0
	for app in APPS:
		data_frames.append(plot_graphs_app(app, feature))
		axes[i].set_title(app)
		if i == 0:
			axes[i].set_ylabel(FEATURES[feature][1])
		data_frames[i].plot(kind = 'bar', ax = axes[i], rot = 90, color = COLORS[app], legend = False)
		patch = mpatches.Patch(color= COLORS[app][0], label = app + "_default")
		patch_tor = mpatches.Patch(color= COLORS[app][1], label = app + "_tor")
		legends.append(patch)
		legends.append(patch_tor)
		i += 1
	plt.suptitle(FEATURES[feature][0])
	plt.legend(handles = legends, loc='center left', bbox_to_anchor=(1, 0.5))
	split_feature_name = feature.split(" ")
	filename = ""
	for string in split_feature_name:
		filename += string.lower()
	fig.savefig(OUT_FOLDER + filename + ".pdf", bbox_inches='tight')

#for ax in axes:
