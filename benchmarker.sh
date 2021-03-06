#! /bin/bash

# the application to be benchmarked

APP="Evernote"

# the name of script performing the user action
#SCRIPT="UserActions/Evernote/evernote_send_message.sh"

# the network card used to be sniffed to capture the network traffic
INTERFACE="ra0"

# the IP of the Android device
DEVICE_IP="192.168.1.2"

# the number of iterations of the benchmarker
ITERATIONS=6

function set_Tor_proxy() {

        echo "Setting Tor Proxy...."	
	# open the Orbot app
	adb shell am start "org.torproject.android/.OrbotMainActivity"

	# wait for the app to be ready
	sleep 1.0

	# click the "start" button to start the Onion proxy
	adb shell input tap 530 1820 1>/dev/null
	
	# set the proxy for the wireless connection of the Android device
	adb shell am start -n tk.elevenk.proxysetter/.MainActivity -e host localhost -e port 8118
	
	# wait for the modifications to take effect
	sleep 30
}

function clear_Tor_proxy() {
	
        echo "Clearing Tor Proxy...."	
	# stop the Orbot app to stop the Onion proxy
	adb shell am force-stop "org.torproject.android"

	# clear the proxy for the wireless connection of the Android device
	adb shell am start -n tk.elevenk.proxysetter/.MainActivity -e clear true
	
	# wait for the modifications to take effect	
	sleep 10
}

# for ITERATIONS times capture the traffic generated by the user actions corresponding to the application. For each iteration the actions are executed one after the other, in the same order and each action is executed twice, once using the default network and once using the Tor network  

for ((i=0; i<ITERATIONS; i++)); do
	
for SCRIPT  in UserActions/${APP}/*; do

	echo "iteration $i SCRIPT:${SCRIPT}"
	
        # if the index of the iteration is even, first capture the flow from the default network and then the one from the Tor network; if the the index is odd, do the other way round

	if (( i%2==0 ))
	then
		# first capture the traffic generated under the default network (see the parameter "0")
		bash $SCRIPT 0 $i $INTERFACE $DEVICE_IP

		# then capture the traffic generated under the Tor network -> first set the proxy to access this network
		set_Tor_proxy

		# capture the traffic (see the parameter "1")
		bash $SCRIPT 1 $i $INTERFACE $DEVICE_IP
		
		# clear the proxy configuration
		clear_Tor_proxy
	else
		# first capture the traffic generated under the Tor network -> set the proxy to access the network
		set_Tor_proxy

		# capture the traffic produced under the anonymous network (see the parameter "1")
		bash $SCRIPT 1 $i $INTERFACE $DEVICE_IP

		# then capture the traffic generated under the default network -> clear the proxy configuration to access the network
		clear_Tor_proxy

		# capture the traffic produced under the default network (see the parameter "0")
		bash $SCRIPT 0 $i $INTERFACE $DEVICE_IP
	fi
	
	# sleep before going to the next action
	sleep 30
done

# sleep before going to the next iteraction
sleep 300
done

# finally plot the graphs relative to the user actions
for SCRIPT  in UserActions/${APP}/*; do
	python plots.py $SCRIPT $ITERATIONS $DEVICE_IP
done 
