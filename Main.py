import sys
import time
import logging
import json
import csv
from genie.testbed import load
from pyats.log.utils import banner

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(message)s')
log = logging.getLogger()

log.info(banner("Loading TESTBED FILES"))
testbed = load('device.yml')
log.info("\nPASS: Successfully loaded testbed '{}'\n".format(testbed.name))

######## Defining header lists for information to be stored within the csv files under each category ########

device_names = ['Switch', 'Version', 'Image', 'Model', 'Memory', 'Flash', 'Serial Number']
interface_names = ['Switch', 'Description', 'Status', 'VLAN', 'DUPLEX', 'SPEED','PORT TYPE']
arp_names = ['Switch', 'IP', 'MAC', 'INTERFACE', 'ORIGIN', 'AGE']
cdp_names = ['Switch', 'REMOTE_DEVICE', 'REMOTE_NATIVEVLAN', 'REMOTE_DEVICE_NAME', 'REMOTE_DEVICE_MGTIP', 'REMOTE_IP', 'REMOTE_PORT', 'LOCAL_PORT']
mac_names = ["Switch","MAC_ADDRESS", "MAC_TYPE", "MAC_VLAN", "MAC_PORT"]
portchannel_names = ["Switch","CHANNEL_ID", "CHANNEL_TYPE", "CHANNEL_PROT", "CHANNEL_LAYER", "CHANNEL_STATUS", "CHANNEL_MEMBERS"]
intf_brief_names = ["Switch","INTERFACE_NAME", "IP_ADDRESS", "INTERFACE_STATUS"]


########## Defining output csv file names for each output category
csv_file = "Device.csv"
csv_file = "Interface.csv"
csv_file = "Arp.csv"
csv_file = "cdp.csv"
csv_file = "mac.csv"
csv_file = "portchannel.csv"
csv_file = "IntBrief.csv"

########## Create a dictionary that collects output from each category commands

Device_Audit = {}
Intf_Audit = {}
Arp_Audit = {}
cdp_Audit = {}
mac_Audit = {}
portchannel_Audit = {}
intf_brief_Audit = {}

########## Create a list to store each of the dictionary outputs from each of the category commands #########

Device_Store = []
Intf_Store = []
Arp_Store = []
cdp_Store = []
mac_Store = []
portchannel_Store = []
intf_brief_Store = []

######## Connection to the device within the testbed environment files ###########################

for device in testbed:
    
    device.connect()

    runn = device.execute('show run')
    ver_raw = device.execute('show version')
    ver = device.parse('show version')
    intf_status = device.parse('show interface status')
    intf_status_raw = device.execute('show interface status')
    arp_raw = device.execute('show ip arp')
    arp = device.parse('show ip arp')
    cdp_nei = device.parse('show cdp neighbor detail')
    cdp_nei_raw = device.execute('show cdp neighbor detail')
    mac_raw = device.execute('show mac address-table')
    mac3 = device.execute('show mac address-table | json')
    port_channel_raw = device.execute('show port-channel summary')
    port_channel = device.parse('show port-channel summary')
    intf_brief = device.parse('show ip int brief')
    intf_brief_raw = device.execute('show ip int brief')
    
    
########## Write each of the section outputs into the text file for reference later ###################################

    with open(device.alias+'Output.txt', 'a') as f:
        f.write('\n\n ########## RUNNING CONFIGURATION OUTPUT ########################## \n\n ')
        f.write(str(runn))
        f.write('\n\n ########### SHOW VERSION OUTPUT ###################### \n\n ')
        f.write(str(ver_raw))
        f.write('\n\n ##############SHOW INTERFACE STATUS OUTPUT ########################## \n\n')
        f.write(str(intf_status_raw))
        f.write('\n\n ##############SHOW IP ARP TABLE OUTPUT ############################# \n\n')
        f.write(str(arp_raw))
        f.write('\n\n ##############SHOW CDP NEIGHBOR OUTPUT ############################# \n\n')
        f.write(str(cdp_nei_raw))
        f.write('\n\n ##############SHOW MAC ADDRESS TABLE OUTPUT ############################# \n\n ')
        f.write(str(mac_raw))
        f.write('\n\n ##############SHOW PORT CHANNEL SUMMARY OUTPUT ############################# \n\n ')
        f.write(str(port_channel_raw))
        f.write('\n\n ##############SHOW IP INT BRIEF OUTPUT ############################# \n\n ')
        f.write(str(intf_brief_raw))

#####################################################################################################################
######## Extracting Audit Requirements from the Show version output #################################################

    sys_version = ver['platform']['software']['system_version']
    sys_image = ver['platform']['software']['system_image_file']
    sys_model = ver['platform']['hardware']['model']
    sys_memory = ver['platform']['hardware']['memory']
    sys_flash = ver['platform']['hardware']['bootflash']
    sys_serial = ver['platform']['hardware']['processor_board_id']

    Device_Audit = {"Switch": device.alias, "Version": sys_version, "Image": sys_image, "Model": sys_model, "Memory": sys_memory, "Flash": sys_flash, "Serial Number": sys_serial}
    Device_Store.append(Device_Audit)


##################################################################################################################################
######## Extracting Audit Requirements from the Show interfaces status output #################################################

    for intf in intf_status['interfaces'].keys():
        #print(intf_status['interfaces'][intf]['vlan'])
        if 'name' and 'type' in intf_status['interfaces'][intf].keys():
            intfa_desc = intf_status['interfaces'][intf]['name']
            intfa_status = intf_status['interfaces'][intf]['status']
            intfa_vlan = intf_status['interfaces'][intf]['vlan']
            intfa_duplex = intf_status['interfaces'][intf]['duplex_code']
            intfa_speed = intf_status['interfaces'][intf]['port_speed']
            intfa_type = intf_status['interfaces'][intf]['type']
        elif 'name' in intf_status['interfaces'][intf].keys():
            intfa_desc = intf_status['interfaces'][intf]['name']
            intfa_status = intf_status['interfaces'][intf]['status']
            intfa_vlan = intf_status['interfaces'][intf]['vlan']
            intfa_duplex = intf_status['interfaces'][intf]['duplex_code']
            intfa_speed = intf_status['interfaces'][intf]['port_speed']
            intfa_type = 'NA'
        else:
            #print(intf_status['interfaces'])
            intfa_desc = 'N/A'
            intfa_status = intf_status['interfaces'][intf]['status']
            intfa_vlan = intf_status['interfaces'][intf]['vlan']
            intfa_duplex = intf_status['interfaces'][intf]['duplex_code']
            intfa_speed = intf_status['interfaces'][intf]['port_speed']
            intfa_type = 'N/A'
    
        Intf_Audit = {"Switch": device.alias, "Description": intfa_desc, "Status": intfa_status, "VLAN": intfa_vlan, "DUPLEX": intfa_duplex, "SPEED": intfa_speed, "PORT TYPE": intfa_type}
        Intf_Store.append(Intf_Audit)

####################################################################################################################################################################################       
######## Extracting Audit Requirements from the Show ip arp output #################################################

    for intf in arp['interfaces'].keys():
        for arp_intf in arp['interfaces'][intf]['ipv4']['neighbors'].keys():
            arp_ip = arp['interfaces'][intf]['ipv4']['neighbors'][arp_intf]['ip']
            arp_mac = arp['interfaces'][intf]['ipv4']['neighbors'][arp_intf]['link_layer_address']
            arp_phy = arp['interfaces'][intf]['ipv4']['neighbors'][arp_intf]['physical_interface']
            arp_origin = arp['interfaces'][intf]['ipv4']['neighbors'][arp_intf]['origin']
            arp_age = arp['interfaces'][intf]['ipv4']['neighbors'][arp_intf]['age']

            Arp_Audit = {"Switch": device.alias, "IP": arp_ip, "MAC": arp_mac, "INTERFACE": arp_phy, "ORIGIN": arp_origin, "AGE": arp_age}
            Arp_Store.append(Arp_Audit)         

####################################################################################################################################################################################       
######## Extracting Audit Requirements from the Show cdp neighbor detail output #################################################

    j = 1
    while j < len(cdp_nei['index'].keys()):
        cdp_remote_device = cdp_nei['index'][j]['device_id']
        print(cdp_nei['index'][j]['duplex_mode'])   
        print(cdp_nei['index'][j]['vtp_management_domain'])   
        cdp_remote_nativevlan = print(cdp_nei['index'][j]['native_vlan'])   
        #print(cdp_nei['index'][j]['physical_location'])   
        cdp_remote_name = cdp_nei['index'][j]['system_name']
        cdp_remote_mgtip = cdp_nei['index'][j]['management_addresses']
        cdp_remote_ip = cdp_nei['index'][j]['interface_addresses']
        #print(cdp_nei['index'][j]['capabilities'])   
        print(cdp_nei['index'][j]['platform'])   
        cdp_remote_port = cdp_nei['index'][j]['port_id']
        cdp_local_port = cdp_nei['index'][j]['local_interface']
        #print(cdp_nei['index'][j]['hold_time']) 
        #print(cdp_nei['index'][j]['software_version']) 
        #print(cdp_nei['index'][j]['advertisement_ver'])
        j+=1     

        cdp_Audit = {"Switch": device.alias, "REMOTE_DEVICE": cdp_remote_device, "REMOTE_NATIVEVLAN": cdp_remote_nativevlan, "REMOTE_DEVICE_NAME": cdp_remote_name, "REMOTE_DEVICE_MGTIP": cdp_remote_mgtip, "REMOTE_IP": cdp_remote_ip, "REMOTE_PORT": cdp_remote_port, "LOCAL_PORT": cdp_local_port}
        cdp_Store.append(cdp_Audit)
        
####################################################################################################################################################################################       
######## Extracting Audit Requirements from the Show mac address-table output ################################################# 
    
    mac2 = json.loads(mac3)
    
    i=0
    while i < len(mac2['TABLE_mac_address']['ROW_mac_address']):
        mac = mac2['TABLE_mac_address']['ROW_mac_address'][i]
        mac_hwaddress = mac['disp_mac_addr']
        mac_hwtype = mac['disp_type']
        mac_hwvlan = mac['disp_vlan']
        mac_hwstatic = mac['disp_is_static']
        mac_hwage = mac['disp_age']
        mac_hwsecure = mac['disp_is_secure']
        mac_hwnotify = mac['disp_is_ntfy']
        mac_hwdisport = mac['disp_port']
        i=i+1

        mac_Audit = {"Switch": device.alias, "MAC_ADDRESS": mac_hwaddress, "MAC_TYPE": mac_hwtype, "MAC_VLAN": mac_hwvlan, "MAC_PORT": mac_hwdisport}
        mac_Store.append(mac_Audit)

####################################################################################################################################################################################       
######## Extracting Audit Requirements from the Show Port-Channel Summary output ################################################# 

    for port_intf in port_channel['interfaces'].keys():
        portchannel_id = port_channel['interfaces'][port_intf]['bundle_id']
        portchannel_type = port_channel['interfaces'][port_intf]['type']
        portchannel_prot = port_channel['interfaces'][port_intf]['protocol']
        portchannel_layer = port_channel['interfaces'][port_intf]['layer']
        portchannel_operstatus = port_channel['interfaces'][port_intf]['oper_status']
        portchannel_members = port_channel['interfaces'][port_intf]['members']
        #for member in port_channel['interfaces'][port_intf]['members'].keys():
            #print(member)
            #print(port_channel['interfaces'][port_intf]['members'][member]['flags'])
        portchannel_Audit = {"Switch": device.alias, "CHANNEL_ID": portchannel_id, "CHANNEL_TYPE": portchannel_type, "CHANNEL_PROT": portchannel_prot, "CHANNEL_LAYER": portchannel_layer , "CHANNEL_STATUS": portchannel_operstatus, "CHANNEL_MEMBERS":portchannel_members}
        portchannel_Store.append(portchannel_Audit)        


####################################################################################################################################################################################       
######## Extracting Audit Requirements from the Show ip int brief output ################################################# 

    for set in intf_brief['interface'].keys():
        if 'vlan_id' in intf_brief['interface'][set].keys():
            for key in intf_brief['interface'][set]['vlan_id']:
                intfb_name = set
                intfb_ip = intf_brief['interface'][set]['vlan_id'][key]['ip_address']
                intfb_status = intf_brief['interface'][set]['vlan_id'][key]['interface_status']
        elif 'ip_address' in intf_brief['interface'][set].keys():
            intfb_name = set
            intfb_ip = intf_brief['interface'][set]['ip_address']
            intfb_status = intf_brief['interface'][set]['interface_status']
              
        intf_brief_Audit = {"Switch": device.alias, "INTERFACE_NAME": intfb_name, "IP_ADDRESS": intfb_ip, "INTERFACE_STATUS": intfb_status}
        intf_brief_Store.append(intf_brief_Audit)        

##########  Writing the final lists of results into the various csv outputs  ################# 

with open('Device.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= device_names)
    writer.writeheader()
    writer.writerows(Device_Store)

with open('Interface.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= interface_names)
    writer.writeheader()
    writer.writerows(Intf_Store)
    
with open('Arp.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= arp_names)
    writer.writeheader()
    writer.writerows(Arp_Store)

with open('cdp.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= cdp_names)
    writer.writeheader()
    writer.writerows(cdp_Store)

with open('mac.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= mac_names)
    writer.writeheader()
    writer.writerows(mac_Store)

with open('portchannel.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= portchannel_names)
    writer.writeheader()
    writer.writerows(portchannel_Store)

with open('intf_brief.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames= intf_brief_names)
    writer.writeheader()
    writer.writerows(intf_brief_Store)