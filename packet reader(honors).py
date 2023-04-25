import dpkt
import os
import socket
   
    
def filecreator(total_ip):
    
   
    for flow,packets in total_ip.items():
        #directory
        directory = "flows"
        #parent Directory path
        parent_dir = r"E:\week7files"
        #path
        path = os.path.join(parent_dir, directory, flow)
        #if os.path.exists(directory):
            #os.remove(directory)
        #create direcotry here named flow
        os.mkdir(path)
        print("Directory '%s' created" %path)
    
        counter = 0
        for p in packets:
            fname = os.path.join(path, f"{counter}")
            with open(fname, "wb") as f:
                f.write(p)
                counter +=1
                print(fname)
                
    summary(total_ip)
    
def Analyser(pcap_file):
    # Ips
    src_ip = []
    dst_ip = []
    total_ip = {}
    file = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(file)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
            #src = socket.inet_ntoa(ip.src)
            #dst = socket.inet_ntoa(ip.dst)
        if eth.type == 2048:
            
            try:
                ip = eth.data
                tcp = ip.data
                #transform values into human readeable format
                ip.src = socket.inet_ntoa(ip.src)
                ip.dst = socket.inet_ntoa(ip.dst)
                #Append source and destination IPs
                src_ip.append(ip.src)
                dst_ip.append(ip.dst)
               
                
                
                  
                total_ip[f'{ip.src}:{tcp.sport}  {ip.dst}:{tcp.dport}'].append(buf)
                
            # if error sets start value not incrementation
            except KeyError:
                   total_ip[f'{ip.src}.{tcp.sport}  {ip.dst}.{tcp.dport}'] = [buf]
            except AttributeError:
                
                 pass
    #call the json file
    filecreator(total_ip)
        
            
   
            
def main():
    pcap_file_found = False
    while pcap_file_found != True:
        #the file we work with, can be changed easily
        pcap_file = 'net-2009-11-13-09_24.pcap'
        if os.path.exists(pcap_file):
            print(f'\nFile {pcap_file} found.')
            pcap_file_found = True
        else:
            print('File not found. Please try again.\n')
    # call the analyser funciton
    Analyser(pcap_file)
# bolier plate
if __name__ == '__main__':
    main()