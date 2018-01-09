import socket  # for sockets
import sys  # for exit
import binascii
import logging
import os
from datetime import datetime
import collections
import subprocess

def sendUdpRequest(h,p):
    port=int(p)
    host=h
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        #print 'Failed to create socket'
        logging.error('Failed to create socket')
        sys.exit()

    #msg = raw_input('Enter message to send : ')
    msg = "006D0000000D00000001010000005101BB000001003C01004E02B393B197E4B350CB420CAAC664CD56A4C8B98D08B2B490334405105C12102E11E302910E3104C4B40092100001000000000000000000000000000096040002000067080000000000000000E7A2322A3876C3340F"
    msg = msg.decode('hex')

    try:
        # Set the whole string
        #print 'Sending to:',host,port,'...' # ,binascii.hexlify(msg)
        logging.debug('Sending to:'+str(host)+':'+str(port))

        s.sendto(msg, (host, port))
        s.settimeout(4)

        # receive data from client (data, addr)
        d = s.recvfrom(1024)
        reply = d[0]
        addr = d[1]

        #print 'Server reply: ', binascii.hexlify(reply)
        logging.debug('Server reply: '+str(binascii.hexlify(reply)))

    except socket.error, msg:
        #print 'Error Code :', socket.error, str(msg[0])
        logging.error('Error Code :'+ str(socket.error) + str(msg[0]))
        #print 'Sending alert ...'
        logging.debug('Sending alert ...')
        try:
            cmd = "echo 'Subject: SSH Board ERROR' | sendmail -v " + params['email']
            ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = ps.communicate()[0]
            #print output
            logging.debug(output)

        except:
            #print "could not send email"
            logging.error("could not send email")
            #sys.exit()
        pass


def get_hosts(ssh_config_file, c, argu=0):
    myfunc = sys._getframe().f_code.co_name
    logging.info("Calling function: " + myfunc)
    hosts = []
    if argu:
        return [c['host']]
    else:
        with open(ssh_config_file, 'r') as f:
            lines = filter(None, (line.rstrip() for line in f))
            for line in lines:
                if not line.startswith(";") and 'HostName' in line:
                    results = collections.Counter(line)
                    if results['='] <= 1:
                        (key, val) = line.split("=")
                        key = key.lstrip()
                        val = val.lstrip()
                        val = val.replace('"', '')
                        if 'HostName' in key:
                            if key.startswith("HostName"):
                                hosts.append(val)
        if hosts:
            #print 'hosts:', hosts
            logging.debug(hosts)
        else:
            logging.error("ERROR no host found")
            #print 'ERROR no host found'

            sys(exit())

        return hosts

def get_params(config_file, argu=0):
    myfunc = sys._getframe().f_code.co_name
    logging.info("Calling function: " + myfunc)
    # hardcoded default values
    params = {#'host': '',
              'email': '',
              'timeout': '',
              'port': '',
              'ssh_client_path': '',
              }
    with open(config_file, 'r') as f:
        lines = filter(None, (line.rstrip() for line in f))
        for line in lines:
            if not line.startswith("#") and '=' in line:
                results = collections.Counter(line)
                if results['='] <= 1:
                    (key, val) = line.split("=")
                    if val and params.has_key(key):
                        params[key] = val
                    if 'email' in key:
                        if key.startswith("email"):
                            params['email'] = val
                    if 'timeout' in key:
                        if key.startswith("timeout"):
                            params['timeout'] = int(val)
                    if 'ssh_client_path' in key:
                        if key.startswith("ssh_client_path"):
                            params['ssh_client_path'] = val


    if all(params.values()):
        #print 'Configurations:'
        #print '==============='
        logging.info('Configurations:')
        logging.info('===============')
        for k, v in params.items():
            # Display key and value.
            #print k, '=', v
            logging.info(str(k)+"="+str(v))
        logging.debug(params)
        return params
    else:
        print 'ERROR Missing Configuration', params
        logging.error("ERROR Missing Configuration")
        logging.error(params)
        sys(exit())


logging.basicConfig(filename=datetime.now().strftime('testBoards_%d-%m-%Y.log'),
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
config_file = 'testBoards.cfg'
params = get_params(config_file, (sys.argv[1] if len(sys.argv) >= 2 else ''))
hosts = get_hosts(params['ssh_client_path'],params,(sys.argv[1] if len(sys.argv) >= 2 else ''))
for host in hosts:
    sendUdpRequest(host,params['port'])
