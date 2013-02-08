#!/usr/bin/env python
# -*- coding: utf-8

# Written by Morgan Borman
# Based on smfauth.py which included the following license;
# Copyright (C) 2010 Stefan Hacker <dd0t@users.sourceforge.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:

# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# - Neither the name of the Mumble Developers nor the names of its
#   contributors may be used to endorse or promote products derived from this
#   software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# `AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
#    mumbleteams.py - Automatically adjusts user channels based on in-game teams.
#
#    Requirements:
#        * python >=2.4 and the following python modules:
#            * ice-python
#            * MySQLdb
#            * daemon (when run as a daemon)
#

import sys
import Ice
import thread
import socket
import select
import urllib2
import logging
import threading
import ConfigParser

from threading  import Timer
from optparse   import OptionParser
from logging    import (debug,
                        info,
                        warning,
                        error,
                        critical,
                        exception,
                        getLogger)

try:
    from hashlib import sha1
except ImportError: # python 2.4 compat
    from sha import sha as sha1

def x2bool(s):
    """Helper function to convert strings from the config to bool"""
    if isinstance(s, bool):
        return s
    elif isinstance(s, basestring):
        return s.lower() in ['1', 'true']
    raise ValueError()

#
#--- Default configuration values
#
cfgfile = 'mumbleteams.ini'
default = { 'user':(('id_offset', int, 1000000000),),
                    
            'ice':(('host', str, '127.0.0.1'),
                   ('port', int, 6502),
                   ('slice', str, 'Murmur.ice'),
                   ('secret', str, ''),
                   ('watchdog', int, 30)),
                   
            'iceraw':None,
            'listen':(('port', int, 28783),),
                   
            'murmur':(('servers', lambda x:map(int, x.split(',')), []),),
            'glacier':(('enabled', x2bool, False),
                       ('user', str, 'smf'),
                       ('password', str, 'secret'),
                       ('host', str, 'localhost'),
                       ('port', int, '4063')),
                       
            'log':(('level', int, logging.DEBUG),
                   ('file', str, 'mumbleteams.log'))}
 
#
#--- Helper classes
#
class config(object):
    """
    Small abstraction for config loading
    """

    def __init__(self, filename = None, default = None):
        if not filename or not default: return
        cfg = ConfigParser.ConfigParser()
        cfg.optionxform = str
        cfg.read(filename)
        
        for h,v in default.iteritems():
            if not v:
                # Output this whole section as a list of raw key/value tuples
                try:
                    self.__dict__[h] = cfg.items(h)
                except ConfigParser.NoSectionError:
                    self.__dict__[h] = []
            else:
                self.__dict__[h] = config()
                for name, conv, vdefault in v:
                    try:
                        self.__dict__[h].__dict__[name] = conv(cfg.get(h, name))
                    except (ValueError, ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                        self.__dict__[h].__dict__[name] = vdefault
                    
def entity_decode(string):
    """
    Python reverse implementation of php htmlspecialchars
    """
    htmlspecialchars = (('"', '&quot;'),
                        ("'", '&#039;'),
                        ('<', '&lt;'),
                        ('>', '&gt'),
                        ('&', '&amp;'))
    ret = string
    for (s,t) in htmlspecialchars:
        ret = ret.replace(t, s)
    return ret

def entity_encode(string):
    """
    Python implementation of htmlspecialchars
    """
    htmlspecialchars = (('&', '&amp;'),
                        ('"', '&quot;'),
                        ("'", '&#039;'),
                        ('<', '&lt;'),
                        ('>', '&gt'))
    ret = string
    for (s,t) in htmlspecialchars:
        ret = ret.replace(s, t)
    return ret

def do_main_program():
    #
    #--- Authenticator implementation
    #    All of this has to go in here so we can correctly daemonize the tool
    #    without loosing the file descriptors opened by the Ice module
    Ice.loadSlice('', ['-I' + "/usr/share/Ice-3.4.2/slice/", cfg.ice.slice])
    #Ice.loadSlice('', ['-I' + Ice.getSliceDir(), cfg.ice.slice])
    import Murmur
    
    class mumbleteamsApp(Ice.Application):
        def run(self, args):
            self.shutdownOnInterrupt()
            
            if not self.initializeIceConnection():
                return 1

            if cfg.ice.watchdog > 0:
                self.metaUptime = -1
                self.checkConnection()
                
            # Serve till we are stopped
            self.communicator().waitForShutdown()
            self.watchdog.cancel()
            
            if self.interrupted():
                warning('Caught interrupt, shutting down')
                
            return 0
        
        def initializeIceConnection(self):
            """
            Establishes the two-way Ice connection and adds the authenticator to the
            configured servers
            """
            ice = self.communicator()
            
            if cfg.ice.secret:
                debug('Using shared ice secret')
                ice.getImplicitContext().put("secret", cfg.ice.secret)
            elif not cfg.glacier.enabled:
                warning('Consider using an ice secret to improve security')
                
            if cfg.glacier.enabled:
                #info('Connecting to Glacier2 server (%s:%d)', glacier_host, glacier_port)
                error('Glacier support not implemented yet')
                #TODO: Implement this
    
            info('Connecting to Ice server (%s:%d)', cfg.ice.host, cfg.ice.port)
            base = ice.stringToProxy('Meta:tcp -h %s -p %d' % (cfg.ice.host, cfg.ice.port))
            self.meta = Murmur.MetaPrx.uncheckedCast(base)
        
            adapter = ice.createObjectAdapterWithEndpoints('Callback.Client', 'tcp -h %s' % cfg.ice.host)
            adapter.activate()
            
            metacbprx = adapter.addWithUUID(metaCallback(self))
            self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)
            
            return self.attachCallbacks()
        
        def attachCallbacks(self):
            """
            Attaches all callbacks for meta and authenticators
            """
            
            # Ice.ConnectionRefusedException
            debug('Attaching callbacks')
            try:
                info('Attaching meta callback')
                self.meta.addCallback(self.metacb)
                        
            except (Murmur.InvalidSecretException, Ice.UnknownUserException, Ice.ConnectionRefusedException), e:
                if isinstance(e, Ice.ConnectionRefusedException):
                    error('Server refused connection')
                elif isinstance(e, Murmur.InvalidSecretException) or \
                     isinstance(e, Ice.UnknownUserException) and (e.unknown == 'Murmur::InvalidSecretException'):
                    error('Invalid ice secret')
                else:
                    # We do not actually want to handle this one, re-raise it
                    raise e
                
                self.connected = False
                return False

            self.connected = True
            return True
        
        def checkConnection(self):
            """
            Tries to retrieve the server uptime to determine wheter the server is
            still responsive or has restarted in the meantime
            """
            #debug('Watchdog run')
            try:
                uptime = self.meta.getUptime()
                if self.metaUptime > 0: 
                    # Check if the server didn't restart since we last checked, we assume
                    # since the last time we ran this check the watchdog interval +/- 5s
                    # have passed. This should be replaced by implementing a Keepalive in
                    # Murmur.
                    if not ((uptime - 5) <= (self.metaUptime + cfg.ice.watchdog) <= (uptime + 5)):
                        # Seems like the server restarted, re-attach the callbacks
                        self.attachCallbacks()
                        
                self.metaUptime = uptime
            except Ice.Exception, e:
                error('Connection to server lost, will try to reestablish callbacks in next watchdog run (%ds)', cfg.ice.watchdog)
                debug(str(e))
                self.attachCallbacks()

            # Renew the timer
            self.watchdog = Timer(cfg.ice.watchdog, self.checkConnection)
            self.watchdog.start()
            
        def isChildChannel(self, server, child_chid, parent_chid):
            channels = server.getChannels()
            
            current_channel = child_chid
            while current_channel != -1 and current_channel != parent_chid:
                current_channel = channels[current_channel].parent
            return current_channel == parent_chid
            
        def findChannel(self, server, channel_name):
            for channel in server.getChannels().itervalues():
                if channel.name == channel_name:
                    return channel
            return None
     
        def findChildChannel(self, channels, root_id, channel_name):
            for channel in channels.itervalues():
                if channel.parent == root_id and channel.name == channel_name:
                    return channel
            return None
            
        def linkChildren(self, server, channel_id):
            child_ids = []
            children = []
            for channel in server.getChannels().itervalues():
                if channel.parent == channel_id:
                    children.append(channel)
                    child_ids.append(channel.id)
                    
            for channel in children:
                channel.links = child_ids
                server.setChannelState(channel)
                
        def findSubtree(self, tree, channel_id):
            if tree.c.id == channel_id:
                return tree
                
            for child in tree.children: 
                result = self.findSubtree(child, channel_id)
                if result is not None:
                    return result
            return None
            
        def countTreeUsers(self, tree, tree_counts):
            user_count = len(tree.users)
            for child in tree.children:
                self.countTreeUsers(child, tree_counts)
                user_count += tree_counts[child.c.id]
            tree_counts[tree.c.id] = user_count
            
        def removeEmptyLeaves(self, server, tree):
            tree_counts = {}
            self.countTreeUsers(tree, tree_counts)
            
            for channel_id in tree_counts:
                if tree_counts[channel_id] == 0:
                    channels = server.getChannels()
                    if channel_id in channels:
                        server.removeChannel(channel_id)
                
        def removeEmptyChildren(self, server, channel_id):
            tree = server.getTree()
            tree = self.findSubtree(tree, channel_id)
            
            if tree is not None:
                self.removeEmptyLeaves(server, tree)
            
        def ensureChannelPathExists(self, server, root_id, channel_path):
            """
            @server: the server instance
            @channel_path: a list of channels which must form a path under the specified root
            
            returns the channel state of the end of the path.
            """
            channels = server.getChannels()
            current_channel = server.getChannelState(root_id)
            while len(channel_path):
                child_name = channel_path.pop(0)
                child_channel = self.findChildChannel(channels, current_channel.id, child_name)
                
                if child_channel is not None:
                    current_channel = child_channel
                else:
                    child_id = server.addChannel(child_name, current_channel.id)
                    current_channel = server.getChannelState(child_id)
            
            return current_channel
            
        def setTeam(self, uid, server_name, team_name):
            uid += cfg.user.id_offset
            
            debug("got setTeam({}, '{}', '{}')".format(uid, server_name, team_name))
            
            for server in self.meta.getBootedServers():
                autoteam_channel = self.findChannel(server, "autoteam")
                
                if autoteam_channel is not None:
                    debug("found autoteam channel: {}".format(autoteam_channel))
                
                    users = server.getUsers()
                    
                    for user in users.itervalues():
                        if user.userid == uid:
                            #print "found user:", user
                            
                            if self.isChildChannel(server, user.channel, autoteam_channel.id):
                                debug("User found in autoteam subtree.")
                                
                                server_channel = self.ensureChannelPathExists(server, autoteam_channel.id, [server_name])
                                team_channel = self.ensureChannelPathExists(server, server_channel.id, [team_name])
                                
                                team_channel.temporary = True
                                server.setChannelState(team_channel)
                                
                                self.linkChildren(server, server_channel.id)
                                
                                user.channel = team_channel.id
                                server.setState(user)
                                
                                self.removeEmptyChildren(server, autoteam_channel.id)
        
    def checkSecret(func):
        """
        Decorator that checks whether the server transmitted the right secret
        if a secret is supposed to be used.
        """
        if not cfg.ice.secret:
            return func
        
        def newfunc(*args, **kws):
            if 'current' in kws:
                current = kws["current"]
            else:
                current = args[-1]
            
            if not current or 'secret' not in current.ctx or current.ctx['secret'] != cfg.ice.secret:
                error('Server transmitted invalid secret. Possible injection attempt.')
                raise Murmur.InvalidSecretException()
            
            return func(*args, **kws)
        
        return newfunc

    def fortifyIceFu(retval = None, exceptions = (Ice.Exception,)):
        """
        Decorator that catches exceptions,logs them and returns a safe retval
        value. This helps preventing the authenticator getting stuck in
        critical code paths. Only exceptions that are instances of classes
        given in the exceptions list are not caught.
        
        The default is to catch all non-Ice exceptions.
        """
        def newdec(func):
            def newfunc(*args, **kws):
                try:
                    return func(*args, **kws)
                except Exception, e:
                    catch = True
                    for ex in exceptions:
                        if isinstance(e, ex):
                            catch = False
                            break

                    if catch:
                        critical('Unexpected exception caught')
                        exception(e)
                        return retval
                    raise

            return newfunc
        return newdec
                
    class metaCallback(Murmur.MetaCallback):
        def __init__(self, app):
            Murmur.MetaCallback.__init__(self)
            self.app = app

        @fortifyIceFu()
        @checkSecret
        def started(self, server, current = None):
            """
            This function is called when a virtual server is started
            and makes sure an authenticator gets attached if needed.
            """
            debug('Virtual server %d got started', server.id())

        @fortifyIceFu()
        @checkSecret
        def stopped(self, server, current = None):
            """
            This function is called when a virtual server is stopped
            """
            debug('Server shutdown stopped a virtual server')
            
    class mumbleTeamsListener(threading.Thread):
        def __init__(self, port, app, listenhost="localhost", maxconn=5):
            threading.Thread.__init__(self)
            self.running = False
            
            self.app = app
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((listenhost, port))
            self.socket.listen(maxconn)
            
            self.clients = {}
            
        def shutdown(self):
            self.running = False
            
        def run(self):
            self.running = True
            while self.running:
                
                rfds = [self.socket] + self.clients.keys()
                
                try:
                    rfds, wfds, efds = select.select(rfds, [], [], None)
                
                    for rfd in rfds:
                        if rfd == self.socket:
                            self.handle_connect()
                        else:
                            self.handle_client(rfd)
                            
                except select.error:
                    pass
                
        def handle_connect(self):
            (clientsocket, address) = self.socket.accept()
            self.clients[clientsocket] = ""
            
        def handle_client(self, clientsocket):
            data = clientsocket.recv(1024)
            if len(data) <= 0:
                del self.clients[clientsocket]
                return
            self.clients[clientsocket] += data
            
            next_nl_pos = self.clients[clientsocket].find("\n")
            while next_nl_pos != -1:
                datum, self.clients[clientsocket] = self.clients[clientsocket].split('\n', 1)
                next_nl_pos = self.clients[clientsocket].find("\n")
                self.handle_datum(datum)
        
        def handle_datum(self, datum):
            datum = datum.split()
            if len(datum) < 4:
                return
            msgtype, uid, server, team = datum
            if msgtype == "changeteam":
                self.app.setTeam(int(uid), server, team)
        
    class CustomLogger(Ice.Logger):
        """
        Logger implementation to pipe Ice log messages into
        out own log
        """
        
        def __init__(self):
            Ice.Logger.__init__(self)
            self._log = getLogger('Ice')
            
        def _print(self, message):
            self._log.info(message)
            
        def trace(self, category, message):
            self._log.debug('Trace %s: %s', category, message)
            
        def warning(self, message):
            self._log.warning(message)
            
        def error(self, message):
            self._log.error(message)

    #
    #--- Start of mumbleteams app
    #
    info('Starting mumble teams')
    initdata = Ice.InitializationData()
    initdata.properties = Ice.createProperties([], initdata.properties)
    for prop, val in cfg.iceraw:
        initdata.properties.setProperty(prop, val)
        
    initdata.properties.setProperty('Ice.ImplicitContext', 'Shared')
    initdata.logger = CustomLogger()
    
    app = mumbleteamsApp()
    setTeamListener = mumbleTeamsListener(cfg.listen.port, app)
    setTeamListener.start()
    state = app.main(sys.argv[:1], initData = initdata)
    setTeamListener.shutdown()
    info('Shutdown complete')

#
#--- Start of program
#
if __name__ == '__main__':
    # Parse commandline options
    parser = OptionParser()
    parser.add_option('-i', '--ini',
                      help = 'load configuration from INI', default = cfgfile)
    parser.add_option('-v', '--verbose', action='store_true', dest = 'verbose',
                      help = 'verbose output [default]', default = True)
    parser.add_option('-q', '--quiet', action='store_false', dest = 'verbose',
                      help = 'only error output')
    parser.add_option('-d', '--daemon', action='store_true', dest = 'force_daemon',
                      help = 'run as daemon', default = False)
    parser.add_option('-a', '--app', action='store_true', dest = 'force_app',
                      help = 'do not run as daemon', default = False)
    (option, args) = parser.parse_args()
    
    if option.force_daemon and option.force_app:
        parser.print_help()
        sys.exit(1)
        
    # Load configuration
    try:
        cfg = config(option.ini, default)
    except Exception, e:
        print>>sys.stderr, 'Fatal error, could not load config file from "%s"' % cfgfile
        sys.exit(1)
    
    # Initialize logger
    if cfg.log.file:
        try:
            logfile = open(cfg.log.file, 'a')
        except IOError, e:
            #print>>sys.stderr, str(e)
            print>>sys.stderr, 'Fatal error, could not open logfile "%s"' % cfg.log.file
            sys.exit(1)
    else:
        logfile = logging.sys.stderr
        
            
    if option.verbose:
        level = cfg.log.level
    else:
        level = logging.ERROR
    
    logging.basicConfig(level = level,
                        format='%(asctime)s %(levelname)s %(message)s',
                        stream = logfile)
        
    # As the default try to run as daemon. Silently degrade to running as a normal application if this fails
    # unless the user explicitly defined what he expected with the -a / -d parameter. 
    try:
        if option.force_app:
            raise ImportError # Pretend that we couldn't import the daemon lib
        import daemon
    except ImportError:
        if option.force_daemon:
            print>>sys.stderr, 'Fatal error, could not daemonize process due to missing "daemon" library, ' \
            'please install the missing dependency and restart the authenticator'
            sys.exit(1)
        do_main_program()
    else:
        context = daemon.DaemonContext(working_directory = sys.path[0],
                                       stderr = logfile)
        context.__enter__()
        try:
            do_main_program()
        finally:
            context.__exit__(None, None, None)
