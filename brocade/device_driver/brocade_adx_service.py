# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Brocade Communications Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Pattabi Ayyasami, Brocade Communications Systems,Inc.
#
import base64
import StringIO
import time

import httplib2
from suds import client as suds_client
from suds.sax import element as suds_element
from suds import transport as suds_transport

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class ClientCache:

    _ADX_SERVICE_CLIENTS = dict()

    @classmethod
    def add_adx_service_client(cls, device):
        LOG.debug(_('add_adx_service_client to dictionary'))
        ip = device['ip']
        user = device['user']
        password = device['password']

        if ip not in cls._ADX_SERVICE_CLIENTS:
            adxSlbService = AdxService(ip, user, password)
            slb_service_client = adxSlbService.createSlbServiceClient()

            adxSysService = AdxService(ip, user, password)
            sys_service_client = adxSysService.createSysServiceClient()

            cls._ADX_SERVICE_CLIENTS[ip] = [slb_service_client,
                                            sys_service_client]

    @classmethod
    def delete_adx_service_client(cls, device):
        LOG.debug(_('delete_adx_service_client from dictionary'))
        ip = device['ip']
        if ip in cls._ADX_SERVICE_CLIENTS:
            del cls._ADX_SERVICE_CLIENTS[ip]

    @classmethod
    def get_adx_service_client(cls, device):
        LOG.debug(_('get_adx_service_client'))
        ip = device['ip']

        if ip not in cls._ADX_SERVICE_CLIENTS:
            LOG.debug(_('Adx Service Client not yet initialized ...'))
            cls.add_adx_service_client(device)

        return cls._ADX_SERVICE_CLIENTS[ip]


class Httplib2Response:
    pass


class Httplib2Transport(suds_transport.Transport):
    def __init__(self, **kwargs):
        self.username = kwargs["username"]
        self.password = kwargs["password"]
        suds_transport.Transport.__init__(self)
        self.http = httplib2.Http()

    def credentials(self):
        return (self.username, self.password)

    def addCredentials(self, request):
        credentials = self.credentials()
        if not (None in credentials):
            encoded = base64.encodestring(':'.join(credentials))
            basic = 'Basic %s' % encoded[:-1]
            request.headers['Authorization'] = basic

    def open(self, request):
        response = Httplib2Response()
        response.headers, response.message = (self.http.request
                                              (request.url,
                                               "GET",
                                               body=request.message,
                                               headers=request.headers))
        return StringIO.StringIO(response.message)

    def send(self, request):
        self.addCredentials(request)
        url = request.url
        message = request.message
        headers = request.headers
        response = Httplib2Response()
        response.headers, response.message = (self.http.request
                                              (url,
                                               "POST",
                                               body=message,
                                               headers=headers))
        return response


class AdxService:
    "ADX Service Initialization Class"
    ns0 = ('ns0', 'http://schemas.xmlsoap.org/soap/envelope123/')

    def __init__(self, adxIpAddress, userName, password):
        self.adxIpAddress = adxIpAddress
        self.userName = userName
        self.password = password
        self.wsdl_base = "http://" + adxIpAddress + "/wsdl/"
        self.sys_service_wsdl = "sys_service.wsdl"
        self.slb_service_wsdl = "slb_service.wsdl"
        self.location = "http://" + adxIpAddress + "/WS/SYS"
        self.transport = Httplib2Transport(username=self.userName,
                                           password=self.password)

    def createSlbServiceClient(self):
        def soapHeader():
            requestHeader = suds_element.Element('RequestHeader',
                                                 ns=AdxService.ns0)
            context = suds_element.Element('context').setText('default')
            requestHeader.append(context)
            return requestHeader

        url = self.wsdl_base + self.slb_service_wsdl
        location = "http://" + self.adxIpAddress + "/WS/SLB"
        start = time.time()
        client = suds_client.Client(url, transport=self.transport,
                                    service='AdcSlb',
                                    location=location, timeout=300)
        elapsed = (time.time() - start)
        LOG.debug(_('Time to initialize SLB Service Client: %s'), elapsed)

        requestHeader = soapHeader()
        client.set_options(soapheaders=requestHeader)
        return client

    def createSysServiceClient(self):
        def soapHeader():
            requestHeader = suds_element.Element('RequestHeader',
                                                 ns=AdxService.ns0)
            context = suds_element.Element('context').setText('default')
            requestHeader.append(context)
            return requestHeader

        url = self.wsdl_base + self.sys_service_wsdl
        location = "http://" + self.adxIpAddress + "/WS/SYS"
        start = time.time()
        client = suds_client.Client(url, transport=self.transport,
                                    service='AdcSysInfo',
                                    location=location, timeout=300)
        elapsed = (time.time() - start)
        LOG.debug(_('Time to initialize SYS Service Client: %s'), elapsed)

        requestHeader = soapHeader()
        client.set_options(soapheaders=requestHeader)
        return client
