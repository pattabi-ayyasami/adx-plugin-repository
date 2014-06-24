# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Brocade Communications Systems, Inc.
# All Rights Reserved.
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
# @author: Pattabi Ayyasami, Brocade Communication Systems, Inc.
#
import json

from neutron.common import exceptions as q_exc
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class NoValidDevice(q_exc.NotFound):
    message = _("No valid device found")


class NoValidDeviceFile(q_exc.NotFound):
    message = _("Device Inventory File %(name)s either not found or invalid")


class DeviceInventory(object):
    def __init__(self, device_driver, devices_file_name):
        self.device_driver = device_driver
        self.devices_file_name = devices_file_name
        self._ADX_DEVICES = dict()

    def _is_device_updated(self, device):
        ip = device['ip']
        user = device['user']
        password = device['password']
        device_in_cache = self._ADX_DEVICES[ip]
        if (user != device_in_cache['user'] or
            password != device_in_cache['password']):
            return True
        return False

    def load_devices(self):
        if not self.devices_file_name:
            LOG.error(_('Device Inventory File: %s could not be found'),
                      self.devices_file_name)
            raise NoValidDeviceFile(name=self.devices_file_name)

        try:
            with open(self.devices_file_name) as data_file:
                data = json.load(data_file)
        except IOError:
            LOG.error(_('Device Inventory File: %s could not be found'),
                      self.devices_file_name)
            raise NoValidDeviceFile(name=self.devices_file_name)
        except Exception:
            LOG.error(_('Error loading file: %s'), self.devices_file_name)
            raise NoValidDeviceFile(name=self.devices_file_name)

        for device in data:
            ip = device['ip']
            if ip in self._ADX_DEVICES:
                if self._is_device_updated(device):
                    self._ADX_DEVICES[ip] = device
                    # Update Client Cache
                    self.device_driver.update_device(device)
            else:
                self._ADX_DEVICES[ip] = device
                self.device_driver.add_device(device)

    def get_devices(self):
        LOG.debug(_('Get devices'))
        return self._ADX_DEVICES.values()
