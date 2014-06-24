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

from neutron.common import log
from neutron.services.loadbalancer.drivers.brocade.device_driver import (
    brocade_adx_driver_impl as driver_impl
)
from neutron.services.loadbalancer.drivers.brocade.device_driver import (
    brocade_adx_service as adx_service
)


class BrocadeAdxDeviceDriver():
    def __init__(self, plugin):
        self.plugin = plugin

    @log.log
    def add_device(self, device):
        adx_service.ClientCache.add_adx_service_client(device)

    @log.log
    def delete_device(self, device):
        adx_service.ClientCache.delete_adx_service_client(device)

    @log.log
    def update_device(self, device):
        adx_service.ClientCache.delete_adx_service_client(device)
        adx_service.ClientCache.add_adx_service_client(device)

    @log.log
    def create_vip(self, device, vip):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_vip(vip)

    @log.log
    def update_vip(self, device, new_vip, old_vip):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_vip(new_vip, old_vip)

    @log.log
    def delete_vip(self, device, vip):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_vip(vip)

    @log.log
    def create_pool(self, device, pool):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_pool(pool)

    @log.log
    def update_pool(self, device, new_pool, old_pool):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_pool(new_pool, old_pool)

    @log.log
    def delete_pool(self, device, pool):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_pool(pool)

    @log.log
    def create_member(self, device, member):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_member(member)

    @log.log
    def update_member(self, device, new_member, old_member):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_member(new_member, old_member)

    @log.log
    def delete_member(self, device, member):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_member(member)

    @log.log
    def create_health_monitor(self, device, health_monitor, pool_id):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_health_monitor(health_monitor, pool_id)

    @log.log
    def delete_health_monitor(self, device, health_monitor, pool_id):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_health_monitor(health_monitor, pool_id)

    @log.log
    def update_health_monitor(self, device, new_hm, old_hm, pool_id):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_health_monitor(new_hm, old_hm, pool_id)

    @log.log
    def get_pool_stats(self, device, pool_id):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        return impl.get_pool_stats(pool_id)
