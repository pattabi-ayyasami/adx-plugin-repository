# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Brocade Communication Systems,Inc.
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

from oslo.config import cfg

from neutron.common import log
from neutron.db.loadbalancer import loadbalancer_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers import abstract_driver
from neutron.services.loadbalancer.drivers.brocade.device_driver import (
    brocade_adx_driver as device_driver
)
from neutron.services.loadbalancer.drivers.brocade.device_inventory import (
    device_inventory
)

LOG = logging.getLogger(__name__)

brocade_plugin_driver_opts = [
    cfg.StrOpt('devices_file_name',
               default='/etc/neutron/services/loadbalancer/'
                       'brocade/devices.json',
               help=_('file containing the brocade load balancer devices'))]
cfg.CONF.register_opts(brocade_plugin_driver_opts, "brocade")


class LoadBalancerPluginDriver(abstract_driver.LoadBalancerAbstractDriver):

    """Brocade LBAAS Plugin Driver."""

    def __init__(self, plugin):
        LOG.debug(_('Initializing Brocade Load Balancer Plugin Driver'))
        self.plugin = plugin
        self.db = loadbalancer_db.LoadBalancerPluginDb()
        self.devices_file = cfg.CONF.brocade.devices_file_name
        self.device_driver = device_driver.BrocadeAdxDeviceDriver(plugin)
        self.device_inventory_manager = (device_inventory
                                         .DeviceInventory(self.device_driver,
                                                          self.devices_file))

    def _get_device(self, context, subnet_id):
        devices = self.device_inventory_manager.get_devices()
        if len(devices) == 0:
            raise device_inventory.NoValidDevice()

        # filter by subnet_id
        filtered = [device for device in devices
                   if subnet_id or 'ALL' in device['subnet_id'] ]

        if not filtered:
            LOG.error(_('No device was found for subnet: %s'), subnet_id)
            raise device_inventory.NoValidDevice()

        device = filtered[0]
        LOG.debug(_('Found device %(device)s for subnet: %(subnet_id)'),
                  device, subnet_id)
        return device

    def _fetch_device(self, context, pool_id):
        pool = self.db.get_pool(context, pool_id)
        subnet_id = pool['subnet_id']
        self.device_inventory_manager.load_devices()
        device = self._get_device(context, subnet_id)
        return device

    def _is_update_allowed(self, obj):
        return obj['status'] in [constants.ACTIVE]

    @log.log
    def create_vip(self, context, vip):
        try:
            device = self._fetch_device(context, vip['pool_id'])
            # call the device driver api
            self.device_driver.create_vip(device, vip)
            self.db.update_status(context,
                                  loadbalancer_db.Vip,
                                  vip["id"],
                                  constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in create_vip in device driver : %s"), e)
            self.db.update_status(context,
                                  loadbalancer_db.Vip,
                                  vip["id"],
                                  constants.ERROR,
                                  e.msg)

    @log.log
    def update_vip(self, context, old_vip, new_vip):
        try:
            device = self._fetch_device(context, new_vip['pool_id'])
            # call the device driver api
            self.device_driver.update_vip(device, new_vip, old_vip)
            self.db.update_status(context,
                                  loadbalancer_db.Vip,
                                  new_vip["id"],
                                  constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in update_vip in device driver : %s"), e)
            self.db.update_status(context,
                                  loadbalancer_db.Vip,
                                  new_vip["id"],
                                  constants.ERROR,
                                  e.msg)

    @log.log
    def delete_vip(self, context, vip):
        try:
            device = self._fetch_device(context, vip['pool_id'])
            # call the device driver api
            self.device_driver.delete_vip(device, vip)
        except Exception as e:
            LOG.error(_("Exception in delete_vip in device driver : %s"), e)

        # Delete VIP from DB any case
        self.plugin._delete_db_vip(context, vip["id"])

    @log.log
    def create_pool(self, context, pool):
        try:
            device = self._fetch_device(context, pool['id'])
            # call the device driver api
            self.device_driver.create_pool(device, pool)
            self.db.update_status(context, loadbalancer_db.Pool, pool["id"],
                                  constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in create_pool in device driver : %s"), e)
            self.db.update_status(context, loadbalancer_db.Pool, pool["id"],
                                  constants.ERROR, e.msg)

    @log.log
    def update_pool(self, context, old_pool, new_pool):
        try:
            device = self._fetch_device(context, new_pool['id'])
            # call the device driver api
            self.device_driver.update_pool(device, new_pool, old_pool)
            self.db.update_status(context,
                                  loadbalancer_db.Pool,
                                  new_pool["id"],
                                  constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in update in device driver : %s"), e)
            self.db.update_status(context,
                                  loadbalancer_db.Pool,
                                  new_pool["id"],
                                  constants.ERROR, e.msg)

    @log.log
    def delete_pool(self, context, pool):
        try:
            device = self._fetch_device(context, pool['id'])
            # call the device driver api
            self.device_driver.delete_pool(device, pool)
        except Exception as e:
            LOG.error(_("Exception in delete_pool in device driver : %s"), e)

        # Delete Pool from DB any case
        self.plugin._delete_db_pool(context, pool['id'])

    @log.log
    def stats(self, context, pool_id):
        device = self._fetch_device(context, pool_id)
        # call the device driver api
        self.device_driver.get_pool_stats(device, pool_id)

    @log.log
    def create_member(self, context, member):
        try:
            device = self._fetch_device(context, member['pool_id'])
            # call the device driver api
            self.device_driver.create_member(device, member)
            self.db.update_status(context,
                                  loadbalancer_db.Member,
                                  member["id"],
                                  constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in create_member in device driver : %s"), e)
            self.db.update_status(context,
                                  loadbalancer_db.Member,
                                  member["id"],
                                  constants.ERROR,
                                  e.msg)

    @log.log
    def update_member(self, context, old_member, new_member):
        try:
            device = self._fetch_device(context, new_member['pool_id'])
            # call the device driver api
            self.device_driver.update_member(device, new_member, old_member)
            self.db.update_status(context,
                                  loadbalancer_db.Member,
                                  new_member["id"],
                                  constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in update_member in device driver : %s"), e)
            self.db.update_status(context,
                                  loadbalancer_db.Member,
                                  new_member["id"],
                                  constants.ERROR,
                                  e.msg)

    @log.log
    def delete_member(self, context, member):
        try:
            device = self._fetch_device(context, member['pool_id'])
            # call the device driver api
            self.device_driver.delete_member(device, member)
        except Exception as e:
            LOG.error(_("Exception in delete_member in device driver : %s"), e)

        # Delete Member from DB any case
        self.plugin._delete_db_member(context, member["id"])

    @log.log
    def update_pool_health_monitor(self, context, old_health_monitor,
                              new_health_monitor,
                              pool_id):
        try:
            device = self._fetch_device(context, pool_id)
            # call the device driver api
            self.device_driver.update_health_monitor(device,
                                                     new_health_monitor,
                                                     old_health_monitor,
                                                     pool_id)
            self.db.update_pool_health_monitor(context,
                                               new_health_monitor['id'],
                                               pool_id,
                                               constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in update_health_monitor "
                        "in device driver : %s"), e)
            self.db.update_pool_health_monitor(context,
                                               new_health_monitor['id'],
                                               pool_id,
                                               constants.ERROR,
                                               e.msg)

    @log.log
    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        try:
            device = self._fetch_device(context, pool_id)
            # call the device driver api
            self.device_driver.create_health_monitor(device,
                                                     health_monitor,
                                                     pool_id)
            self.db.update_pool_health_monitor(context,
                                               health_monitor['id'],
                                               pool_id,
                                               constants.ACTIVE)
        except Exception as e:
            LOG.error(_("Exception in create_health_monitor "
                        "in device driver : %s"), e)
            self.db.update_pool_health_monitor(context,
                                               health_monitor['id'],
                                               pool_id,
                                               constants.ERROR,
                                               e.msg)

    @log.log
    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        try:
            device = self._fetch_device(context, pool_id)
            # call the device driver api
            self.device_driver.delete_health_monitor(device,
                                                     health_monitor,
                                                     pool_id)
        except Exception as e:
            LOG.error(_("Exception in delete_health_monitor "
                        "in device driver : %s"), e)

        self.plugin._delete_db_pool_health_monitor(context,
                                                   health_monitor["id"],
                                                   pool_id)
