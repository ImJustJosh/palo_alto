"""Support for Palo Alto Firewalls."""
import logging
import re

from pexpect import pxssh
import voluptuous as vol

from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA as PARENT_PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = vol.All(
    PARENT_PLATFORM_SCHEMA.extend(
        {
            vol.Required(CONF_HOST): cv.string,
            vol.Required(CONF_USERNAME): cv.string,
            vol.Optional(CONF_PASSWORD, default=""): cv.string,
            vol.Optional(CONF_PORT): cv.port,
        }
    )
)


def get_scanner(hass, config):
    """Validate the configuration and return a Palo Alto scanner."""
    scanner = Palo_AltoDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


class Palo_AltoDeviceScanner(DeviceScanner):
    """This class queries a firewall running Palo Alto firmware."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.port = config.get(CONF_PORT)
        self.password = config[CONF_PASSWORD]

        self.last_results = {}

        self.success_init = self._update_info()
        _LOGGER.info("Initialized Palo_Alto scanner")

    def get_device_name(self, device):
        """Get the firmware doesn't save the name of the device."""
        return None

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        return self.last_results

    def _update_info(self):
        """
        Ensure the information from the Palo Alto firewall is up to date.

        Returns boolean if scanning successful.
        """
        string_result = self._get_arp_data()

        if string_result:
            self.last_results = []
            last_results = []

            lines_result = string_result.splitlines()

            # Remove the first two lines, as they contains the arp command
            # and the arp table titles e.g.
            # show ip arp
            # interface | ip address | hw address | port | status | ttl
            lines_result = lines_result[9:]

            for line in lines_result:
                parts = line.split()
                if len(parts) != 7:
                    continue

                # [interface | ip address | hw address | port | status | ttl]
                age = parts[6]
                hw_addr = parts[2]

                if age != "-":
                    mac = hw_addr
                    age = int(age)
                    if age < 1:
                        last_results.append(mac)

            self.last_results = last_results
            return True

        return False

    def _get_arp_data(self):
        """Open connection to the firewall and get arp entries."""

        try:
            palo_alto_ssh = pxssh.pxssh()
            palo_alto_ssh.login(
                self.host,
                self.username,
                self.password,
                port=self.port,
                sync_multiplier=5,
                auto_prompt_reset=False,
            )

            # Find the hostname
            initial_line = palo_alto_ssh.before.decode("utf-8").splitlines()
            firewall_hostname = initial_line[len(initial_line) - 1]
            firewall_hostname += ">"
            # Set the discovered hostname as prompt
            regex_expression = f"(?i)^{firewall_hostname}".encode()
            palo_alto_ssh.PROMPT = re.compile(regex_expression, re.MULTILINE)
            # Allow full arp table to print at once
            palo_alto_ssh.sendline("set cli pager off")
            palo_alto_ssh.prompt(1)

            palo_alto_ssh.sendline("show arp all")
            palo_alto_ssh.prompt(1)

            devices_result = palo_alto_ssh.before

            return devices_result.decode("utf-8")
        except pxssh.ExceptionPxssh as px_e:
            _LOGGER.error("Failed to login via pxssh: %s", px_e)
        return None
