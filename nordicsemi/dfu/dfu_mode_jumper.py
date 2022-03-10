import nordicsemi.dfu.dfu_transport_ble_native as dfu_transport_ble_native
import nordicsemi.dfu.dfu_transport_ble_bluepy as dfu_transport_ble_bluepy
import nordicsemi.dfu.dfu as dfu

from bluepy.btle import *
from bluepy.btle import Peripheral, ADDR_TYPE_RANDOM
import logging
LOG_LEVEL  = logging.INFO
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(message)s"
logging.basicConfig(level = LOG_LEVEL, format = LOG_FORMAT)


class DfuModeJumper():
    BUTTONLESS_UUID = "8ec90003-f315-4f60-9fb8-838830daea50"


    def from_addr(addr):
        p = Peripheral(addr, addrType = ADDR_TYPE_RANDOM)
        logging.info("New peripheral opened.")
        return DfuModeJumper(p)

    def __init__(self, p):
        if not isinstance(p, Peripheral):
            raise ValueError("DfuModeJumper.__init__(): expected Peripheral, but got "
                             f"{type(p).__name__}.")
        self.p = p

        self.buttonless_char        = self.p.getCharacteristics(uuid = DfuModeJumper.BUTTONLESS_UUID)[0]
        self.buttonless_char_handle = self.buttonless_char.getHandle()
        logging.info("Got buttonless characteristic and handle.")

        cccd_handle = self.buttonless_char_handle + 1
        res = self.p.writeCharacteristic(cccd_handle, b"\x02\x00", withResponse = True)
        logging.info("Subscribed to indications for buttonless characteristic "
                     f"with response: {res}.")

    def jump_to_dfu_mode(self):
        res = self.p.writeCharacteristic(self.buttonless_char_handle,
                                         b"\x01",
                                         withResponse = True)
        logging.info("Successfully wrote to buttonless characteristic with"
                     f" response: {res}")
        time.sleep(4) # TODO: do we need to enforce a sleep here? if so, is
                      #       there an official recommendation on how long?

        #  return self.is_properly_disconnected()

    def is_properly_disconnected(self):
        """
        since we need to *assert* disconnection after jumping to DFU mode, and
        not just assume it, the definition of "is disconnected" here is not
        simply the negation of "is connected".
        """
        try:
            state = self.p.getState()
            if state == "disc":
                return True

            msg = ("Got a valid BTLE state after jumping to DFU mode, but"
                   f" got '{state}' where 'disc' was expected.")
            logging.info(msg)
            #  raise Exception(msg)
            return False

        except BTLEDisconnectError:
            return True

        except BTLEInternalError as e:
            logging.info(f"BTLEInternalError during disconnection check: {e}")
            e_msg = str(e).casefold()
            return "helper exited" in e_msg or "helper not started" in e_msg

        except Exception as e:
            logging.info(f"Unexpected exception during disconnection check: {type(e).__name__}: {e}")
            return False

    def get_bootloader_addr(self):
        # given a mac address string; increment the address and construct new 
        # mac address string with colon separated bytes.
        addr_out = int(self.p.addr.replace(":", ""), 16) + 1
        tmp = "{:x}".format(addr_out)
        tmp = (12 - len(tmp)) * "0" + tmp # pad with leading zeroes if necessary.
        return ":".join(tmp[i:i + 2] for i in range(12)[::2]) # insert colons.
        

    def intoDfuTransportBleNative(self):
        return dfu_transport_ble_native.DfuTransportBleNative(self.get_bootloader_addr())

    def intoDfuTransportBleBluepy(self):
        return dfu_transport_ble_native.DfuTransportBleBluepy(self.get_bootloader_addr())
