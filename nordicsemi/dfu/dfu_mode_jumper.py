import dfu.dfu_transport_ble_native as transport
import dfu.dfu as dfu

from bluepy.btle import *
import logging
LOG_LEVEL  = logging.INFO
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(message)s"
logging.basicConfig(level = LOG_LEVEL, format = LOG_FORMAT)
#  logging = logging.getlogging(__name__)
#  logging.setLevel(logging.INFO)

def readable_char(c):
    s = "".join("{:x}".format(b) for b in c.uuid.binVal)
    return f"{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:]}"

class DfuModeJumper(Peripheral):
    BUTTONLESS_UUID = "8ec90003-f315-4f60-9fb8-838830daea50"

    class DummyDelegate(DefaultDelegate):
        # TODO: necessary..? don't think so, but keep for now.
        def __init__(self):
            DefaultDelegate.__init__(self)
        def handleNotification(self, _cHandle, _data):
            pass


    def __init__(self, addr):
        self.addr = addr
        self.p = Peripheral(self.addr, addrType = ADDR_TYPE_RANDOM)
        logging.info("Peripheral open.")

        try:
            self.p.setDelegate(DfuModeJumper.DummyDelegate())
            logging.info("Set dummy delegate.")

            self.buttonless_char        = self.p.getCharacteristics(uuid = DfuModeJumper.BUTTONLESS_UUID)[0]
            self.buttonless_char_handle = self.buttonless_char.getHandle()
            logging.info("Got buttonless characteristic and handle.")

            cccd_handle = self.buttonless_char_handle + 1
            res = self.p.writeCharacteristic(cccd_handle, b"\x02\x00", withResponse = True)
            logging.info("Subscribed to indications for buttonless characteristic "
                         f"with response: {res}.")

        except Exception as e:
            self.p.disconnect()
            raise e

    def jump_to_dfu_mode(self):
        try:
            res = self.p.writeCharacteristic(self.buttonless_char_handle,
                                             b"\x01",
                                             withResponse = True)
            logging.info("Successfully wrote to buttonless characteristic with"
                         f" response: {res}")

        except Exception as e:
            self.p.disconnect()
            raise e

        #  time.sleep(4) # TODO: do we need to enforce a sleep here? if so, is
                      #       there an official recommendation on how long?
        #  return self.__is_properly_disconnected()

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
            logging.info(f"Unexpected exception during disconnection check: {e}")
            return False

    def intoDfuTransportBleNative(self):
        device_addr_int = int(self.addr.replace(":", ""), 16)
        tmp             = "{:x}".format(device_addr_int + 1)
        bootloader_addr = ":".join(tmp[i:i + 2] for i in range(12)[::2])
        return transport.DfuTransportBleNative(bootloader_addr)



#  import time
#  time.sleep(4)
#  jumper.jump_to_dfu_mode()
#  time.sleep(4)
#  my_dfu.dfu_send_images()


def run():
    TEST_MAC = "de:92:6f:64:91:d9"
    jumper = DfuModeJumper(TEST_MAC)
    my_transport = jumper.intoDfuTransportBleNative()

    ZIP_FILE_PATH = "/home/sortraev/move/foodop/ota_dfu/test_app_packages/v2.0.4-dfu_package.zip"
    my_dfu = dfu.Dfu(ZIP_FILE_PATH, my_transport, 0)
    return jumper, my_dfu
