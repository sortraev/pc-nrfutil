#
# Copyright (c) 2016 Nordic Semiconductor ASA
# Copyright (c) 2021 Andrzej Szombierski
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# Python standard library
import time
import wrapt
import queue
import struct
import logging
import binascii

from nordicsemi.dfu.dfu_transport   import DfuTransport, DfuEvent
from pc_ble_driver_py.exceptions    import NordicSemiException, IllegalStateException
import bluepy.btle as btle
logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

#from pc_ble_driver_py import config
#global nrf_sd_ble_api_ver
#nrf_sd_ble_api_ver = config.sd_api_ver_get()

class ValidationException(NordicSemiException):
    """"
    Exception used when validation failed
    """
    pass

class MyDelegate(btle.DefaultDelegate):

    # TODO: can we assume that handles are static for a given uuid and
    #       device? if so then these need not be passed here.
    def __init__(self, cp_handle, dp_handle):
        btle.DefaultDelegate.__init__(self)

        self.cp_handle = cp_handle
        self.dp_handle = dp_handle

        self.last_cp_notification = None
        self.last_dp_notification = None

    def handleNotification(self, cHandle, data):
        logger.info("Caught notification.\n"
                     f">> handle: {cHandle}\n>> data:   {data}")

        if cHandle == self.cp_handle:
            self.last_cp_notification = data
        elif cHandle == self.dp_handle:
            self.last_dp_notification = data


    def getLastCPNotification(self):
        tmp = self.last_cp_notification
        self.last_cp_notification = None
        logger.info(f"Got last CP notification: {tmp}"
                     if tmp else "No new CP notification")
        return tmp

class MyDfuDevice(btle.Peripheral):

    CP = '8ec90001-f315-4f60-9fb8-838830daea50'
    DP = '8ec90002-f315-4f60-9fb8-838830daea50'

    def __init__(self, address, addrType = btle.ADDR_TYPE_RANDOM):
        super().__init__(address, addrType)
        self.packet_size = 16

        # get characteristics and their respective handles; set up delegate
        # (ie. notification handler).
        self.CP_char = self.getCharacteristics(uuid = MyDfuDevice.CP)[0]
        self.DP_char = self.getCharacteristics(uuid = MyDfuDevice.DP)[0]
        logger.info("Got CP and DP characteristics.")

        self.CP_handle = self.CP_char.getHandle()
        self.DP_handle = self.DP_char.getHandle()

        res1 = self.writeCharacteristic(self.CP_handle, b"\x01\x00", withResponse = True)
        res2 = self.writeCharacteristic(self.DP_handle, b"\x01\x00", withResponse = True)
        logger.info("Subscribed to notifications for CP and DP handles with "
                     f"responses:\nres1: {res1}\nres2: {res2}")

        #  self.delegate = MyDelegate(self.CP_handle, self.DP_handle)
        self.setDelegate(MyDelegate(self.CP_handle, self.DP_handle))
        logger.info("Set up delegate.")


    def poll_cp_notification(self):
        MAX_RETRIES = 10
        for i in range(MAX_RETRIES):
            logger.info("Attempting to poll CP notification. "
                         f"{MAX_RETRIES - i - 1} attempts left.")

            if self.waitForNotifications(4): # TODO: how long timeout?
                tmp = 42#self.delegate.getLastCPNotification()
                logger.info(f"Polled CP notification: {tmp}")
                return tmp

        logger.info(f"Failed to get last CP notification!")
        return None


    def write_control_point(self, data):
        res = self.writeCharacteristic(self.CP_handle,
                                       bytes(data),
                                       withResponse = True)
        logger.info(f"Wrote control point: {data}, with response: {res}")

    def write_data_point(self, data):
        res = self.writeCharacteristic(self.DP_handle,
                                       bytes(data),
                                       withResponse = True)
        logger.info(f"Writing data point: {data}, with response: {res}")


class DfuTransportBleBluepy(DfuTransport):

    DEFAULT_TIMEOUT = 20
    RETRIES_NUMBER  = 3

    def __init__(self,
                 target_device_addr = None,
                 prn = 0):
        super().__init__()
        self.device             = None
        self.target_device_addr = target_device_addr
        self.prn                = prn

    def open(self):
        if self.device:
            raise IllegalStateException('DFU Adapter is already open')

        super().open()

        self.device = MyDfuDevice(self.target_device_addr)
        #  self.device.connect()
        #  self.device.setup()

        self.__set_prn()

    def close(self):
        # Get bonded status and BLE keyset from DfuAdapter
        if not self.device:
            raise IllegalStateException('DFU Adapter is already closed')
        super().close()
        self.device.cleanup()
        self.device = None

    def send_init_packet(self, init_packet):
        def try_to_recover():
            if response['offset'] == 0 or response['offset'] > len(init_packet):
                # There is no init packet or present init packet is too long.
                return False

            expected_crc = (binascii.crc32(init_packet[:response['offset']]) & 0xFFFFFFFF)

            if expected_crc != response['crc']:
                # Present init packet is invalid.
                return False

            if len(init_packet) > response['offset']:
                # Send missing part.
                try:
                    self.__stream_data(data     = init_packet[response['offset']:],
                                       crc      = expected_crc,
                                       offset   = response['offset'])
                except ValidationException:
                    return False

            self.__execute()
            return True

        response = self.__select_command()
        assert len(init_packet) <= response['max_size'], 'Init command is too long'

        if try_to_recover():
            return

        for r in range(DfuTransportBleBluepy.RETRIES_NUMBER):
            try:
                self.__create_command(len(init_packet))
                self.__stream_data(data=init_packet)
                self.__execute()
            except ValidationException:
                pass
            break
        else:
            raise NordicSemiException("Failed to send init packet")

    def send_firmware(self, firmware):
        def try_to_recover():
            if response['offset'] == 0:
                # Nothing to recover
                return

            expected_crc = binascii.crc32(firmware[:response['offset']]) & 0xFFFFFFFF
            remainder    = response['offset'] % response['max_size']

            if expected_crc != response['crc']:
                # Invalid CRC. Remove corrupted data.
                response['offset'] -= remainder if remainder != 0 else response['max_size']
                response['crc']     = binascii.crc32(firmware[:response['offset']]) & 0xFFFFFFFF
                return

            if (remainder != 0) and (response['offset'] != len(firmware)):
                # Send rest of the page.
                try:
                    to_send             = firmware[response['offset'] : response['offset'] + response['max_size'] - remainder]
                    response['crc']     = self.__stream_data(data   = to_send,
                                                             crc    = response['crc'],
                                                             offset = response['offset'])
                    response['offset'] += len(to_send)
                except ValidationException:
                    # Remove corrupted data.
                    response['offset'] -= remainder
                    response['crc']     = binascii.crc32(firmware[:response['offset']]) & 0xFFFFFFFF
                    return

            self.__execute()
            self._send_event(event_type=DfuEvent.PROGRESS_EVENT, progress=response['offset'])

        response = self.__select_data()
        try_to_recover()

        for i in range(response['offset'], len(firmware), response['max_size']):
            data = firmware[i:i+response['max_size']]
            for r in range(DfuTransportBleBluepy.RETRIES_NUMBER):
                try:
                    self.__create_data(len(data))
                    response['crc'] = self.__stream_data(data=data, crc=response['crc'], offset=i)
                    self.__execute()
                except ValidationException:
                    pass
                break
            else:
                raise NordicSemiException("Failed to send firmware")
            self._send_event(event_type=DfuEvent.PROGRESS_EVENT, progress=len(data))

    def __set_prn(self):
        logger.debug("BLE: Set Packet Receipt Notification {}".format(self.prn))
        self.device.write_control_point([DfuTransportBleBluepy.OP_CODE['SetPRN']] + list(struct.pack('<H', self.prn)))
        self.__get_response(DfuTransportBleBluepy.OP_CODE['SetPRN'])

    def __create_command(self, size):
        self.__create_object(0x01, size)

    def __create_data(self, size):
        self.__create_object(0x02, size)

    def __create_object(self, object_type, size):
        self.device.write_control_point([DfuTransportBleBluepy.OP_CODE['CreateObject'], object_type]\
                                            + list(struct.pack('<L', size)))
        self.__get_response(DfuTransportBleBluepy.OP_CODE['CreateObject'])

    def __calculate_checksum(self):
        self.device.write_control_point([DfuTransportBleBluepy.OP_CODE['CalcChecSum']])
        response = self.__get_response(DfuTransportBleBluepy.OP_CODE['CalcChecSum'])

        (offset, crc) = struct.unpack('<II', bytearray(response))
        return {'offset': offset, 'crc': crc}

    def __execute(self):
        self.device.write_control_point([DfuTransportBleBluepy.OP_CODE['Execute']])
        self.__get_response(DfuTransportBleBluepy.OP_CODE['Execute'])

    def __select_command(self):
        return self.__select_object(0x01)

    def __select_data(self):
        return self.__select_object(0x02)

    def __select_object(self, object_type):
        logger.debug("BLE: Selecting Object: type:{}".format(object_type))
        self.device.write_control_point([DfuTransportBleBluepy.OP_CODE['ReadObject'], object_type])
        response = self.__get_response(DfuTransportBleBluepy.OP_CODE['ReadObject'])

        (max_size, offset, crc)= struct.unpack('<III', bytearray(response))
        logger.debug("BLE: Object selected: max_size:{} offset:{} crc:{}".format(max_size, offset, crc))
        return {'max_size': max_size, 'offset': offset, 'crc': crc}

    def __get_checksum_response(self):
        response = self.__get_response(DfuTransportBleBluepy.OP_CODE['CalcChecSum'])

        (offset, crc) = struct.unpack('<II', bytearray(response))
        return {'offset': offset, 'crc': crc}

    def __stream_data(self, data, crc=0, offset=0):
        logger.debug("BLE: Streaming Data: len:{0} offset:{1} crc:0x{2:08X}".format(len(data), offset, crc))
        def validate_crc():
            if (crc != response['crc']):
                raise ValidationException('Failed CRC validation.\n'\
                                + 'Expected: {} Received: {}.'.format(crc, response['crc']))
            if (offset != response['offset']):
                raise ValidationException('Failed offset validation.\n'\
                                + 'Expected: {} Received: {}.'.format(offset, response['offset']))

        current_pnr = 0
        for i in range(0, len(data), self.device.packet_size):
            to_transmit     = data[i:i + self.device.packet_size]
            self.device.write_data_point(list(to_transmit))
            crc     = binascii.crc32(to_transmit, crc) & 0xFFFFFFFF
            offset += len(to_transmit)
            current_pnr    += 1
            if self.prn == current_pnr:
                current_pnr = 0
                response    = self.__get_checksum_response()
                validate_crc()

        response = self.__calculate_checksum()
        validate_crc()

        return crc

    def __get_response(self, operation):
        def get_dict_key(dictionary, value):
            return next((key for key, val in list(dictionary.items()) if val == value), None)

        resp = self.device.poll_cp_notification()

        if resp[0] != DfuTransportBleBluepy.OP_CODE['Response']:
            raise NordicSemiException('No Response: 0x{:02X}'.format(resp[0]))

        if resp[1] != operation:
            raise NordicSemiException('Unexpected Executed OP_CODE.\n' \
                                    + 'Expected: 0x{:02X} Received: 0x{:02X}'.format(operation, resp[1]))

        if resp[2] == DfuTransport.RES_CODE['Success']:
            return resp[3:]

        elif resp[2] == DfuTransport.RES_CODE['ExtendedError']:
            try:
                data = DfuTransport.EXT_ERROR_CODE[resp[3]]
            except IndexError:
                data = "Unsupported extended error type {}".format(resp[3])
            raise NordicSemiException('Extended Error 0x{:02X}: {}'.format(resp[3], data))
        else:
            raise NordicSemiException('Response Code {}'.format(get_dict_key(DfuTransport.RES_CODE, resp[2])))
