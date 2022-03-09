import dfu_mode_jumper as dfu_mode_jumper
import dfu


def run():
    # TEST_MAC = "de:92:6f:64:91:d9"
    TEST_MAC = "cb:bb:2e:e8:45:8b"
    ZIP_FILE_PATH = "/home/pi/v2.0.5-dfu_package.zip"

    jumper = dfu_mode_jumper.DfuModeJumper.from_addr(TEST_MAC)
    jumper = dfu_mode_jumper.DfuModeJumper(TEST_MAC)
    my_transport = jumper.intoDfuTransportBleBluepy()

    my_dfu = dfu.Dfu(ZIP_FILE_PATH, my_transport, 0)
    return jumper, my_dfu

if __name__ == "__main__":
    jumper, my_dfu = run()
