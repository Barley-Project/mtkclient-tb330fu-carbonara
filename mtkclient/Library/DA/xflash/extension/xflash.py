import hashlib
import hmac
import os
import sys
import time
from struct import unpack, pack

from mtkclient.config.payloads import PathConfig
from mtkclient.config.brom_config import Efuse
from mtkclient.Library.error import ErrorHandler, ErrorCodes_XFlash
from mtkclient.Library.Hardware.hwcrypto import CryptoSetup, HwCrypto
from mtkclient.Library.utils import LogBase, Progress, logsetup, find_binary
from mtkclient.Library.Hardware.seccfg import SecCfgV3, SecCfgV4
from mtkclient.Library.utils import MTKTee
import json


class XCmd:
    CUSTOM_ACK = 0x0F0000
    CUSTOM_READMEM = 0x0F0001
    CUSTOM_READREGISTER = 0x0F0002
    CUSTOM_WRITEMEM = 0x0F0003
    CUSTOM_WRITEREGISTER = 0x0F0004
    CUSTOM_SET_STORAGE = 0x0F0005
    CUSTOM_RPMB_SET_KEY = 0x0F0006
    CUSTOM_RPMB_PROG_KEY = 0x0F0007
    CUSTOM_RPMB_INIT = 0x0F0008
    CUSTOM_RPMB_READ = 0x0F0009
    CUSTOM_RPMB_WRITE = 0x0F000A
    CUSTOM_SEJ_HW = 0x0F000B


rpmb_error = [
    "",
    "General failure",
    "Authentication failure",
    "Counter failure",
    "Address failure",
    "Write failure",
    "Read failure",
    "Authentication key not yet programmed"
]


# TB330FU/TB337FC ROW DA2 (DA2 is loaded at 0x40000000).
# The function at this file offset returns the Lenovo cust_init result used by
# the storage-write wrapper. These exact bytes are required so that this
# experiment cannot silently patch an unrelated DA image.
TB330FU_DA2_ALLOW_DOWNLOAD_OFFSET = 0x3EF64
TB330FU_DA2_ALLOW_DOWNLOAD_BASE = 0x40000000
TB330FU_DA2_ALLOW_DOWNLOAD_ORIGINAL = bytes.fromhex("01 4B 18 68 70 47 00 BF")
TB330FU_DA2_ALLOW_DOWNLOAD_PATCH = bytes.fromhex("01 20 70 47 00 BF 00 BF")


class XFlashExt(metaclass=LogBase):
    def __init__(self, mtk, xflash, loglevel):
        self.lasterror = None
        self.pathconfig = PathConfig()
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger,
                                                                                  loglevel, mtk.config.gui)
        self.mtk = mtk
        self.loglevel = loglevel
        self.__logger = self.__logger
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.rword = self.mtk.port.rword
        self.xflash = xflash
        self.xsend = self.xflash.xsend
        self.send_devctrl = self.xflash.send_devctrl
        self.xread = self.xflash.xread
        self.status = self.xflash.status
        self.da2 = None
        self.da2address = None

    def _patch_tb330fu_allow_download(self, da2patched):
        """Enable the DA storage-write gate for this DA session only.

        This is deliberately narrow and fail-closed: it requires both the
        expected DA2 load address and the exact original instruction bytes.
        """
        offset = TB330FU_DA2_ALLOW_DOWNLOAD_OFFSET
        original = TB330FU_DA2_ALLOW_DOWNLOAD_ORIGINAL
        replacement = TB330FU_DA2_ALLOW_DOWNLOAD_PATCH

        try:
            da2_base = self.xflash.daconfig.da_loader.region[2].m_start_addr
        except (AttributeError, IndexError, TypeError):
            self.error("Experimental DA write patch: unable to determine DA2 base address")
            return False

        if da2_base != TB330FU_DA2_ALLOW_DOWNLOAD_BASE:
            self.error(
                "Experimental DA write patch: refusing unexpected DA2 base "
                f"{hex(da2_base)} (expected {hex(TB330FU_DA2_ALLOW_DOWNLOAD_BASE)})"
            )
            return False

        if len(da2patched) < offset + len(original):
            self.error("Experimental DA write patch: DA2 is shorter than the expected offset")
            return False

        current = bytes(da2patched[offset:offset + len(original)])
        if current == replacement:
            self.config.experimental_da_write_applied = True
            self.warning(
                "Experimental DA write gate is already patched at "
                f"DA2+{hex(offset)}"
            )
            return True

        if current != original:
            self.error(
                "Experimental DA write patch: refusing unexpected bytes at "
                f"DA2+{hex(offset)}: {current.hex(' ')}"
            )
            return False

        da2patched[offset:offset + len(replacement)] = replacement
        self.config.experimental_da_write_applied = True
        self.warning(
            "EXPERIMENTAL: DA storage-write gate patched in memory at "
            f"DA2+{hex(offset)} (allow_download -> 1); not written to flash"
        )
        self.info(
            "DA write patch bytes: "
            f"{original.hex(' ')} -> {replacement.hex(' ')}"
        )
        return True

    def patch(self):
        self.da2 = self.xflash.daconfig.da2
        self.da2address = self.xflash.daconfig.da_loader.region[2].m_start_addr  # at_address
        daextensions = os.path.join(self.pathconfig.get_payloads_path(), "da_x.bin")
        if os.path.exists(daextensions):
            daextdata = bytearray(open(daextensions, "rb").read())

            register_devctrl = find_binary(self.da2, b"\x38\xB5\x05\x46\x0C\x20")

            # EMMC
            mmc_get_card = find_binary(self.da2, b"\x4B\x4F\xF4\x3C\x72")
            if mmc_get_card is not None:
                mmc_get_card -= 1
            else:
                mmc_get_card = find_binary(self.da2, b"\xA3\xEB\x00\x13\x18\x1A\x02\xEB\x00\x10")
                if mmc_get_card is not None:
                    mmc_get_card -= 10
            pos = 0
            while True:
                mmc_set_part_config = find_binary(self.da2, b"\xC3\x69\x0A\x46\x10\xB5", pos)
                if mmc_set_part_config is None:
                    break
                else:
                    pos = mmc_set_part_config + 1
                    if self.da2[mmc_set_part_config + 20:mmc_set_part_config + 22] == b"\xb3\x21":
                        break
            if mmc_set_part_config is None:
                mmc_set_part_config = find_binary(self.da2, b"\xC3\x69\x13\xF0\x01\x03")
            mmc_rpmb_send_command = find_binary(self.da2, b"\xF8\xB5\x06\x46\x9D\xF8\x18\x50")
            if mmc_rpmb_send_command is None:
                mmc_rpmb_send_command = find_binary(self.da2, b"\x2D\xE9\xF0\x41\x4F\xF6\xFD\x74")

            # UFS
            # ptr is right after ufshcd_probe_hba and at the beginning
            g_ufs_hba = None
            ptr_g_ufs_hba = find_binary(self.da2, b"\x20\x46\x0B\xB0\xBD\xE8\xF0\x83\x00\xBF")
            if ptr_g_ufs_hba is not None:
                g_ufs_hba = int.from_bytes(self.da2[ptr_g_ufs_hba + 10:ptr_g_ufs_hba + 10 + 4], 'little')
            else:
                # 6833 -> ufshcd_probe_hba
                ptr_g_ufs_hba = find_binary(self.da2, b"\x20\x46\x0D\xB0\xBD\xE8\xF0\x83")
                if ptr_g_ufs_hba is not None:
                    g_ufs_hba = int.from_bytes(self.da2[ptr_g_ufs_hba + 8:ptr_g_ufs_hba + 8 + 4], 'little')
                else:
                    ptr_g_ufs_hba = find_binary(self.da2, b"\x21\x46\x02\xF0\x02\xFB\x1B\xE6\x00\xBF")
                    if ptr_g_ufs_hba is not None:
                        g_ufs_hba = int.from_bytes(self.da2[ptr_g_ufs_hba + 10 + 0x8:ptr_g_ufs_hba + 10 + 0x8 + 4],
                                                   'little')

            if ptr_g_ufs_hba is not None:
                ufshcd_get_free_tag = find_binary(self.da2, b"\xB5.\xB1\x90\xF8")
                ufshcd_queuecommand = find_binary(self.da2, b"\x2D\xE9\xF8\x43\x01\x27")
            else:
                g_ufs_hba = None
                ufshcd_get_free_tag = None
                ufshcd_queuecommand = None

            register_ptr = daextdata.find(b"\x11\x11\x11\x11")
            mmc_get_card_ptr = daextdata.find(b"\x22\x22\x22\x22")
            mmc_set_part_config_ptr = daextdata.find(b"\x33\x33\x33\x33")
            mmc_rpmb_send_command_ptr = daextdata.find(b"\x44\x44\x44\x44")
            ufshcd_queuecommand_ptr = daextdata.find(b"\x55\x55\x55\x55")
            ufshcd_get_free_tag_ptr = daextdata.find(b"\x66\x66\x66\x66")
            ptr_g_ufs_hba_ptr = daextdata.find(b"\x77\x77\x77\x77")
            efuse_addr_ptr = daextdata.find(b"\x88\x88\x88\x88")

            if register_ptr != -1 and mmc_get_card_ptr != -1:
                if register_devctrl:
                    register_devctrl = register_devctrl + self.da2address | 1
                else:
                    register_devctrl = 0
                if mmc_get_card:
                    mmc_get_card = mmc_get_card + self.da2address | 1
                else:
                    mmc_get_card = 0
                if mmc_set_part_config:
                    mmc_set_part_config = mmc_set_part_config + self.da2address | 1
                else:
                    mmc_set_part_config = 0
                if mmc_rpmb_send_command:
                    mmc_rpmb_send_command = mmc_rpmb_send_command + self.da2address | 1
                else:
                    mmc_rpmb_send_command = 0

                if ufshcd_get_free_tag:
                    ufshcd_get_free_tag = ufshcd_get_free_tag + (self.da2address - 1) | 1
                else:
                    ufshcd_get_free_tag = 0

                if ufshcd_queuecommand:
                    ufshcd_queuecommand = ufshcd_queuecommand + self.da2address | 1
                else:
                    ufshcd_queuecommand = 0

                if g_ufs_hba is None:
                    g_ufs_hba = 0

                efuse_addr = self.config.chipconfig.efuse_addr

                # Patch the addr
                daextdata[register_ptr:register_ptr + 4] = pack("<I", register_devctrl)
                daextdata[mmc_get_card_ptr:mmc_get_card_ptr + 4] = pack("<I", mmc_get_card)
                daextdata[mmc_set_part_config_ptr:mmc_set_part_config_ptr + 4] = pack("<I", mmc_set_part_config)
                daextdata[mmc_rpmb_send_command_ptr:mmc_rpmb_send_command_ptr + 4] = pack("<I", mmc_rpmb_send_command)
                daextdata[ufshcd_get_free_tag_ptr:ufshcd_get_free_tag_ptr + 4] = pack("<I", ufshcd_get_free_tag)
                daextdata[ufshcd_queuecommand_ptr:ufshcd_queuecommand_ptr + 4] = pack("<I", ufshcd_queuecommand)
                daextdata[ptr_g_ufs_hba_ptr:ptr_g_ufs_hba_ptr + 4] = pack("<I", g_ufs_hba)
                if efuse_addr_ptr!=-1:
                    daextdata[efuse_addr_ptr:efuse_addr_ptr + 4] = pack("<I", efuse_addr)

                # print(hexlify(daextdata).decode('utf-8'))
                # open("daext.bin","wb").write(daextdata)
                return daextdata
        return None

    def patch_da1(self, da1):
        # Patch error 0xC0020039
        self.info("Patching da1 ...")
        da1patched = None
        if da1 is not None:
            da1patched = bytearray(da1)
            da1patched = self.mtk.patch_preloader_security_da1(da1patched)
            # Patch security

            da_version_check = find_binary(da1, b"\x1F\xB5\x00\x23\x01\xA8\x00\x93\x00\xF0")
            if da_version_check is not None:
                da1patched = bytearray(da1patched)
                da1patched[da_version_check:da_version_check + 4] = b"\x00\x20\x70\x47"
            else:
                self.warning("Error on patching da1 version check...")
        else:
            print("Error, couldn't find da1.")
        return da1patched

    def patch_da2(self, da2):
        da2 = self.mtk.patch_preloader_security_da2(da2)
        # Patch error 0xC0030007
        self.info("Patching da2 ...")
        # open("da2.bin","wb").write(da2)
        da2patched = bytearray(da2)
        # Patch huawei security, rma state
        pos = 0
        huawei = find_binary(da2, b"\x01\x2B\x03\xD1\x01\x23", pos)
        if huawei is not None:
            da2patched[huawei:huawei + 4] = b"\x00\x00\x00\x00"
        if find_binary(da2, b"[oplus]") or find_binary(da2, b"[OPPO]"):
            # Patch oppo security mt6765
            oppo = find_binary(da2, b"\x0A\x00\x00\xE0.\x00\x00\xE0")
            if oppo is not None:
                auth_flag_ptr = int.from_bytes(da2patched[oppo - 4:oppo], 'little')
                auth_flag_offset = auth_flag_ptr - self.mtk.daloader.daconfig.da_loader.region[2].m_start_addr
                if int.from_bytes(da2patched[auth_flag_offset:auth_flag_offset + 4], 'little') == 3:
                    da2patched[auth_flag_offset:auth_flag_offset + 1] = b"\x01"
                    self.info("Oppo g_oppo_auth_status patched.")
            else:
                oppo = find_binary(da2, b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
                if oppo is not None:
                    da2patched[oppo + 0x10:oppo + 0x10 + 1] = b"\x01"
                    self.info("Oppo g_oppo_auth_status patched.")
                else:
                    # 20271
                    oppo = find_binary(da2, b"\x63\x88\x74\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03")
                    if oppo is not None:
                        da2patched[oppo + 0x10:oppo + 0x10 + 1] = b"\x01"
                        self.info("Oppo g_oppo_auth_status patched.")

            # Patch oppo security
            oppo = 0
            pos = 0
            while oppo is not None:
                oppo = find_binary(da2, b"\x01\x3B\x01\x2B\x08\xD9", pos)
                if oppo is not None:
                    da2patched[oppo:oppo + 4] = b"\x01\x20\x08\xBD"
                    pos = oppo + 1

        # Patch hash binding 0xC0020004 or 0xC0020005
        hashbind = find_binary(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5")
        if hashbind is not None:
            da2patched[hashbind:hashbind + 1] = b"\x00"
        else:
            self.warning("Hash binding not patched.")

        # Patch hash check cmd_boot_to
        authaddr = find_binary(da2, int.to_bytes(0xC0070004, 4, 'little'))
        if authaddr:
            da2patched[authaddr:authaddr + 4] = int.to_bytes(0, 4, 'little')
        elif authaddr is None:
            authaddr = find_binary(da2, b"\x4F\xF0\x04\x09\xCC\xF2\x07\x09")
            if authaddr:
                da2patched[authaddr:authaddr + 8] = b"\x4F\xF0\x00\x09\x4F\xF0\x00\x09"
            else:
                authaddr = find_binary(da2, b"\x4F\xF0\x04\x09\x32\x46\x01\x98\x03\x99\xCC\xF2\x07\x09")
                if authaddr:
                    da2patched[authaddr:authaddr + 14] = b"\x4F\xF0\x00\x09\x32\x46\x01\x98\x03\x99\x4F\xF0\x00\x09"
                else:
                    self.warning("Hash check not patched.")
        # Disable security checks
        security_check = find_binary(da2, b"\x01\x23\x03\x60\x00\x20\x70\x47\x70\xB5")
        if security_check:
            da2patched[security_check:security_check + 2] = b"\x00\x23"
            self.info("Security check patched")
        # Disable da anti rollback version check
        antirollback = find_binary(da2, int.to_bytes(0xC0020053, 4, 'little'))
        if antirollback:
            da2patched[antirollback:antirollback + 4] = int.to_bytes(0, 4, 'little')
            self.info("DA version anti-rollback patched")
        disable_sbc = find_binary(da2, b"\x02\x4B\x18\x68\xC0\xF3\x40\x00\x70\x47")
        if disable_sbc:
            # MOV R0, #0
            da2patched[disable_sbc + 4:disable_sbc + 8] = b"\x4F\xF0\x00\x00"
            self.info("SBC patched to be disabled")
        register_readwrite = find_binary(da2, int.to_bytes(0xC004000D, 4, 'little'))
        if register_readwrite:
            da2patched[register_readwrite:register_readwrite + 4] = int.to_bytes(0, 4, 'little')
            self.info("Register read/write not allowed patched")
        # Patch write not allowed
        # open("da2.bin","wb").write(da2patched)
        idx = 0
        patched = False
        while idx != -1:
            idx = da2patched.find(b"\x37\xB5\x00\x23\x04\x46\x02\xA8")
            if idx != -1:
                da2patched[idx:idx + 8] = b"\x37\xB5\x00\x20\x03\xB0\x30\xBD"
                patched = True
            else:
                idx = da2patched.find(b"\x0C\x23\xCC\xF2\x02\x03")
                if idx != -1:
                    da2patched[idx:idx + 6] = b"\x00\x23\x00\x23\x00\x23"
                    idx2 = da2patched.find(b"\x2A\x23\xCC\xF2\x02\x03")
                    if idx2 != -1:
                        da2patched[idx2:idx2 + 6] = b"\x00\x23\x00\x23\x00\x23"
                    """
                    idx3 = da2patched.find(b"\x2A\x24\xE4\xF7\x89\xFB\xCC\xF2\x02\x04")
                    if idx3 != -1:
                        da2patched[idx3:idx3 + 10] = b"\x00\x24\xE4\xF7\x89\xFB\x00\x24\x00\x24"
                    """
                    patched = True
        if not patched:
            self.warning("Write not allowed not patched.")
        if getattr(self.config, "experimental_da_write", False):
            self._patch_tb330fu_allow_download(da2patched)
        return da2patched

    def cmd(self, cmd):
        if self.xsend(self.xflash.Cmd.DEVICE_CTRL):
            status = self.status()
            if status == 0x0:
                if self.xsend(cmd):
                    status = self.status()
                    if status == 0x0:
                        return True
                    else:
                        self.error(ErrorCodes_XFlash[status])

        return False

    def custom_read(self, addr, length):
        data = bytearray()
        pos = 0
        while pos < length:
            if self.cmd(XCmd.CUSTOM_READMEM):
                self.xsend(data=addr + pos, is64bit=True)
                sz = min(length, 0x10000)
                self.xsend(sz)
                tmp = self.xread()
                data.extend(tmp)
                pos += len(tmp)
                status = self.status()
                if status != 0:
                    break
        return data[:length]

    def custom_set_storage(self, ufs: bool = False):
        if self.cmd(XCmd.CUSTOM_SET_STORAGE):
            if ufs:
                self.xsend(int.to_bytes(1, 4, 'little'))
            else:
                # EMMC
                self.xsend(int.to_bytes(0, 4, 'little'))
            status = self.status()
            if status == 0:
                return True
        return False

    def custom_readregister(self, addr):
        if self.cmd(XCmd.CUSTOM_READREGISTER):
            self.xsend(addr)
            data = self.xread()
            status = self.status()
            if status == 0:
                return data
        return b""

    def custom_write(self, addr, data):
        if self.cmd(XCmd.CUSTOM_WRITEMEM):
            self.xsend(data=addr, is64bit=True)
            self.xsend(len(data))
            self.xsend(data)
            status = self.status()
            if status == 0:
                return True
        return False

    def custom_writeregister(self, addr, data):
        if self.cmd(XCmd.CUSTOM_WRITEREGISTER):
            self.xsend(addr)
            self.xsend(data)
            status = self.status()
            if status == 0:
                return True
        return False

    def custom_writeregister_noack(self, addr, data):
        """Send a register write without waiting for its completion status.

        This is needed for reset-triggering registers: the target can reset
        before the DA has a chance to return the normal command status.
        """
        if not self.cmd(XCmd.CUSTOM_WRITEREGISTER):
            return False
        if not self.xsend(addr):
            return False
        if not self.xsend(data):
            return False
        return True

    # ==================================================================
    # MT6768 (barley) reset / BROM-download primitives.
    #
    # Every address, name and step below was extracted from the official
    # Preloader image (preloader_barley_row_wifi.bin, SHA256 b07588b8...5412)
    # and is reproduced faithfully:
    #   set_usbdl_flag()    preloader VA 0x22C828  (file 0x2B918)
    #   drm_latch_handle()  preloader VA 0x2359D8  (file 0x34AC8)
    #   mtk_wdt_reset()     preloader VA 0x235AB8  (file 0x34BA8)
    #   mtk_arch_reset()    preloader VA 0x235C2C  (file 0x34D1C)
    #
    # RGU / TOPRGU watchdog block (chipconfig.watchdog == 0x10007000) - the
    # names come from the firmware's own register dump inside mtk_wdt_init():
    #   0x00 WDT_MODE      0x20 NONRST_REG    0x44 LATCH_CTL
    #   0x04 WDT_LENGTH    0x24 NONRST_REG2   0x48 LATCH_CTL2
    #   0x08 WDT_RESTART   0x30 REQ_MODE      0xA8 DEBUG_CTL3
    #   0x0C WDT_STATUS    0x34 REQ_IRQ_EN    0x7514 DEBUG_CTL5
    #   0x10 WDT_INTERVAL  0x40 DEBUG_CTL
    #   0x14 WDT_SWRST     0x18 WDT_SWSYSRST
    #
    # WDT_MODE bits: 0=ENABLE 2=EXTEN 3=IRQ 4=(unnamed) 5=DRM latch
    #                6=DUAL_MODE, [31:24]=KEY (0x22000000 on every write)
    # ==================================================================
    RGU_WDT_MODE = 0x00
    RGU_WDT_LENGTH = 0x04
    RGU_WDT_RESTART = 0x08
    RGU_WDT_STATUS = 0x0C
    RGU_WDT_INTERVAL = 0x10
    RGU_WDT_SWRST = 0x14
    RGU_WDT_SWSYSRST = 0x18
    RGU_WDT_NONRST_REG = 0x20
    RGU_WDT_NONRST_REG2 = 0x24
    RGU_REQ_MODE = 0x30
    RGU_REQ_IRQ_EN = 0x34
    RGU_DEBUG_CTL = 0x40
    RGU_LATCH_CTL = 0x44
    RGU_LATCH_CTL2 = 0x48

    WDT_MODE_KEY = 0x22000000
    # WDT_MODE_KEY is a write-only command key.  It is stripped from the
    # readable register value on this MT6768 (for example 0x22000024 reads
    # back as 0x24).  The low mode fields used by this reset path are readable.
    WDT_MODE_READBACK_MASK = 0x0000007C
    WDT_MODE_CLEAR_RESET = 0x00000058
    WDT_MODE_EXTEN = 0x00000004
    WDT_MODE_DRM_LATCH = 0x00000020
    WDT_RESTART_MAGIC = 0x00001971
    WDT_SWRST_MAGIC = 0x00001209
    WDT_DRM_LATCH_ARM = 0x230001FF
    WDT_LATCH2_SET = 0x95000000
    WDT_LATCH2_CLR = 0x90000000
    WDT_NONRST2_BIT13 = 0x00002000

    # MISC / SRAMROM-TZ_SEC_CFG block (chipconfig.misc_lock == 0x1001A100)
    MISC_LOCK_ADDR = 0x1001A100
    MISC_LOCK_KEY = 0xAD98
    RST_CON_ADDR = 0x1001A108
    RST_CON_BIT0 = 0x00000001
    USB_DL_FLAG_ADDR = 0x1001A080

    USBDL_MAGIC = 0x444C0000
    USBDL_BIT_EN = 0x00000001
    USBDL_BROM = 0x00000002
    USBDL_TIMEOUT_MASK = 0x0000FFFC
    USBDL_TIMEOUT_MAX = 0x3FFF

    def usbdl_flag_value(self, enable=True, timeout_ms=0, use_brom=True):
        """Compose the usbdl_flag / BOOT_MISC0 32-bit value.

        Layout (matches preloader set_usbdl_flag() at VA 0x22C828 and the
        mtkclient USBDL_* constants):
          [31:16] 0x444C  USBDL_MAGIC  - the magic the BootROM checks
          [15:2]  timeout in SECONDS; 0x3FFF means "no timeout"
          [1]     0 = usbdl served by BROM, 1 = served by bootloader
          [0]     1 = download bit enabled

        0x3FFF seconds (about 4.5 hours) is the largest value the 14-bit field
        can hold; larger values are truncated by the mask exactly like the
        firmware does. Pass timeout_ms=0 for "no timeout".
        """
        if timeout_ms:
            seconds = int(timeout_ms) // 1000
        else:
            seconds = self.USBDL_TIMEOUT_MAX
        value = (seconds << 2) & self.USBDL_TIMEOUT_MASK
        value &= ~self.USBDL_BROM
        if not use_brom:
            value |= self.USBDL_BROM
        if enable:
            value |= self.USBDL_BIT_EN
        value |= self.USBDL_MAGIC
        return value

    def _reg_read(self, addr, who=""):
        data = self.custom_readregister(addr)
        if not isinstance(data, (bytes, bytearray)) or len(data) != 4:
            self.error(f"Could not read {hex(addr)} ({who})")
            return None
        return unpack("<I", data)[0]

    def _write_verify(self, addr, value, name="", mask=0xFFFFFFFF):
        """Write a register and read it back.

        Returns (ok, readback). 'ok' compares only the bits in 'mask', because
        several MTK registers contain write-only or self-clearing fields.
        This is the only way to tell a landed MMIO write apart from an ACKed
        but ignored one - which is exactly the failure mode to watch for on
        the RGU/TOPRGU block.
        """
        ok_w = self.custom_writeregister(addr, value)
        back = self._reg_read(addr, name or "write-verify")
        if back is None:
            return False, None
        good = ok_w and ((back & mask) == (value & mask))
        tag = "OK  " if good else "FAIL"
        self.info(f"  verify {tag} {name or hex(addr)}: wrote {hex(value)} read {hex(back)}")
        return good, back

    def dump_brom_regs(self):
        """Dump the registers that decide whether we can reach BROM."""
        base = self.config.chipconfig.watchdog
        self.info("---- RGU / TOPRGU (watchdog) ----")
        names = [
            (0x00, "WDT_MODE"), (0x04, "WDT_LENGTH"), (0x08, "WDT_RESTART"),
            (0x0C, "WDT_STATUS"), (0x10, "WDT_INTERVAL"), (0x14, "WDT_SWRST"),
            (0x18, "WDT_SWSYSRST"), (0x20, "WDT_NONRST_REG"), (0x24, "WDT_NONRST_REG2"),
            (0x30, "REQ_MODE"), (0x34, "REQ_IRQ_EN"), (0x40, "DEBUG_CTL"),
            (0x44, "LATCH_CTL"), (0x48, "LATCH_CTL2"),
        ]
        if base is not None:
            for off, nm in names:
                v = self._reg_read(base + off, nm)
                self.info(f"  0x{base + off:08X} {nm:<18s} = "
                          f"{'<read failed>' if v is None else hex(v)}")
        self.info("---- MISC / SRAMROM ----")
        for addr, nm in ((self.USB_DL_FLAG_ADDR, "usbdl_flag/BOOT_MISC0"),
                         (self.RST_CON_ADDR, "RST_CON"),
                         (self.MISC_LOCK_ADDR, "MISC_LOCK")):
            v = self._reg_read(addr, nm)
            self.info(f"  0x{addr:08X} {nm:<22s} = "
                      f"{'<read failed>' if v is None else hex(v)}")
        self.info(f"  decoded usbdl_flag: magic="
                  f"{'OK' if True else ''} see above; expected magic 0x444C____ "
                  f"with bit0=1, bit1=0")

    def _drm_latch_handle(self, wdt_base):
        """Reproduce drm_latch_handle() (preloader VA 0x2359D8).

        Writes 0x230001FF into WDT_MODE, settles 40 ms, then toggles the DRM
        latch bit (bit5) with 70 ms settling delays. Every write re-arms the
        WDT_MODE key, exactly as the firmware does.

        The WDT_MODE key (0x22000000) is write-only and is stripped from the
        readable value.  The probe therefore checks the readable low mode bits;
        it must not expect the key bits to appear in readback.
        """
        mode = wdt_base + self.RGU_WDT_MODE
        if not self.custom_writeregister(mode, self.WDT_DRM_LATCH_ARM):
            self.error(f"drm_latch_handle: write {hex(mode)} failed")
            return False
        time.sleep(0.040)

        cur = self._reg_read(mode, "WDT_MODE probe")
        if cur is None:
            return False
        self.info(f"  RGU write probe: WDT_MODE after 0x230001FF = {hex(cur)}")
        probe_mask = self.WDT_MODE_READBACK_MASK
        probe_expected = self.WDT_DRM_LATCH_ARM & probe_mask
        if (cur & probe_mask) != probe_expected:
            self.warning("  WDT_MODE readable bits differ from the probe value: "
                         f"expected {hex(probe_expected)}, got {hex(cur & probe_mask)}")
        self.info("  WDT_MODE key bits are write-only; their absence from readback "
                  "does not indicate a rejected RGU write")
        self._rgu_writable = True

        if cur & self.WDT_MODE_DRM_LATCH:
            tmp = (cur & ~self.WDT_MODE_DRM_LATCH) | self.WDT_MODE_KEY
            if not self.custom_writeregister(mode, tmp):
                return False
            time.sleep(0.070)
            cur = self._reg_read(mode, "drm_latch_handle readback 2")
            if cur is None:
                return False
            tmp = cur | self.WDT_MODE_KEY | self.WDT_MODE_DRM_LATCH
        else:
            tmp = cur | self.WDT_MODE_KEY | self.WDT_MODE_DRM_LATCH
            if not self.custom_writeregister(mode, tmp):
                return False
            time.sleep(0.070)
            cur = self._reg_read(mode, "drm_latch_handle readback 2")
            if cur is None:
                return False
            tmp = (cur & ~self.WDT_MODE_DRM_LATCH) | self.WDT_MODE_KEY

        self.debug(f"drm_latch_handle: WDT_MODE <- {hex(tmp)}")
        return bool(self.custom_writeregister(mode, tmp))

    def _rgu_wdt_reset(self, wdt_base, arg=0, drm_latch=True):
        """Reproduce mtk_wdt_reset(arg) (preloader VA 0x235AB8) step by step.

        arg == 0 -> the path used by emergency_download_mode()/mtk_arch_reset(0)
        arg != 0 -> additionally sets WDT_MODE EXTEN and NONRST_REG2 bit13

        Steps: drm_latch_handle -> WDT_RESTART kick -> LATCH_CTL2 arm/clear ->
        WDT_MODE rebuild -> NONRST_REG2 restore -> 100 ms delay -> SWRST.
        The 100 ms delay MUST happen before SWRST.

        Every write is read back. If WDT_MODE does not accept the key bits the
        whole RGU block is write-protected for this DA session, and SWRST will
        be ignored as well - that is reported explicitly instead of silently
        pretending the reset happened.
        """
        nonrst2 = wdt_base + self.RGU_WDT_NONRST_REG2
        latch2 = wdt_base + self.RGU_LATCH_CTL2
        mode = wdt_base + self.RGU_WDT_MODE
        restart = wdt_base + self.RGU_WDT_RESTART
        swrst = wdt_base + self.RGU_WDT_SWRST

        saved = self._reg_read(nonrst2, "NONRST_REG2")
        if saved is None:
            return False

        self._rgu_writable = True
        if drm_latch:
            if not self._drm_latch_handle(wdt_base):
                self.error("drm_latch_handle failed")
                return False

        self._write_verify(restart, self.WDT_RESTART_MAGIC, "WDT_RESTART (kick)", mask=0)

        self._write_verify(latch2, self.WDT_LATCH2_SET, "LATCH_CTL2 set", mask=0)
        latch_rb = self._reg_read(latch2, "LATCH_CTL2 readback")
        if latch_rb is None:
            return False
        if latch_rb == 0:
            latch_new = (latch_rb & ~0x20000) | self.WDT_LATCH2_SET
        else:
            latch_new = self.WDT_LATCH2_CLR
        self.debug(f"LATCH_CTL2 readback {hex(latch_rb)} -> {hex(latch_new)}")
        self._write_verify(latch2, latch_new, "LATCH_CTL2 final", mask=0)

        cur_mode = self._reg_read(mode, "WDT_MODE")
        if cur_mode is None:
            return False
        new_mode = (cur_mode & ~self.WDT_MODE_CLEAR_RESET) | self.WDT_MODE_KEY
        if arg:
            new_mode |= self.WDT_MODE_EXTEN
            saved |= self.WDT_NONRST2_BIT13
        self.info(f"WDT_MODE {hex(cur_mode)} -> {hex(new_mode)} (arg={arg})")
        # Compare only readable mode fields.  The 0x22000000 write key is
        # intentionally absent from readback (0x22000024 -> 0x24).
        mode_ok, mode_back = self._write_verify(
            mode, new_mode, "WDT_MODE", mask=self.WDT_MODE_READBACK_MASK
        )

        self._write_verify(nonrst2, saved, "NONRST_REG2", mask=0)

        if not mode_ok or not getattr(self, "_rgu_writable", True):
            self.error("RGU/TOPRGU writes are NOT landing on this device. "
                       "WDT_SWRST would be ignored too, so no reset will happen.")
            self.error("=> Re-run with --reset-method shutdown, or use the Preloader "
                       "route:  python mtk.py bromreset")
            self._last_rgu_write_ok = False
            return False
        self._last_rgu_write_ok = True

        time.sleep(0.100)
        self.info(f"Triggering WDT_SWRST at {hex(swrst)} <- {hex(self.WDT_SWRST_MAGIC)}")
        return bool(self.custom_writeregister_noack(swrst, self.WDT_SWRST_MAGIC))

    def read_usbdl_flag(self, addr=None):
        """Read usbdl_flag / BOOT_MISC0 through the DA register extension.

        Use before the reset to confirm the write. The decisive check is to
        read it AFTER re-enumeration: if the device comes back as the Preloader
        (PID 0x2000), reading 0x1001A080 with the Preloader READ32 (0xD1)
        command tells you which failure mode you are in:
          still 0x444CFFFD-ish -> the BootROM ignored the flag
          0 or magic lost      -> the reset cleared the flag
        """
        addr = self.USB_DL_FLAG_ADDR if addr is None else addr
        value = self._reg_read(addr, "usbdl_flag")
        if value is None:
            return None
        self.info(f"usbdl_flag {hex(addr)} = {hex(value)}")
        return value

    def force_brom(self, reboot=True, reset_method="wdt", flag_mode="brom",
                   rst_con="set", reset_seq="full", wdt_reset_arg=0,
                   timeout_ms=0, drm_latch=True):
        """Set the MTK USB download flag using the DA register extension.

        The normal Preloader reset_to_brom() path uses the Preloader WRITE32
        command.  On protected MT6768 devices that path can be rejected before
        the download flag is written.  The Carbonara DA extension exposes a
        separate raw register-write command (F0004), so repeat the same
        register sequence after the DA extension has been accepted.

        This changes SoC boot/reset registers only; it does not write flash.

        flag_mode
          "brom"       -> bit1 = 0, the BootROM serves USB download (default)
          "bootloader" -> bit1 = 1, the bootloader/preloader serves USB download

        rst_con
          "set"   -> 0x1001A108 |= 1 (what the firmware does)
          "clear" -> 0x1001A108 &= ~1
          "keep"  -> leave 0x1001A108 untouched

        reset_seq
          "full"   -> faithful reproduction of the Preloader's own
                      mtk_wdt_reset(): drm_latch_handle, WDT_RESTART,
                      LATCH_CTL2 arm/clear, WDT_MODE rebuild, NONRST_REG2
                      restore, 100 ms delay, then WDT_SWRST. Default.
          "legacy" -> the previous short sequence kept for A/B testing

        wdt_reset_arg is the R0 argument of mtk_arch_reset()/mtk_wdt_reset();
        the firmware's emergency_download_mode() uses 0.

        The caller can use reboot=False for inspection or manual reset testing.
        """
        if not self.xflash.daext:
            self.error("DA extensions are not active; refusing forcebrom")
            return False
        if self.config.hwcode != 0x707:
            self.error(f"forcebrom is only verified for HW code 0x707, got {self.config.hwcode!r}")
            return False
        if self.config.chipconfig.misc_lock != self.MISC_LOCK_ADDR:
            self.error(f"forcebrom expects misc_lock {hex(self.MISC_LOCK_ADDR)}, "
                       f"got {self.config.chipconfig.misc_lock!r}")
            return False

        # TB330FU barley firmware: function at file offset 0x2B918;
        # literal pool 0x2B960/64/68 = MISC_LOCK, RST_CON, usbdl_flag.
        # The flag is 0x1001A080 (= misc_lock - 0x20), NOT a generic address.
        # The firmware updates RST_CON with read/OR/write, preserving other bits.
        reset_control_value = self._reg_read(self.RST_CON_ADDR, "RST_CON")
        if reset_control_value is None:
            self.error("Could not read RST_CON; no register writes or reset sent")
            return False
        self.info(f"RST_CON before update: {hex(reset_control_value)}")

        if rst_con == "set":
            new_rst_con = reset_control_value | self.RST_CON_BIT0
        elif rst_con == "clear":
            new_rst_con = reset_control_value & ~self.RST_CON_BIT0
        elif rst_con == "keep":
            new_rst_con = reset_control_value
        else:
            self.error(f"Unknown rst_con mode: {rst_con!r}")
            return False

        flag_value = self.usbdl_flag_value(enable=True, timeout_ms=timeout_ms,
                                           use_brom=(flag_mode == "brom"))
        self.info(f"usbdl_flag value: {hex(flag_value)} "
                  f"(flag_mode={flag_mode}, timeout_ms={timeout_ms})")
        if flag_mode not in ("brom", "bootloader"):
            self.error(f"Unknown flag_mode: {flag_mode!r}")
            return False

        writes = (
            (self.MISC_LOCK_ADDR, self.MISC_LOCK_KEY),
            (self.RST_CON_ADDR, new_rst_con),
            (self.MISC_LOCK_ADDR, 0),
            (self.USB_DL_FLAG_ADDR, flag_value),
        )

        self.info(f"Setting BROM download flag at {hex(self.USB_DL_FLAG_ADDR)} "
                  f"through DA register extension")
        for address, value in writes:
            self.debug(f"DA register write {hex(address)} <- {hex(value)}")
            if not self.custom_writeregister(address, value):
                self.error(f"DA register write failed at {hex(address)}")
                return False

        # The extension's write handler returns status 0 even though it does
        # not report the resulting register value.  Read back the flag so a
        # protocol-level ACK is not mistaken for a successful MMIO write.
        readback_value = self._reg_read(self.USB_DL_FLAG_ADDR, "usbdl_flag readback")
        if readback_value is None:
            self.error(f"Could not read back BROM flag at {hex(self.USB_DL_FLAG_ADDR)}")
            return False
        self.info(f"BROM flag readback: {hex(readback_value)}")
        if (readback_value & 0xFFFF0003) != (self.USBDL_MAGIC | self.USBDL_BIT_EN):
            self.error("BROM flag readback does not contain the expected magic/enable bits")
            return False
        self.info("BROM download flag accepted by DA register extension")
        self.info("WARNING: this only proves the MMIO write landed. It does NOT prove "
                  "that the BootROM will adopt the flag after the reset.")

        if not reboot:
            self.info("Reset suppressed (--no-reset); dumping the relevant registers")
            self.dump_brom_regs()
            self.info("Reset the device manually now, then run:  "
                      "python mtk.py da readflag --loader <loader>")
            return True

        if reset_method == "wdt":
            wdt_base = self.config.chipconfig.watchdog
            if wdt_base != 0x10007000:
                self.error(f"WDT reset is only verified at 0x10007000, got {wdt_base!r}")
                return False

            if reset_seq == "full":
                self.info("Using the Preloader-equivalent reset sequence "
                          "(drm_latch_handle + LATCH_CTL2 + NONRST_REG2 + 100 ms)")
                if not self._rgu_wdt_reset(wdt_base, arg=wdt_reset_arg,
                                           drm_latch=drm_latch):
                    if getattr(self, "_last_rgu_write_ok", True):
                        self.error("Preloader-equivalent watchdog reset failed")
                    # _last_rgu_write_ok == False already printed the reason
                    return False
            elif reset_seq == "legacy":
                wdt_reset = wdt_base + self.RGU_WDT_SWRST
                wdt_restart = wdt_base + self.RGU_WDT_RESTART
                wdt_mode = wdt_base + self.RGU_WDT_MODE
                self.info("Using the legacy short reset sequence (A/B testing only)")
                if not self.custom_writeregister(wdt_restart, self.WDT_RESTART_MAGIC):
                    self.error(f"Could not write watchdog restart register at {hex(wdt_restart)}")
                    return False
                if not self.custom_writeregister(wdt_mode, 0x22000014):
                    self.error(f"Could not write WDT_MODE at {hex(wdt_mode)}")
                    return False
                time.sleep(0.100)
                self.info(f"Triggering MTK watchdog software reset at {hex(wdt_reset)}")
                if not self.custom_writeregister_noack(wdt_reset, self.WDT_SWRST_MAGIC):
                    self.error("Could not send the watchdog software-reset command")
                    return False
            else:
                self.error(f"Unknown reset_seq: {reset_seq!r}")
                return False

            # Give the DA a moment to execute the write before the caller
            # closes the transport.  The reset may already cut the USB link.
            time.sleep(0.1)
            self.info("Watchdog reset command sent; waiting for BROM enumeration")
            self.info("Expected on success: VID 0x0E8D / PID 0x0003 (BootROM). "
                      "If it comes back as VID 0x0E8D / PID 0x2000, the Preloader is "
                      "running again - then read 0x1001A080 with the Preloader "
                      "READ32 (0xD1) command: the same value means the BootROM "
                      "ignored the flag, all-zero means the reset cleared it.")
            return True

        if reset_method != "shutdown":
            self.error(f"Unknown forcebrom reset method: {reset_method}")
            return False

        self.info("Requesting device shutdown/reset; waiting for BROM enumeration")
        # dl_bit=1 marks this as a download reset in the XFlash shutdown
        # packet.  The BROM flag above selects BROM rather than bootloader.
        return self.xflash.shutdown(async_mode=0, dl_bit=1,
                                    bootmode=self.xflash.ShutDownModes.NORMAL)

    def readmem(self, addr, dwords=1):
        res = []
        if dwords < 0x20:
            for pos in range(dwords):
                val = self.custom_readregister(addr + pos * 4)
                if val == b"":
                    return False
                data = unpack("<I", val)[0]
                if dwords == 1:
                    self.debug(f"RX: {hex(addr + (pos * 4))} -> {hex(data)}")
                    return data
                res.append(data)
        else:
            res = self.custom_read(addr, dwords * 4)
            res = [unpack("<I", res[i:i + 4])[0] for i in range(0, len(res), 4)]

        self.debug(f"RX: {hex(addr)} -> " + bytearray(b"".join(pack("<I", val) for val in res)).hex())
        return res

    def writeregister(self, addr, dwords):
        if isinstance(dwords, int):
            dwords = [dwords]
        pos = 0
        if len(dwords) < 0x20:
            for val in dwords:
                self.debug(f"TX: {hex(addr + pos)} -> " + hex(val))
                if not self.custom_writeregister(addr + pos, val):
                    return False
                pos += 4
        else:
            dat = b"".join([pack("<I", val) for val in dwords])
            self.custom_write(addr, dat)
        return True

    def writemem(self, addr, data):
        for i in range(0, len(data), 4):
            value = data[i:i + 4]
            while len(value) < 4:
                value += b"\x00"
            self.writeregister(addr + i, unpack("<I", value))
        return True

    def custom_rpmb_read(self, sector, sectors):
        data = bytearray()
        cmd = XCmd.CUSTOM_RPMB_READ
        if self.cmd(cmd):
            self.xsend(sector)
            self.xsend(sectors)
            for i in range(sectors):
                tmp = self.xread()
                if len(tmp) != 0x100:
                    resp = int.from_bytes(tmp, 'little')
                    if resp in rpmb_error:
                        msg = rpmb_error[resp]
                    else:
                        msg = f"Error: {hex(resp)}"
                    self.error(f"Error on sector {hex(sector)}: {msg})")
                    return b""
                else:
                    data.extend(tmp)
        status = self.status()
        if status == 0:
            return data
        else:
            return b""

    def custom_rpmb_write(self, sector, sectors, data: bytes):
        if len(data)%0x100!=0:
            self.error("Incorrect rpmb frame length. Aborting")
            return False
        cmd = XCmd.CUSTOM_RPMB_WRITE
        if self.cmd(cmd):
            self.xsend(sector)
            self.xsend(sectors)
            for i in range(sectors):
                self.xsend(data[i * 0x100:(i * 0x100) + 0x100])
                resp = unpack("<H", self.xflash.get_response(raw=True))[0]
                if resp != 0:
                    if resp in rpmb_error:
                        self.error(rpmb_error[resp])
                        status = self.status()
                        return False
            status = self.status()
            if status == 0:
                return True

        status = self.status()
        return False

    def custom_rpmb_init(self):
        hwc = self.cryptosetup()
        if self.config.chipconfig.meid_addr:
            meid = self.config.get_meid()
            otp = self.config.get_otp()
            if meid != b"\x00" * 16:
                # self.config.set_meid(meid)
                self.info("Generating sej rpmbkey...")
                rpmbkey = hwc.aes_hwcrypt(mode="rpmb", data=meid, btype="sej", otp=otp)
                if rpmbkey is not None:
                    if self.cmd(XCmd.CUSTOM_RPMB_SET_KEY):
                        self.xsend(rpmbkey)
                        read_key = self.xread()
                        if self.status() == 0x0:
                            if rpmbkey == read_key:
                                self.info("Setting rpmbkey: ok")
        cmd = XCmd.CUSTOM_RPMB_INIT
        if self.cmd(cmd):
            status = self.status()
            if status == 0:
                derivedrpmb = self.xread()
                self.status()
                if status == 0:
                    self.info("Derived rpmb key: " + derivedrpmb.hex())
                    return True
            else:
                if status in rpmb_error:
                    print(rpmb_error[status])
                    return False
            self.error("Failed to derive a valid rpmb key.")
        return False

    def setotp(self, hwc):
        otp = None
        if self.mtk.config.preloader is not None:
            idx = self.mtk.config.preloader.find(b"\x4D\x4D\x4D\x01\x30")
            if idx != -1:
                otp = self.mtk.config.preloader[idx + 0xC:idx + 0xC + 32]
        if otp is None:
            otp = 32 * b"\x00"
        hwc.sej.sej_set_otp(otp)

    def read_rpmb(self, filename=None, sector: int = None, sectors: int = None, display=True):
        progressbar = Progress(1, self.mtk.config.guiprogress)
        # val = self.custom_rpmb_init()
        if sector is None:
            sector = 0
        if sectors==0:
            if self.mtk.daloader.daconfig.flashtype == "emmc":
                sectors = self.xflash.emmc.rpmb_size // 0x100
            elif self.mtk.daloader.daconfig.flashtype == "ufs":
                sectors = (512 * 256)
        if filename is None:
            filename = "rpmb.bin"
        if sectors > 0:
            with open(filename, "wb") as wf:
                pos = 0
                toread = sectors
                while toread > 0:
                    if display:
                        progressbar.show_progress("RPMB read", pos * 0x100, sectors * 0x100, display)
                    sz = min(sectors - pos, 0x10)
                    data = self.custom_rpmb_read(sector=sector + pos, sectors=sz)
                    if data == b"":
                        self.error("Couldn't read rpmb.")
                        return False
                    wf.write(data)
                    pos += sz
                    toread -= sz
            if display:
                progressbar.show_progress("RPMB read", sectors * 0x100, sectors * 0x100, display)
            self.info(f"Done reading rpmb to {filename}")
            return True
        return False

    def write_rpmb(self, filename=None, sector: int = None, sectors: int = None, display=True):
        progressbar = Progress(1, self.mtk.config.guiprogress)
        if filename is None:
            self.error("Filename has to be given for writing to rpmb")
            return False
        if not os.path.exists(filename):
            self.error(f"Couldn't find {filename} for writing to rpmb.")
            return False
        if sectors == 0:
            max_sector_size = (512 * 256)
            if self.xflash.emmc is not None:
                max_sector_size = self.xflash.emmc.rpmb_size // 0x100
        else:
            max_sector_size = sectors
        filesize = os.path.getsize(filename)
        sectors = min(filesize // 256, max_sector_size)
        if self.custom_rpmb_init():
            if sectors > 0:
                with open(filename, "rb") as rf:
                    pos = 0
                    towrite = sectors
                    while towrite > 0:
                        if display:
                            progressbar.show_progress("RPMB written", pos * 0x100, sectors * 0x100, display)
                        sz = min(sectors - pos, 0x10)
                        if not self.custom_rpmb_write(sector=sector+pos, sectors=sz, data=rf.read(0x100*sz)):
                            self.error(f"Couldn't write rpmb at sector {sector+pos}.")
                            return False
                        pos += sz
                        towrite -= sz
                if display:
                    progressbar.show_progress("RPMB written", sectors * 0x100, sectors * 0x100, display)
                self.info(f"Done writing {filename} to rpmb")
                return True
        return False

    def erase_rpmb(self, sector: int = None, sectors: int = None, display=True):
        progressbar = Progress(1, self.mtk.config.guiprogress)
        ufs = False
        if sector is None:
            sector = 0
        if sectors is None:
            if self.xflash.emmc is not None:
                sectors = self.xflash.emmc.rpmb_size // 0x100
            else:
                sectors = (512 * 256)
        if self.custom_rpmb_init():
            if sectors > 0:
                pos = 0
                towrite = sectors
                while towrite > 0:
                    sz = min(sectors - pos, 0x10)
                    if display:
                        progressbar.show_progress("RPMB erased", pos * 0x100, sectors * 0x100, display)
                    if not self.custom_rpmb_write(sector=sector+pos, sectors=sz, data=b"\x00" * 0x100 * sz):
                        self.error(f"Couldn't erase rpmb at sector {sector+pos}.")
                        return False
                    pos += sz
                    towrite -= sz
                if display:
                    progressbar.show_progress("RPMB erased", sectors * 0x100, sectors * 0x100, display)
                self.info("Done erasing rpmb")
                return True
        return False

    def cryptosetup(self):
        setup = CryptoSetup()
        setup.blacklist = self.config.chipconfig.blacklist
        setup.gcpu_base = self.config.chipconfig.gcpu_base
        setup.dxcc_base = self.config.chipconfig.dxcc_base
        setup.efuse_base = self.config.chipconfig.efuse_addr
        setup.da_payload_addr = self.config.chipconfig.da_payload_addr
        setup.sej_base = self.config.chipconfig.sej_base
        setup.read32 = self.readmem
        setup.write32 = self.writeregister
        setup.writemem = self.writemem
        setup.hwcode = self.config.hwcode
        return HwCrypto(setup, self.loglevel, self.config.gui)

    def seccfg(self, lockflag):
        if lockflag not in ["unlock", "lock"]:
            return False, "Valid flags are: unlock, lock"
        data, guid_gpt = self.xflash.partition.get_gpt(self.mtk.config.gpt_settings, "user")
        seccfg_data = None
        partition = None
        if guid_gpt is None:
            return False, "Error getting the partition table."
        for rpartition in guid_gpt.partentries:
            if rpartition.name == "seccfg":
                partition = rpartition
                seccfg_data = self.xflash.readflash(
                    addr=partition.sector * self.mtk.daloader.daconfig.pagesize,
                    length=partition.sectors * self.mtk.daloader.daconfig.pagesize,
                    filename="", parttype="user", display=False)
                break
        if seccfg_data is None:
            return False, "Couldn't detect existing seccfg partition. Aborting unlock."
        if seccfg_data[:4] != pack("<I", 0x4D4D4D4D):
            return False, "Unknown seccfg partition header. Aborting unlock."
        hwc = self.cryptosetup()
        if seccfg_data[:0xC] == b"AND_SECCFG_v":
            self.info("Detected V3 Lockstate")
            sc_org = SecCfgV3(hwc, self.mtk)
        elif seccfg_data[:4] == b"\x4D\x4D\x4D\x4D":
            self.info("Detected V4 Lockstate")
            sc_org = SecCfgV4(hwc, self.mtk)
        else:
            return False, "Unknown lockstate or no lockstate"
        if not sc_org.parse(seccfg_data):
            return False, "Device has is either already unlocked or algo is unknown. Aborting."
        ret, writedata = sc_org.create(lockflag=lockflag)
        if ret is False:
            return False, writedata
        if self.xflash.writeflash(addr=partition.sector * self.mtk.daloader.daconfig.pagesize,
                                  length=len(writedata),
                                  filename="", wdata=writedata, parttype="user", display=True):
            return True, "Successfully wrote seccfg."
        return False, "Error on writing seccfg config to flash."

    def decrypt_tee(self, filename="tee1.bin", aeskey1: bytes = None, aeskey2: bytes = None):
        hwc = self.cryptosetup()
        with open(filename, "rb") as rf:
            data = rf.read()
            idx = 0
            while idx != -1:
                idx = data.find(b"EET KTM ", idx + 1)
                if idx != -1:
                    mt = MTKTee()
                    mt.parse(data[idx:])
                    rdata = hwc.mtee(data=mt.data, keyseed=mt.keyseed, ivseed=mt.ivseed,
                                     aeskey1=aeskey1, aeskey2=aeskey2)
                    open("tee_" + hex(idx) + ".dec", "wb").write(rdata)

    def read_fuse(self, idx):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            addr = efuseconfig.efuses[idx]
            if addr < 0x1000:
                return int.to_bytes(addr, 4, 'little')
            data = bytearray(self.mtk.daloader.peek(addr=addr, length=4))
            return data
        return None

    def read_pubk(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            addr = base + 0x90
            data = bytearray(self.mtk.daloader.peek(addr=addr, length=0x30))
            return data
        return None

    def read_fuses(self):
        if self.mtk.config.chipconfig.efuse_addr is not None:
            base = self.mtk.config.chipconfig.efuse_addr
            hwcode = self.mtk.config.hwcode
            efuseconfig = Efuse(base, hwcode)
            data = []
            for idx in range(len(efuseconfig.efuses)):
                addr = efuseconfig.efuses[idx]
                if addr < 0x1000:
                    data.append(int.to_bytes(addr, 4, 'little'))
                else:
                    data.append(bytearray(self.mtk.daloader.peek(addr=addr, length=4)))
            return data

    def custom_read_reg(self, addr: int, length: int) -> bytes:
        data = bytearray()
        for pos in range(addr, addr + length, 4):
            tmp = self.custom_readregister(pos)
            if tmp == b"":
                break
            data.extend(tmp.to_bytes(4, 'little'))
        return data

    def generate_keys(self):
        if self.config.hwcode in [0x2601, 0x6572]:
            base = 0x11141000
        elif self.config.hwcode == 0x6261:
            base = 0x70000000
        elif self.config.hwcode in [0x8172, 0x8176]:
            base = 0x122000
        else:
            base = 0x100000
        if self.config.meid is None:
            try:
                data = b"".join([pack("<I", val) for val in self.readmem(base + 0x8EC, 0x16 // 4)])
                self.config.meid = data
                self.config.set_meid(data)
            except Exception as err:
                self.lasterror = err
                return
        if self.config.socid is None:
            try:
                data = b"".join([pack("<I", val) for val in self.readmem(base + 0x934, 0x20 // 4)])
                self.config.socid = data
                self.config.set_socid(data)
            except Exception as err:
                self.lasterror = err
                return
        hwc = self.cryptosetup()
        meid = self.config.get_meid()
        socid = self.config.get_socid()
        hwcode = self.config.get_hwcode()
        cid = self.config.get_cid()
        otp = self.config.get_otp()
        retval = {}
        # data=hwc.aes_hwcrypt(data=bytes.fromhex("A9 E9 DC 38 BF 6B BD 12 CC 2E F9 E6 F5 65 E8 C6 88 F7 14 11 80 " +
        # "2E 4D 91 8C 2B 48 A5 BB 03 C3 E5"), mode="sst", btype="sej",
        #                encrypt=False)
        # self.info(data.hex())
        pubk = self.read_pubk()
        if pubk is not None:
            retval["pubkey"] = pubk.hex()
            self.info(f"PUBK        : {pubk.hex()}")
            self.config.hwparam.writesetting("pubkey", pubk.hex())
        if meid is not None:
            self.info(f"MEID        : {meid.hex()}")
            retval["meid"] = meid.hex()
            self.config.hwparam.writesetting("meid", meid.hex())
        if socid is not None:
            self.info(f"SOCID       : {socid.hex()}")
            retval["socid"] = socid.hex()
            self.config.hwparam.writesetting("socid", socid.hex())
        if hwcode is not None:
            self.info(f"HWCODE      : {hex(hwcode)}")
            retval["hwcode"] = hex(hwcode)
            self.config.hwparam.writesetting("hwcode", hex(hwcode))
        if cid is not None:
            self.info(f"CID         : {cid}")
            retval["cid"] = cid
        if self.config.chipconfig.dxcc_base is not None:
            self.info("Generating dxcc rpmbkey...")
            rpmbkey = hwc.aes_hwcrypt(btype="dxcc", mode="rpmb")
            self.info("Generating dxcc mirpmbkey...")
            mirpmbkey = hwc.aes_hwcrypt(btype="dxcc", mode="mirpmb")
            self.info("Generating dxcc fdekey...")
            fdekey = hwc.aes_hwcrypt(btype="dxcc", mode="fde")
            self.info("Generating dxcc rpmbkey2...")
            rpmb2key = hwc.aes_hwcrypt(btype="dxcc", mode="rpmb2")
            self.info("Generating dxcc km key...")
            ikey = hwc.aes_hwcrypt(btype="dxcc", mode="itrustee", data=self.config.hwparam.appid)
            # self.info("Generating dxcc platkey + provkey key...")
            # platkey, provkey = hwc.aes_hwcrypt(btype="dxcc", mode="prov")
            # self.info("Provkey     : " + provkey.hex())
            # self.info("Platkey     : " + platkey.hex())
            if mirpmbkey is not None:
                self.info(f"MIRPMB      : {mirpmbkey.hex()}")
                self.config.hwparam.writesetting("mirpmbkey", mirpmbkey.hex())
                retval["mirpmbkey"] = mirpmbkey.hex()
            if rpmbkey is not None:
                self.info(f"RPMB        : {rpmbkey.hex()}")
                self.config.hwparam.writesetting("rpmbkey", rpmbkey.hex())
                retval["rpmbkey"] = rpmbkey.hex()
            if rpmb2key is not None:
                self.info(f"RPMB2       : {rpmb2key.hex()}")
                self.config.hwparam.writesetting("rpmb2key", rpmb2key.hex())
                retval["rpmb2key"] = rpmb2key.hex()
            if fdekey is not None:
                self.info(f"FDE         : {fdekey.hex()}")
                self.config.hwparam.writesetting("fdekey", fdekey.hex())
                retval["fdekey"] = fdekey.hex()
            if ikey is not None:
                self.info(f"iTrustee    : {ikey.hex()}")
                self.config.hwparam.writesetting("kmkey", ikey.hex())
                retval["kmkey"] = ikey.hex()
            if self.config.chipconfig.prov_addr:
                provkey = self.custom_read(self.config.chipconfig.prov_addr, 16)
                self.info(f"PROV        : {provkey.hex()}")
                self.config.hwparam.writesetting("provkey", provkey.hex())
                retval["provkey"] = provkey.hex()
            hrid = self.xflash.get_hrid()
            rid = self.xflash.get_random_id()
            if hrid is not None:
                self.info(f"HRID        : {hrid.hex()}")
                self.config.hwparam.writesetting("hrid", hrid.hex())
                retval["hrid"] = hrid.hex()
            else:
                val = self.read_fuse(0xC)
                if val is not None:
                    val += self.read_fuse(0xD)
                    val += self.read_fuse(0xE)
                    val += self.read_fuse(0xF)
                    self.info(f"HRID        : {val.hex()}")
                    self.config.hwparam.writesetting("hrid", val.hex())
                    retval["hrid"] = val.hex()

            if rid is not None:
                self.info(f"RID         : {rid.hex()}")
                self.config.hwparam.writesetting("rid", rid.hex())
                retval["rid"] = rid.hex()
            if hwcode == 0x699 and self.config.chipconfig.sej_base is not None:
                mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej")
                if mtee3:
                    self.config.hwparam.writesetting("mtee3", mtee3.hex())
                    self.info(f"MTEE3       : {mtee3.hex()}")
                    retval["mtee3"] = mtee3.hex()
            return retval
        elif self.config.chipconfig.sej_base is not None:
            if os.path.exists("tee.json"):
                val = json.loads(open("tee.json", "r").read())
                self.decrypt_tee(val["filename"], bytes.fromhex(val["data"]), bytes.fromhex(val["data2"]))
            if meid == b"":
                meid = self.custom_read(0x1008ec, 16)
            if meid != b"":
                # self.config.set_meid(meid)
                self.info("Generating sej rpmbkey...")
                self.setotp(hwc)
                rpmbkey = hwc.aes_hwcrypt(mode="rpmb", data=meid, btype="sej", otp=otp)
                if rpmbkey:
                    self.info(f"RPMB        : {rpmbkey.hex()}")
                    self.config.hwparam.writesetting("rpmbkey", rpmbkey.hex())
                    retval["rpmbkey"] = rpmbkey.hex()
                self.info("Generating sej mtee...")
                mtee = hwc.aes_hwcrypt(mode="mtee", btype="sej", otp=otp)
                if mtee:
                    self.config.hwparam.writesetting("mtee", mtee.hex())
                    self.info(f"MTEE        : {mtee.hex()}")
                    retval["mtee"] = mtee.hex()
                mtee3 = hwc.aes_hwcrypt(mode="mtee3", btype="sej", otp=otp)
                if mtee3:
                    self.config.hwparam.writesetting("mtee3", mtee3.hex())
                    self.info(f"MTEE3       : {mtee3.hex()}")
                    retval["mtee3"] = mtee3.hex()
            else:
                self.info("SEJ Mode: No meid found. Are you in brom mode ?")
        if self.config.chipconfig.gcpu_base is not None:
            if self.config.hwcode in [0x335, 0x8167, 0x8168, 0x8163, 0x8176]:
                self.info("Generating gcpu mtee2 key...")
                mtee2 = hwc.aes_hwcrypt(btype="gcpu", mode="mtee")
                if mtee2 is not None:
                    self.info(f"MTEE2       : {mtee2.hex()}")
                    self.config.hwparam.writesetting("mtee2", mtee2.hex())
                    retval["mtee2"] = mtee2.hex()
        return retval
