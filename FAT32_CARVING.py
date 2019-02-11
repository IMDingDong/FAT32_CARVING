import sys
import os
from struct import *


class FAT32:
    def __init__(self, file_name):
        try:
            self.f = open(file_name, "rb")
        except IOError:
            print(" 해당 파일이 존재하지 않거나, 파일 읽기 에러가 발생했습니다!")

        self.parse_boot_record()    # Boot Record 분석
        self.parse_fs_info()        # FS Info 분석
        self.parse_fat()            # FAT #1, FAT #2 분석
        self.carving_unallocated()  # Unallocated Cluster 카빙

    # Sector 읽기
    def read_sectors(self, fd, sector, count=1):
        fd.seek(sector * 512)
        return fd.read(count * 512)

    # Boot Record 분석
    def parse_boot_record(self):
        boot_record = self.read_sectors(self.f, 0)

        boot_signature = unpack(">H", boot_record[510:512])[0]
        if not boot_signature == 0x55AA:
            print(" This is not FAT32 image file!")
            sys.exit(1)

        self.bytes_per_sector = unpack_from("<H", boot_record[11:13])[0]
        self.sector_per_cluster = boot_record[13]
        self.reserved_sector_count = unpack_from("<H", boot_record[14:16])[0]
        self.number_of_fats = boot_record[16]
        self.media = boot_record[21]
        self.hidden_sector = unpack_from("<L", boot_record[28:32])[0]
        self.total_sector_32 = unpack_from("<L", boot_record[32:36])[0]

        self.fat_size_32 = unpack_from("<L", boot_record[36:40])[0]
        self.root_dir_cluster = unpack_from("<L", boot_record[44:48])[0]
        self.file_system_info = unpack_from("<H", boot_record[48:50])[0]
        self.boot_record_backup_sec = unpack_from("<H", boot_record[50:52])[0]
        self.volume_id = unpack_from("<L", boot_record[67:71])[0]
        self.volume_label = unpack_from("11s", boot_record[71:82])[0]
        self.file_system_type = unpack_from("8s", boot_record[82:90])[0]

        self.media_type = ""
        if self.media == 0xF8:
            self.media_type = "DISK"
        elif self.media == 0xF0 or self.media == 0xF9:
            self.media_type = "FLOPPY DISK"
        elif self.media == 0xFC or self.media == 0xFD or self.media == 0xFE or self.media == 0xFF:
            self.media_type = "FLOPPY DISK"

        print("\n===================== [Boot Record] =====================\n")
        print(" [*] Bytes Per Sector: ", self.bytes_per_sector)                     # 섹터 당 바이트 수
        print(" [*] Sector Per Cluster: ", self.sector_per_cluster)                 # 클러스터 당 섹터 수
        print(" [*] Reserved Sector Count: ", self.reserved_sector_count)           # 예약된 영역 섹터 수
        print(" [*] Number Of FATs: ", self.number_of_fats)                         # FAT 테이블 수
        print(" [*] Media Type: ", hex(self.media), "(", self.media_type, ")")      # 미디어 타입
        print(" [*] Hidden Sector: ", self.hidden_sector)                           # 파티션 시작 전 섹터의 수
        print(" [*] Total Sector: ", self.total_sector_32)                          # 4byte 크기 파티션 총 섹터 수
        print(" [*] Fat Size: ", self.fat_size_32)                                  # FAT 영역이 가지는 4byte 크기 섹터 수
        print(" [*] Root Dir Cluster: ", self.root_dir_cluster)                     # 루트 디렉터리가 위치한 클러스터 값
        print(" [*] File System Info: ", self.file_system_info)                     # FS Info 영역이 위치한 섹터 번호
        print(" [*] Boot Record Backup Sec: ", self.boot_record_backup_sec)         # 백업된 부트가 위치한 섹터 번호
        print(" [*] Volume ID: ", self.volume_id)                                   # 볼륨 시리얼 번호
        print(" [*] Volume Label: ", self.volume_label.decode("utf-8"))             # 볼륨 레이블
        print(" [*] File System Type: ", self.file_system_type.decode("utf-8"))     # 파일 시스템 형식

    # FS Info 분석
    def parse_fs_info(self):
        fs_info = self.read_sectors(self.f, 1)

        lead_signature = unpack_from(">L", fs_info[0:4])[0]
        struct_signature = unpack_from(">L", fs_info[484:488])[0]
        trail_signature = unpack_from(">L", fs_info[508:512])[0]

        if lead_signature != 0x52526141 or struct_signature != 0x72724161 or trail_signature != 0x000055AA:
            print(" This is not FS Info area!")
            sys.exit(1)

        self.free_cluster_count = unpack_from("<L", fs_info[488:492])[0]
        self.next_free_cluster = unpack_from("<L", fs_info[492:496])[0]

        print("\n====================== [FS Info] ========================\n")
        print(" [*] Free Cluster Count: ", self.free_cluster_count)     # 현재 비어있는 클러스터 수
        print(" [*] Next Free Cluster: ", self.next_free_cluster)       # 현재 비어있는 클러스터 번호

    # FAT #1, FAT #2 분석
    def parse_fat(self):
        fat_area = self.read_sectors(self.f, self.reserved_sector_count)

        self.fat_media_type = unpack_from("<L", fat_area[0:4])[0]
        self.fat_partition_status = unpack_from("<L", fat_area[4:8])[0]

        print("\n====================== [FAT Area] =======================\n")
        print(" [*] Media Type: ", hex(self.fat_media_type))
        print(" [*] Partition Status: ", hex(self.fat_partition_status))

    # Unallocated Cluster -> Sector
    def find_unallocated_sector(self):
        unallocated_sector = self.reserved_sector_count + (self.fat_size_32 * 2) + ((self.next_free_cluster - 2) * self.sector_per_cluster)
        return unallocated_sector

    # Unallocated Cluster 카빙
    def carving_unallocated(self):
        unallocated_cluster_num = self.next_free_cluster
        unallocated_sector_num = self.find_unallocated_sector()

        print("\n============ [Unallocated Cluster Carving] ==============\n")

        while unallocated_cluster_num <= self.free_cluster_count:
            unallocated_space = self.read_sectors(self.f, unallocated_sector_num)
            file_signature = self.get_file_format(unallocated_space[0:16], unallocated_sector_num)
            if file_signature:
                print(" <", unallocated_cluster_num, ">\t<", file_signature, ">")
            unallocated_cluster_num += 1
            unallocated_sector_num += self.sector_per_cluster

        print("\n=========================================================\n")

    # 파일 시그니쳐와 포맷 매칭
    def get_file_format(self, signature, unallocated_sector_num):
        sig_2byte = unpack_from(">H", signature[0:2])[0]
        sig_3byte = (unpack_from(">H", signature[0:2])[0] << 8) + signature[2]
        sig_4byte = unpack_from(">L", signature[0:4])[0]
        sig_6byte = (unpack_from(">L", signature[0:4])[0] << 16) + unpack_from(">H", signature[4:6])[0]
        sig_8byte = unpack_from(">Q", signature[0:8])[0]

        sig_2byte_list = {"0x424d": "BMP"}

        sig_3byte_list = {"0x49492a": "TIF, TIFF", "0x4d4d2a": "TIF, TIFF", "0x1f8b08": "GZ", "0x1f9d90": "TAR.Z",
                "0x425a68": "BZ2, TAR, TBZ2, TB2", "0x435753": "SWF", "0x464c56": "SWF", "0x465753": "SWF",
                "0x494433": "MP3"}

        sig_4byte_list = {"0x00000100": "ICO", "0x00000200": "CUR", "0xffd8ffe0": "JPG",
                "0xffd8ffe1": "JPG", "0xffd8ffe8": "JPG", "0xd7cdc69a": "WMF", "0x01000000": "EMF", "0x000001bx": "MPG",
                "0x00010008": "IMG", "0x25504446": "PDF", "0x414c5a01": "ALZ", "0x504b0304": "ZIP", "0x52494646": "AVI",
                "0x52494646": "WAV"}

        sig_6byte_list = {"0x474946383761": "GIF", "0x474946383961": "GIF", "0x377abcaf271c": "7Z",
                "0x4a4152435300": "JAR"}

        sig_8byte_list = {"0x89504e470d0a1a0a": "PNG", "0x252150532d41646f": "EPS", "0x0000001866747970": "MP4",
                "0x504b030414000600": "DOCX, PPTX, XLSX", "0x504b030414000800": "JAR", "0xd0cf11e0a1b11ae1": "HWP"}

        if hex(sig_8byte) in sig_8byte_list.keys():
            if sig_8byte_list[hex(sig_8byte)] == "DOCX, PPTX, XLSX":
                return self.get_file_in_zip(unallocated_sector_num, 1)
            else:
                return sig_8byte_list[hex(sig_8byte)]
        elif hex(sig_6byte) in sig_6byte_list.keys():
            return sig_6byte_list[hex(sig_6byte)]
        elif hex(sig_4byte) in sig_4byte_list.keys():
            if sig_4byte_list[hex(sig_4byte)] == "ZIP":
                return self.get_file_in_zip(unallocated_sector_num)
            else:
                return sig_4byte_list[hex(sig_4byte)]
        elif hex(sig_3byte) in sig_3byte_list.keys():
            return sig_3byte_list[hex(sig_3byte)]
        elif hex(sig_2byte) in sig_2byte_list.keys():
            return sig_2byte_list[hex(sig_2byte)]
        else:
            return 0

    # ZIP 파일 내의 파일 형식 반환 및 MS Office 파싱
    def get_file_in_zip(self, unallocated_sector_num, office=0):
        file_data = self.read_sectors(self.f, unallocated_sector_num, 20)

        file_name_length = unpack("<H", file_data[26: 28])[0]
        file_name = unpack_from(str(file_name_length) + "s", file_data[30: 30 + int(file_name_length)])[0].decode("euc-kr")

        if office:
            if "word/document" in str(file_data):
                return "DOCX"
            elif "ppt/slides" in str(file_data):
                return "PPTX"
            elif "xl/worksheets" in str(file_data):
                return "XLSX"
        else:
            return "ZIP >\n \t< " + file_name + " >\t< " + os.path.splitext(file_name)[1].replace(".", "").upper()


if __name__ == "__main__":
    if len(sys.argv) is not 2:
        print(" Usage: python FAT32_CARVING.py <file_path>")
        sys.exit(1)

    filename = sys.argv[1]
    fat = FAT32(filename)
