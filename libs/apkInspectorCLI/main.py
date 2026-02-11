import argparse
import io
import os

from apkInspector import __version__ as version
from apkInspector.extract import extract_file_based_on_header_info, extract_all_files_from_central_directory
from apkInspector.headers import print_headers_of_filename, ZipEntry, show_and_save_info_of_headers
from apkInspector.helpers import save_data_to_file, pretty_print_header
from apkInspector.indicators import apk_tampering_check
from apkInspector.axml import get_manifest


def print_nested_dict(dictionary, parent_key=''):
    for key, value in dictionary.items():
        if isinstance(value, dict):
            print_nested_dict(value, parent_key=f"{parent_key}")
        else:
            full_key = f"{parent_key}->{key}" if parent_key else key
            print(f"{full_key}: {value}")


def get_apk_files(path):
    # If the path is a single file, return it as a list if it's an APK
    if os.path.isfile(path):
        return [path]

    # If the path is a directory, return a list of all APK files in it
    elif os.path.isdir(path):
        return [os.path.join(path, f) for f in os.listdir(path) if
                f.endswith('.apk') and os.path.isfile(os.path.join(path, f))]

    # If the path is invalid or not an APK file, return an empty list
    return []


def main():
    parser = argparse.ArgumentParser(description='apkInspector is a tool designed to provide detailed insights into '
                                                 'the zip structure of APK files, offering the '
                                                 'capability to extract content and decode the AndroidManifest.xml '
                                                 'file.')
    parser.add_argument('-apk', help='A single APK to inspect or a directory where multiple APKs may reside.')
    parser.add_argument('-f', '--filename', help='Filename to provide info for')
    parser.add_argument('-ll', '--list-local', action='store_true', help='List all files by name from local headers')
    parser.add_argument('-lc', '--list-central', action='store_true', help='List all files by name from central '
                                                                           'directory header')
    parser.add_argument('-la', '--list-all', action='store_true',
                        help='List all files from both central directory and local headers')
    parser.add_argument('-e', '--export', action='store_true',
                        help='Export to JSON. What you list from the other flags, will be exported')
    parser.add_argument('-x', '--extract', action='store_true', help='Attempt to extract the file specified by the -f '
                                                                     'flag')
    parser.add_argument('-xa', '--extract-all', action='store_true', help='Attempt to extract all files detected in '
                                                                          'the central directory header')
    parser.add_argument('-m', '--manifest', action='store_true',
                        help='Extract and decode the AndroidManifest.xml')
    parser.add_argument('-sm', '--specify-manifest', help='Pass an encoded AndroidManifest.xml file to be decoded')
    parser.add_argument('-a', '--analyze', action='store_true',
                        help='Check an APK for static analysis evasion techniques')
    parser.add_argument('-v', '--version', action='store_true', help='Retrieves version information')
    args = parser.parse_args()

    if args.version:
        mm = """
#                 _     _____                                 _                
#                | |   |_   _|                               | |               
#    __ _  _ __  | | __  | |   _ __   ___  _ __    ___   ___ | |_   ___   _ __ 
#   / _` || '_ \ | |/ /  | |  | '_ \ / __|| '_ \  / _ \ / __|| __| / _ \ | '__|
#  | (_| || |_) ||   <  _| |_ | | | |\__ \| |_) ||  __/| (__ | |_ | (_) || |   
#   \__,_|| .__/ |_|\_\ \___/ |_| |_||___/| .__/  \___| \___| \__| \___/ |_|   
#         | |                             | |                                  
#         |_|                             |_|                                  
"""
        print(mm)
        print(f"apkInspector Library Version: {version}")
        print(f"Copyright 2025 erev0s <projects@erev0s.com>\n")
        return
    print(f"apkInspector Version: {version}")
    print(f"Copyright 2025 erev0s <projects@erev0s.com>\n")
    if args.apk is None and args.specify_manifest is None:
        parser.error('APK file or AndroidManifest.xml file is required')
    if not (args.specify_manifest is None) != (args.apk is None):
        parser.error(
            'Please specify an apk file with flag "-apk" or an AndroidManifest.xml file with flag "-sm", but not both.')
    if args.apk:
        apk_files = get_apk_files(args.apk)
        if not apk_files:
            print(f"No APK files found at: {args.apk}")
            return
        for apk in apk_files:
            pretty_print_header(f"Results for {apk}:")
            apk_name = os.path.splitext(apk)[0]
            with open(apk, 'rb') as apk_file:
                zipentry = ZipEntry.parse(apk_file)
                if args.filename and args.extract:
                    cd_h_of_file = zipentry.get_central_directory_entry_dict(args.filename)
                    if cd_h_of_file is None:
                        print(f"It appears that file: {args.filename} is not among the entries of the central directory!")
                        return
                    local_header_of_file = zipentry.get_local_header_dict(args.filename)
                    print_headers_of_filename(cd_h_of_file, local_header_of_file)
                    extracted_data = extract_file_based_on_header_info(apk_file, local_header_of_file, cd_h_of_file)[0]
                    save_data_to_file(f"EXTRACTED_{args.filename}", extracted_data)
                elif args.filename:
                    cd_h_of_file = zipentry.get_central_directory_entry_dict(args.filename)
                    if cd_h_of_file is None:
                        print(f"It appears that file: {args.filename} is not among the entries of the central directory!")
                        return
                    local_header_of_file = zipentry.get_local_header_dict(args.filename)
                    print_headers_of_filename(cd_h_of_file, local_header_of_file)
                elif args.extract_all:
                    print(f"Number of entries: {len(zipentry.central_directory.entries)}")
                    if not extract_all_files_from_central_directory(apk_file, zipentry.to_dict()["central_directory"], zipentry.to_dict()["local_headers"], apk_name):
                        print(f"Extraction successful for: {apk_name}")
                elif args.list_local:
                    show_and_save_info_of_headers(zipentry.to_dict()["local_headers"], apk_name, "local", args.export, True)
                    print(f"Local headers list complete. Export: {args.export}")
                elif args.list_central:
                    show_and_save_info_of_headers(zipentry.to_dict()["central_directory"], apk_name, "central", args.export, True)
                    print(f"Central header list complete. Export: {args.export}")
                elif args.list_all:
                    show_and_save_info_of_headers(zipentry.to_dict()["central_directory"], apk_name, "local", args.export, True)
                    show_and_save_info_of_headers(zipentry.to_dict()["local_headers"], apk_name, "local", args.export, True)
                    print(f"Central and local headers list complete. Export: {args.export}")
                elif args.manifest:
                    cd_h_of_file = zipentry.get_central_directory_entry_dict("AndroidManifest.xml")
                    local_header_of_file = zipentry.get_local_header_dict("AndroidManifest.xml")
                    extracted_data = io.BytesIO(
                        extract_file_based_on_header_info(apk_file, local_header_of_file, cd_h_of_file)[0])
                    manifest = get_manifest(extracted_data)
                    with open("decoded_AndroidManifest.xml", "w", encoding="utf-8") as xml_file:
                        xml_file.write(manifest)
                    print("AndroidManifest was saved as: decoded_AndroidManifest.xml")
                elif args.analyze:
                    tamperings = apk_tampering_check(zipentry.zip, False)
                    if tamperings['zip tampering']:
                        print(
                            f"\nThe zip structure was tampered with using the following patterns:\n")
                        print_nested_dict(tamperings['zip tampering'])
                    else:
                        print(f"No files were detected were a tampering in the zip structure was present.")
                    if tamperings['manifest tampering']:
                        print(f"\n\nThe AndroidManifest.xml file was tampered using the following patterns:\n")
                        print_nested_dict(tamperings['manifest tampering'])
                    else:
                        print(f"The AndroidManifest.xml file does not seem to be tampered structurally.")
                else:
                    parser.print_help()
    elif args.specify_manifest:
        with open(args.specify_manifest, 'rb') as enc_manifest:
            manifest = get_manifest(io.BytesIO(enc_manifest.read()))
            with open("decoded_AndroidManifest.xml", "w", encoding="utf-8") as xml_file:
                xml_file.write(manifest)
            print("AndroidManifest was saved as: decoded_AndroidManifest.xml")


if __name__ == '__main__':
    main()
