#!/usr/bin/env python3
import argparse
import json
import logging
from pathlib import Path
import re
import sqlite3

# Set up basic configuration for logging
logging.basicConfig(level=logging.INFO,
                    format='%(levelname)s - %(message)s')

parser = argparse.ArgumentParser(
    description=(
        "To execute this script correctly, ensure the following:\n\n"
        "1. The database file must be specified using the '--db' option.\n"
        "2. The 'src_cms_files' directory must be specified using the '--source-file' option.\n"
        "3. The 'src_cms_files' directory must contain one .txt file per CMS.\n"
        "4. Each .txt file must contain specific paths for each CMS, with one path per line.\n"
    ),
    formatter_class=argparse.RawTextHelpFormatter
)

# Add arguments for database path and source files directory
parser.add_argument('--db', required=True, help="Path to the database file")
parser.add_argument('--source-file', required=True, help="Path to the 'src_cms_files' directory")

# Parse the arguments
args = parser.parse_args()

tech_list = []
file_lists = {}
src_dir = Path(args.source_file)
if not src_dir.is_dir():
    raise FileNotFoundError(f"Directory '{src_dir}' does not exist")


txt_pattern = r".*list_files_(.*)\.txt"
pattern = re.compile(txt_pattern)

with sqlite3.connect(args.db) as conn:
    cursor = conn.cursor()
    # Extract technology names from the database
    sql_tech = "SELECT DISTINCT technology FROM hash;"
    cursor.execute(sql_tech)
    for row in cursor.fetchall():
        tech = row[0].lower()
        if tech not in tech_list:
            tech_list.append(tech)

    # Create the list object of the source files
    list_files = [file for file in src_dir.glob("list_files_*.txt")]
    if not list_files:
        raise AssertionError(f"The directory '{src_dir}' is empty or no file match the pattern.")
    for file in list_files:
        match = re.match(pattern, str(file))
        if match:
            tool = match.group(1)
        else:
            logging.warning(f"Warning! Filename {file} does not match pattern {txt_pattern}.")
            continue
        file_lists[tool] = []
        # Read the file contents and extract file_names
        with open(file, "r") as file_buffer:
            for line in file_buffer:
                file_lists[tool].append(line.strip())

    # Create an empty JSON for each technology
    json_objects = {}

    # Check if each technology exists in the database
    for tech_name in file_lists.keys():
        logging.info(f"Updating {tech_name} :")
        if tech_name not in tech_list:
            logging.warning(f"Technology '{tech_name}' does not exist in the 'hash' table.")
            continue
        json_objects[tech_name] = {}
        logging.info("DONE!")

        for file_name in file_lists[tech_name]:
            cursor = conn.cursor()
            # Retrieve data from the hash table for the current file name
            cursor.execute("SELECT file, hash, versions FROM hash WHERE file = ? AND UPPER(technology) = UPPER(?)", (file_name, tech_name))
            data = cursor.fetchall()
            # Convert data to a list of dictionaries
            for row in data:
                file_name, hash_value, versions = row
                if file_name not in json_objects[tech_name]:
                    json_objects[tech_name][file_name] = {}
                versions_str = json.loads(versions)
                versions_json = json.loads(versions_str)
                json_objects[tech_name][file_name][hash_value] = versions_json["versions"]

    # Save the JSON data to a file
    for key, value in json_objects.items():
        with open(f"{key}_hash_files.json", "w") as json_file:
            json.dump(value, json_file, indent=4)
