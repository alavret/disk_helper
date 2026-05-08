import csv
import json
import logging
import logging.handlers as handlers
import os
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from typing import Optional
from urllib.parse import quote

import threading

import requests
from requests.adapters import HTTPAdapter, Retry
from dotenv import load_dotenv

DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_DISK_API_URL = "https://cloud-api.yandex.net"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"

LOG_FILE = "y360_disk.log"
MAX_RETRIES = 3
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5
USERS_PER_PAGE_FROM_API = 1000
ALL_USERS_REFRESH_IN_MINUTES = 15
MAX_THREADS = 10

NEEDED_PERMISSIONS = [
    "directory:read_users",
    "directory:read_organization",
]

SERVICE_APP_PERMISSIONS = [
    "cloud_api:disk.info",
    "cloud_api:disk.read",
]

EXIT_CODE = 1
IGNORE_SSL = False

RESOURCE_OUTPUT_FIELDNAMES = [
    "name", "path", "created", "modified", "md5", "sha256", "type", "size", "public_url", "source", "error",
]

logger = logging.getLogger(LOG_FILE)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
file_handler = handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=1024 * 1024 * 10, backupCount=5, encoding="utf-8"
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
logger.addHandler(console_handler)
logger.addHandler(file_handler)


# ─────────────────────── Rate Limiter ───────────────────────


class RateLimiter:
    def __init__(self, max_calls_per_second: int = 40):
        self.max_calls = max_calls_per_second
        self.period = 1.0
        self.calls: list[float] = []
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < self.period]
            if len(self.calls) >= self.max_calls:
                oldest_call = self.calls[0]
                sleep_time = self.period - (now - oldest_call) + 0.01
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    now = time.time()
                    self.calls = [t for t in self.calls if now - t < self.period]
            self.calls.append(now)

    def get_current_rate(self) -> int:
        with self.lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < self.period]
            return len(self.calls)


api_rate_limiter = RateLimiter(max_calls_per_second=40)

_shared_session: Optional[requests.Session] = None
_session_lock = threading.Lock()


def get_session() -> requests.Session:
    """Возвращает единый общий Session, безопасный для использования из нескольких потоков.

    Размер пула соединений согласован с MAX_THREADS: одновременно может выполняться
    не более MAX_THREADS сетевых запросов, что соответствует размеру ThreadPool-а.
    """
    global _shared_session
    if _shared_session is None:
        with _session_lock:
            if _shared_session is None:
                session = requests.Session()
                retry = Retry(
                    total=5,
                    backoff_factor=1,
                    status_forcelist=[429, 500, 502, 503, 504],
                    raise_on_status=False,
                )
                adapter = HTTPAdapter(
                    max_retries=retry,
                    pool_connections=MAX_THREADS,
                    pool_maxsize=MAX_THREADS,
                    pool_block=True,
                )
                session.mount("https://", adapter)
                session.mount("http://", adapter)
                session.verify = not IGNORE_SSL
                _shared_session = session
    return _shared_session


def close_session() -> None:
    global _shared_session
    if _shared_session is not None:
        with _session_lock:
            if _shared_session is not None:
                try:
                    _shared_session.close()
                except Exception:
                    pass
                _shared_session = None


@dataclass
class SettingParams:
    oauth_token: str
    org_id: int
    service_app_id: str
    service_app_secret: str
    service_app_status: bool
    dry_run: bool
    vd_hashes: list[str]
    disk_resource_input_file: str
    resource_output_file: str
    service_app_api_data_file: str
    users_file: str
    single_report_file: bool
    all_users: list
    all_users_get_timestamp: datetime


class TokenError(RuntimeError):
    pass


# ─────────────────────── Загрузка настроек ───────────────────────


def get_settings() -> Optional[SettingParams]:
    exit_flag = False
    oauth_token_bad = False
    settings = SettingParams(
        oauth_token=os.environ.get("OAUTH_TOKEN"),
        org_id=os.environ.get("ORG_ID"),
        service_app_id=os.environ.get("SERVICE_APP_ID"),
        service_app_secret=os.environ.get("SERVICE_APP_SECRET"),
        service_app_status=False,
        dry_run=os.environ.get("DRY_RUN", "false").lower() == "true",
        vd_hashes=[
            h.strip()
            for h in os.environ.get("VD_HASHES", "").split(",")
            if h.strip()
        ],
        disk_resource_input_file=os.environ.get(
            "DISK_RESOURCE_INPUT_FILE", "input_disk_resources.csv"
        ),
        resource_output_file=os.environ.get("RESOURCE_OUTPUT_FILE", "resource_info.csv"),
        service_app_api_data_file=os.environ.get(
            "SERVICE_APP_API_DATA_FILE", "service_app_api_data.json"
        ),
        users_file=os.environ.get("USERS_FILE", "users.csv"),
        single_report_file=os.environ.get("SINGLE_REPORT_FILE", "true").lower() == "true",
        all_users=[],
        all_users_get_timestamp=datetime.now(),
    )

    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN не установлен.")
        oauth_token_bad = True
    if not settings.org_id:
        logger.error("ORG_ID не установлен.")
        exit_flag = True
    if not settings.service_app_id:
        logger.error("SERVICE_APP_ID не установлен.")
    if not settings.service_app_secret:
        logger.error("SERVICE_APP_SECRET не установлен.")

    if not (oauth_token_bad or exit_flag):
        hard_error, result_ok = check_token_permissions(
            settings.oauth_token, settings.org_id, NEEDED_PERMISSIONS
        )
        if hard_error:
            logger.error(
                "OAUTH_TOKEN не является действительным или не имеет необходимых прав доступа"
            )
            oauth_token_bad = True
        elif not result_ok:
            print(
                "ВНИМАНИЕ: Функциональность скрипта может быть ограничена. "
                "Возможны ошибки при работе с API."
            )
            print("=" * 100)
            input("Нажмите Enter для продолжения..")

    if oauth_token_bad:
        return None

    if settings.service_app_id and settings.service_app_secret:
        check_service_app_status(settings, skip_permissions_check=True)
        if not settings.service_app_status:
            logger.error(
                "Сервисное приложение не настроено. "
                "Настройте сервисное приложение через меню настроек."
            )

    return None if exit_flag else settings


# ─────────────────────── Проверка токенов и прав ───────────────────────


def check_token_permissions(
    token: str, org_id: int, needed_permissions: list
) -> tuple[bool, bool]:
    url = "https://api360.yandex.net/whoami"
    headers = {"Authorization": f"OAuth {token}"}
    try:
        api_rate_limiter.acquire()
        response = get_session().get(url, headers=headers, verify=not IGNORE_SSL)
        if response.status_code != HTTPStatus.OK:
            logger.error(f"Невалидный токен. Статус код: {response.status_code}")
            if response.status_code == 401:
                logger.error("Токен недействителен или истек срок его действия.")
            else:
                logger.error(f"Ошибка при проверке токена: {response.text}")
            return True, False

        data = response.json()
        token_scopes = data.get("scopes", [])
        token_org_ids = data.get("orgIds", [])
        login = data.get("login", "unknown")

        logger.info(f"Проверка прав доступа для токена пользователя: {login}")
        logger.debug(f"Доступные права: {token_scopes}")
        logger.debug(f"Доступные организации: {token_org_ids}")

        if str(org_id) not in [str(org) for org in token_org_ids]:
            logger.error("=" * 100)
            logger.error(
                f"ОШИБКА: Токен не имеет доступа к организации с ID {org_id}"
            )
            logger.error(
                f"Доступные организации для этого токена: {token_org_ids}"
            )
            logger.error("=" * 100)
            return True, False

        missing_permissions = [
            permission
            for permission in needed_permissions
            if permission not in token_scopes
        ]
        if missing_permissions:
            logger.error("=" * 100)
            logger.error("ОШИБКА: У токена отсутствуют необходимые права доступа!")
            logger.error("Недостающие права:")
            for perm in missing_permissions:
                logger.error(f"  - {perm}")
            logger.error("=" * 100)
            return False, False

        logger.info("Все необходимые права доступа присутствуют")
        logger.info(f"Доступ к организации {org_id} подтвержден")
        return False, True

    except requests.exceptions.RequestException as exc:
        logger.error(f"Ошибка при выполнении запроса к API: {exc}")
        return True, False
    except json.JSONDecodeError as exc:
        logger.error(f"Ошибка при парсинге ответа от API: {exc}")
        return True, False
    except Exception as exc:
        logger.error(
            f"Неожиданная ошибка при проверке прав доступа: {type(exc).__name__}: {exc}"
        )
        return True, False


def check_token_permissions_api(token: str) -> tuple[bool, dict]:
    url = "https://api360.yandex.net/whoami"
    headers = {"Authorization": f"OAuth {token}"}
    result = None
    try:
        api_rate_limiter.acquire()
        response = get_session().get(url, headers=headers, verify=not IGNORE_SSL)
        if response.status_code != HTTPStatus.OK:
            logger.error(f"Невалидный токен. Статус код: {response.status_code}")
            if response.status_code == 401:
                logger.error("Токен недействителен или истек срок его действия.")
            else:
                logger.error(f"Ошибка при проверке токена: {response.text}")
            return False, result
        data = response.json()
        return True, data
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False, result
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка при парсинге ответа от API: {e}")
        return False, result
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при проверке прав доступа: {type(e).__name__}: {e}"
        )
        return False, result


def get_service_app_token(settings: "SettingParams", user_email: str) -> str:
    client_id = settings.service_app_id
    client_secret = settings.service_app_secret

    if not client_id or not client_secret:
        raise TokenError("SERVICE_APP_ID and SERVICE_APP_SECRET must be set")

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client_id,
        "client_secret": client_secret,
        "subject_token": user_email,
        "subject_token_type": "urn:yandex:params:oauth:token-type:email",
    }

    try:
        api_rate_limiter.acquire()
        response = get_session().post(DEFAULT_OAUTH_API_URL, data=data, timeout=30, verify=not IGNORE_SSL)
    except requests.RequestException as exc:
        raise TokenError(f"Failed to request token: {exc}") from exc

    if not response.ok:
        raise TokenError(
            f"Token request failed for {user_email}: {response.status_code} {response.text}"
        )

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise TokenError(f"No access_token in response for {user_email}: {payload}")
    return access_token


# ─────────────────────── Пользователи ───────────────────────


def read_users_csv(path: str) -> list[str]:
    if not os.path.exists(path):
        logger.error(f"Файл пользователей не найден: {path}")
        return []

    data_list: list[str] = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            value = row[0].strip()
            if not value:
                continue
            data_list.append(value)
    return data_list


def get_all_api360_users_from_api(settings: "SettingParams") -> list[dict]:
    logger.info("Получение всех пользователей организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    users = []
    current_page = 1
    last_page = 1
    session = get_session()
    while current_page <= last_page:
        params = {"page": current_page, "perPage": USERS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                api_rate_limiter.acquire()
                response = session.get(url, params=params, headers=headers, verify=not IGNORE_SSL)
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(
                        f"Ошибка при GET запросе url - {url}: "
                        f"{response.status_code}. {response.text}"
                    )
                    if retries < MAX_RETRIES:
                        logger.error(
                            f"Повторная попытка ({retries + 1}/{MAX_RETRIES})"
                        )
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        return []
                else:
                    for user in response.json().get("users", []):
                        if not user.get("isRobot"):
                            users.append(user)
                    current_page += 1
                    last_page = response.json().get("pages", current_page)
                    break
        except requests.exceptions.RequestException as exc:
            logger.error(f"RequestException: {exc}")
            return []

    return users


def get_all_api360_users(
    settings: "SettingParams", force: bool = False
) -> list[dict]:
    if not force:
        logger.info("Получение списка пользователей организации из кэша...")

    if (
        not settings.all_users
        or force
        or (datetime.now() - settings.all_users_get_timestamp).total_seconds()
        > ALL_USERS_REFRESH_IN_MINUTES * 60
    ):
        logger.info("Получение списка пользователей организации из API...")
        settings.all_users = get_all_api360_users_from_api(settings)
        settings.all_users_get_timestamp = datetime.now()
    return settings.all_users


def find_users_prompt(
    settings: "SettingParams", answer: str = ""
) -> tuple[list[dict], bool, bool, bool]:
    break_flag = False
    double_users_flag = False
    users_to_add: list[dict] = []
    all_users_flag = False
    print(
        "\nВведите пользователей в Яндекс 360 (алиасы, uid, фамилия), "
        "разделённые запятой или пробелом."
    )
    print("* - все пользователи, ! - загрузить из файла, Enter - выход в меню.\n")
    if not answer:
        answer = input("Пользователи: ")

    if not answer.strip():
        break_flag = True
        return users_to_add, break_flag, double_users_flag, all_users_flag

    users = get_all_api360_users(settings)
    if not users:
        logger.info("Пользователи в организации Яндекс 360 не найдены.")
        break_flag = True
        return users_to_add, break_flag, double_users_flag, all_users_flag

    if answer.strip() == "*":
        all_users_flag = True
        return users, break_flag, double_users_flag, all_users_flag

    search_users: list[str] = []
    if answer.strip() == "!":
        search_users = read_users_csv(settings.users_file)
        if not search_users:
            logger.info(f"Пользователи не найдены в файле {settings.users_file}.")
            break_flag = True
            return users_to_add, break_flag, double_users_flag, all_users_flag

    if not search_users:
        pattern = r"[;,\s]+"
        search_users = re.split(pattern, answer)

    for searched in search_users:
        if not searched:
            continue
        if "@" in searched.strip():
            searched = searched.split("@")[0]
        found_flag = False
        if all(char.isdigit() for char in searched.strip()):
            for user in users:
                if user.get("id") == searched.strip():
                    users_to_add.append(user)
                    found_flag = True
                    break
        else:
            found_last_name_user = []
            for user in users:
                aliases_lower_case = [r.lower() for r in user.get("aliases", [])]
                if user.get("nickname", "").lower() == searched.lower().strip() or (
                    searched.lower().strip() in aliases_lower_case
                ):
                    users_to_add.append(user)
                    found_flag = True
                    break
                if (
                    user.get("name", {}).get("last", "").lower()
                    == searched.lower().strip()
                ):
                    found_last_name_user.append(user)
            if not found_flag and found_last_name_user:
                if len(found_last_name_user) == 1:
                    users_to_add.append(found_last_name_user[0])
                    found_flag = True
                else:
                    logger.error(
                        f"Пользователь {searched} найден более одного раза:"
                    )
                    for user in found_last_name_user:
                        logger.error(
                            f" - фамилия {user.get('name', {}).get('last')}, "
                            f"nickname {user.get('nickname')} "
                            f"({user.get('id')}, {user.get('position')})"
                        )
                    logger.error("Уточните параметры поиска.")
                    double_users_flag = True
                    break

        if not found_flag:
            logger.error(
                f"Пользователь {searched} не найден в организации Яндекс 360."
            )

    return users_to_add, break_flag, double_users_flag, all_users_flag


# ─────────────────────── Сервисные приложения ───────────────────────


def activate_service_applications(settings: "SettingParams") -> bool:
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications/activate"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().post(url, headers=headers, verify=not IGNORE_SSL)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при активации сервисных приложений: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Сервисные приложения активированы.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при активации сервисных приложений: "
            f"{type(e).__name__}: {e}"
        )
        return False


def get_service_applications(settings: "SettingParams") -> tuple:
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"GET URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().get(url, headers=headers, verify=not IGNORE_SSL)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                if response.json()["message"] == "feature is not active":
                    logger.error(
                        "Функционал сервисных приложений не активирован в организации."
                    )
                    return None, response.json()["message"]
                if response.json()["message"] == "Not an owner":
                    logger.error(
                        "Токен в параметре OAUTH_TOKEN_ARG выписан НЕ ВЛАДЕЛЬЦЕМ "
                        "организации (с учеткой в @yandex.ru)."
                    )
                    logger.error(
                        "Невозможно настроить сервисное приложение. "
                        "Получите правильный токен и повторите попытку."
                    )
                    return None, response.json()["message"]
                logger.error(
                    f"Ошибка при получении списка сервисных приложений: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return None, response.json().get("message", "")
            else:
                applications = response.json().get("applications", [])
                logger.info(f"Получен список {len(applications)} сервисных приложений.")
                if not check_service_app_response(settings, response):
                    logger.debug(
                        f"Сервисное приложение {settings.service_app_id} не найдено "
                        f"в списке сервисных приложений организации или не имеет "
                        f"необходимых прав доступа."
                    )
                    return applications, (
                        f"Сервисное приложение {settings.service_app_id} не найдено "
                        f"в списке сервисных приложений организации или не имеет "
                        f"необходимых прав доступа."
                    )
                return applications, None
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return None, f"{e.__class__.__name__}: {e}"
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка при парсинге ответа от API: {e}")
        return None, f"{e.__class__.__name__}: {e}"
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при получении сервисных приложений: "
            f"{type(e).__name__}: {e}"
        )
        return None, f"{e.__class__.__name__}: {e}"


def check_service_app_response(
    settings: "SettingParams", response: requests.Response
) -> bool:
    if len(response.json().get("applications", [])) == 0:
        return False

    found_app = False
    for app in response.json().get("applications", []):
        if app.get("id") == settings.service_app_id:
            found_app = True
            scopes = app.get("scopes", [])
            for perm in SERVICE_APP_PERMISSIONS:
                if perm not in scopes:
                    return False
    if not found_app:
        return False
    return True


def merge_service_app_permissions(
    existing_permissions: list, required_permissions: list
) -> list:
    merged_permissions = list(existing_permissions) if existing_permissions else []
    existing_set = set(merged_permissions)
    for permission in required_permissions:
        if permission not in existing_set:
            merged_permissions.append(permission)
            existing_set.add(permission)
    return merged_permissions


def setup_service_application(settings: "SettingParams") -> bool:
    if not settings.service_app_id:
        logger.error(
            "Параметр SERVICE_APP_ID не задан. "
            "Невозможно настроить сервисное приложение."
        )
        return False

    if not settings.service_app_secret:
        logger.error(
            "Параметр SERVICE_APP_SECRET не задан. "
            "Невозможно проверить статус сервисного приложения."
        )
        return False

    CHECK_TOKEN_PERMISSIONS = [
        "ya360_security:service_applications_read",
        "ya360_security:service_applications_write",
    ]
    success, data = check_token_permissions_api(settings.oauth_token)
    if not success:
        logger.error(
            "Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки."
        )
        return False
    token_scopes = data.get("scopes", [])
    for permission in CHECK_TOKEN_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(
                f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа "
                f"({', '.join(CHECK_TOKEN_PERMISSIONS)}) для модификации списка "
                f"сервисных приложений. Проверьте настройки и повторите попытку."
            )
            return False

    applications, error_message = get_service_applications(settings)
    if applications is None:
        if error_message == "feature is not active":
            result = activate_service_applications(settings)
            if not result:
                logger.error(
                    "Не удалось активировать функционал сервисных приложений. "
                    "Проверьте настройки и повторите попытку."
                )
                return False
            applications, error_message = get_service_applications(settings)
            if applications is None:
                return False
        else:
            return False

    if len(applications) == 0:
        logger.error(
            "Список сервисных приложений пуст. "
            "Невозможно настроить сервисное приложение."
        )
        return False

    client_id = settings.service_app_id
    required_permissions = SERVICE_APP_PERMISSIONS
    changed = False
    found = False

    if applications:
        for app in applications:
            if app.get("id") == client_id:
                found = True
                logger.info(
                    f"Сервисное приложение с ID {client_id} найдено в списке "
                    f"сервисных приложений организации."
                )
                current_permissions = app.get("scopes", [])
                merged_permissions = merge_service_app_permissions(
                    current_permissions, required_permissions
                )
                if merged_permissions != current_permissions:
                    app["scopes"] = merged_permissions
                    changed = True
                    logger.info(
                        "Добавлены недостающие разрешения для сервисного приложения."
                    )
                else:
                    logger.info(
                        "Сервисное приложение уже содержит все необходимые разрешения. "
                        "Выполняем проверку валидности токена сервисного приложения..."
                    )
                    check_service_app_status(settings)
                break
    else:
        applications = []

    if not found:
        applications.append({"id": client_id, "scopes": list(required_permissions)})
        changed = True
        logger.info(
            f"Сервисное приложение с ID {client_id} не найдено в списке "
            f"сервисных приложений организации. Создаем новое."
        )

    if not changed:
        return True

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    payload = {"applications": applications}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().post(url, headers=headers, json=payload, verify=not IGNORE_SSL)
            logger.debug(
                f'X-Request-Id: {response.headers.get("X-Request-Id","")}'
            )
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при обновлении сервисных приложений: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                if not check_service_app_response(settings, response):
                    logger.error(
                        "Не удалось настроить сервисное приложение. "
                        "Проверьте настройки и повторите попытку."
                    )
                    return False
                logger.info(
                    f"Список сервисных приложений успешно обновлен "
                    f"(Client ID - {client_id})."
                )
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при обновлении сервисных приложений: "
            f"{type(e).__name__}: {e}"
        )
        return False

    logger.info(
        f"Сервисное приложение с ID {client_id} успешно настроено. "
        f"Выполняем проверку валидности токена сервисного приложения..."
    )
    check_service_app_status(settings)
    return True


def delete_service_applications_list(settings: "SettingParams") -> bool:
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"DELETE URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().delete(url, headers=headers, verify=not IGNORE_SSL)
            logger.debug(
                f'X-Request-Id: {response.headers.get("X-Request-Id","")}'
            )
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при очистке списка сервисных приложений: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Список сервисных приложений успешно очищен.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при очистке списка сервисных приложений: "
            f"{type(e).__name__}: {e}"
        )
        return False


def deactivate_service_applications(settings: "SettingParams") -> bool:
    url = (
        f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}"
        f"/service_applications/deactivate"
    )
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().post(url, headers=headers, verify=not IGNORE_SSL)
            logger.debug(
                f'X-Request-Id: {response.headers.get("X-Request-Id","")}'
            )
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при деактивации сервисных приложений: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Сервисные приложения деактивированы.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при деактивации сервисных приложений: "
            f"{type(e).__name__}: {e}"
        )
        return False


def delete_service_application_from_list(settings: "SettingParams") -> bool:
    if not settings.service_app_id:
        logger.error(
            "Параметр SERVICE_APP_ID не задан. "
            "Невозможно удалить сервисное приложение."
        )
        return False

    CHECK_TOKEN_PERMISSIONS = [
        "ya360_security:service_applications_read",
        "ya360_security:service_applications_write",
    ]
    success, data = check_token_permissions_api(settings.oauth_token)
    if not success:
        logger.error(
            "Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки."
        )
        return False
    token_scopes = data.get("scopes", [])
    for permission in CHECK_TOKEN_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(
                f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа "
                f"({', '.join(CHECK_TOKEN_PERMISSIONS)}) для модификации списка "
                f"сервисных приложений. Проверьте настройки и повторите попытку."
            )
            return False

    applications, error_message = get_service_applications(settings)
    if applications is None:
        settings.service_app_status = False
        if error_message == "feature is not active":
            return True
        else:
            return False

    if len(applications) == 0:
        logger.info("Список сервисных приложений пуст. Нечего удалять.")
        settings.service_app_status = False
        return True

    client_id = settings.service_app_id
    found = [app for app in applications if app.get("id") == client_id]
    if not found:
        logger.info(
            f"Сервисное приложение с ID {client_id} не найдено в списке "
            f"сервисных приложений организации."
        )
        settings.service_app_status = False
        return False

    new_applications = [app for app in applications if app.get("id") != client_id]
    if not new_applications:
        logger.info(
            "В списке осталось только удаляемое приложение. "
            "Очищаем список и деактивируем функцию."
        )
        if not delete_service_applications_list(settings):
            return False
        settings.service_app_status = False
        return deactivate_service_applications(settings)

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    payload = {"applications": new_applications}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().post(url, headers=headers, json=payload, verify=not IGNORE_SSL)
            logger.debug(
                f'X-Request-Id: {response.headers.get("X-Request-Id","")}'
            )
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при обновлении списка сервисных приложений: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info(
                    f"Сервисное приложение с ID {client_id} удалено из списка "
                    f"сервисных приложений организации."
                )
                settings.service_app_status = False
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при обновлении списка сервисных приложений: "
            f"{type(e).__name__}: {e}"
        )
        return False


def check_service_app_status(
    settings: "SettingParams", skip_permissions_check: bool = False
) -> bool:
    if not settings.service_app_id:
        logger.error(
            "Параметр SERVICE_APP_ID не задан. "
            "Невозможно проверить статус сервисного приложения."
        )
        return False
    if not settings.service_app_secret:
        logger.error(
            "Параметр SERVICE_APP_SECRET не задан. "
            "Невозможно проверить статус сервисного приложения."
        )
        return False

    if not skip_permissions_check:
        CHECK_TOKEN_PERMISSIONS = ["ya360_security:service_applications_read"]
        success, data = check_token_permissions_api(settings.oauth_token)
        if not success:
            logger.error(
                "Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). "
                "Проверьте настройки."
            )
            return False
        token_scopes = data.get("scopes", [])
        for permission in CHECK_TOKEN_PERMISSIONS:
            if permission not in token_scopes:
                logger.error(
                    f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа "
                    f"({', '.join(CHECK_TOKEN_PERMISSIONS)}) для чтения списка "
                    f"сервисных приложений. Проверьте настройки и повторите попытку."
                )
                return False

        applications, error_message = get_service_applications(settings)
        if applications is None:
            settings.service_app_status = False
            return False

        if len(applications) == 0:
            logger.info(
                "Список сервисных приложений пуст. "
                "Невозможно проверить статус сервисного приложения."
            )
            settings.service_app_status = False
            return False

        if error_message:
            logger.error(error_message)
            settings.service_app_status = False
            return False

    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    users = []
    params = {"page": 1, "perPage": USERS_PER_PAGE_FROM_API}
    try:
        retries = 1
        while True:
            logger.debug(f"GET URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().get(url, headers=headers, params=params, verify=not IGNORE_SSL)
            logger.debug(
                f"x-request-id: {response.headers.get('x-request-id','')}"
            )
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"!!! ОШИБКА !!! при GET запросе url - {url}: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                for user in response.json()["users"]:
                    if not user.get("isRobot") and int(user["id"]) >= 1130000000000000:
                        users.append(user)
                logger.debug(
                    f"Загружено {len(response.json()['users'])} пользователей."
                )
                break
    except requests.exceptions.RequestException as e:
        logger.error(
            f"!!! ERROR !!! {type(e).__name__} at line "
            f"{e.__traceback__.tb_lineno} of {__file__}: {e}"
        )
        has_errors = True

    if has_errors:
        return False

    if len(users) == 0:
        logger.error(
            "Не найдено ни одного пользователя в организации. "
            "Невозможно проверить статус сервисного приложения."
        )
        return False

    user = None
    for u in users:
        if u["isEnabled"]:
            user = u
            break
    if not user:
        logger.error(
            "Не найдено ни одного активного пользователя в организации. "
            "Невозможно проверить статус сервисного приложения."
        )
        return False

    user_email = user.get("email", "")
    try:
        user_token = get_service_app_token(settings, user_email)
    except Exception:
        logger.error("Не удалось получить тестовый токен пользователя.")
        settings.service_app_status = False
        return False

    success, data = check_token_permissions_api(user_token)
    if not success:
        logger.error(
            "Не удалось проверить токен пользователя. "
            "Проверьте настройки сервисного приложения."
        )
        return False

    token_scopes = data.get("scopes", [])
    token_org_ids = data.get("orgIds", [])
    login = data.get("login", "unknown")

    logger.debug(f"Проверка прав доступа для токена пользователя: {login}")
    logger.debug(f"Доступные права: {token_scopes}")
    logger.debug(f"Доступные организации: {token_org_ids}")

    for permission in SERVICE_APP_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(
                f"В токене пользователя отсутствуют необходимые права доступа "
                f"{', '.join(SERVICE_APP_PERMISSIONS)}. Проверьте настройки "
                f"сервисного приложения и повторите попытку."
            )
            settings.service_app_status = False
            return False

    logger.info("Сервисное приложение настроено корректно.")
    settings.service_app_status = True
    return True


def export_service_applications_api_data(settings: "SettingParams") -> bool:
    if not settings.service_app_api_data_file:
        logger.error("SERVICE_APP_API_DATA_FILE не задан. Невозможно сохранить данные.")
        return False

    applications, error_message = get_service_applications(settings)
    if applications is None:
        logger.error(
            "Не удалось получить данные API сервисных приложений. "
            "Проверьте настройки и повторите попытку."
        )
        return False
    if not applications:
        logger.error(
            "Список сервисных приложений пуст. Невозможно выгрузить данные."
        )

    data = {"applications": applications}
    target_dir = os.path.dirname(settings.service_app_api_data_file)
    if target_dir and not os.path.exists(target_dir):
        os.makedirs(target_dir)
    base_name = os.path.basename(settings.service_app_api_data_file)
    name_root, ext = os.path.splitext(base_name)
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    output_filename = f"{name_root}_{timestamp}{ext}"
    output_path = (
        os.path.join(target_dir, output_filename) if target_dir else output_filename
    )
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        logger.info(
            f"Данные API сервисных приложений сохранены в файл: {output_path} "
            f"(кол-во приложений: {len(applications)})"
        )
    return True


def import_service_applications_api_data(settings: "SettingParams") -> bool:
    if not settings.service_app_api_data_file:
        logger.error(
            "SERVICE_APP_API_DATA_FILE не задан. Невозможно загрузить данные."
        )
        return False

    if not os.path.exists(settings.service_app_api_data_file):
        logger.error(f"Файл не найден: {settings.service_app_api_data_file}")
        return False

    try:
        with open(settings.service_app_api_data_file, "r", encoding="utf-8") as file:
            raw_content = file.read()
    except OSError as e:
        logger.error(
            f"Ошибка при чтении файла {settings.service_app_api_data_file}: {e}"
        )
        return False

    if not raw_content.strip():
        logger.error(f"Файл пустой: {settings.service_app_api_data_file}")
        return False

    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as e:
        logger.error(
            f"Некорректный JSON в файле {settings.service_app_api_data_file}: {e}"
        )
        return False

    if not isinstance(payload, dict) or "applications" not in payload:
        logger.error("Некорректный формат данных: отсутствует ключ applications.")
        return False

    if not isinstance(payload["applications"], list):
        logger.error("Некорректный формат данных: applications должен быть списком.")
        return False

    CHECK_TOKEN_PERMISSIONS = [
        "ya360_security:service_applications_read",
        "ya360_security:service_applications_write",
    ]
    success, data = check_token_permissions_api(settings.oauth_token)
    if not success:
        logger.error(
            "Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки."
        )
        return False
    token_scopes = data.get("scopes", [])
    for permission in CHECK_TOKEN_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(
                f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа "
                f"({', '.join(CHECK_TOKEN_PERMISSIONS)}) для модификации списка "
                f"сервисных приложений. Проверьте настройки и повторите попытку."
            )
            return False

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    activated = False
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            api_rate_limiter.acquire()
            response = get_session().post(url, headers=headers, json=payload, verify=not IGNORE_SSL)
            logger.debug(
                f'X-Request-Id: {response.headers.get("X-Request-Id","")}'
            )
            if response.status_code != HTTPStatus.OK.value:
                if response.json()["message"] == "feature is not active":
                    if not activated:
                        logger.error(
                            "Функционал сервисных приложений не активирован "
                            "в организации. Выполняем активацию..."
                        )
                        result = activate_service_applications(settings)
                        if not result:
                            logger.error(
                                "Не удалось активировать функционал сервисных "
                                "приложений. Проверьте настройки и повторите попытку."
                            )
                            return False
                        activated = True
                        time.sleep(1)
                        continue
                    else:
                        logger.error(
                            "Функционал сервисных приложений не активирован "
                            "в организации. Проверьте настройки и повторите попытку."
                        )
                        return False
                if response.json()["message"] == "Not an owner":
                    logger.error(
                        "Токен в параметре OAUTH_TOKEN_ARG выписан НЕ ВЛАДЕЛЬЦЕМ "
                        "организации (с учеткой в @yandex.ru)."
                    )
                    logger.error(
                        "Невозможно настроить сервисное приложение. "
                        "Получите правильный токен и повторите попытку."
                    )
                    return False
                logger.error(
                    f"Ошибка при загрузке сервисных приложений из файла: "
                    f"{response.status_code}. Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                app_count = len(payload.get("applications", []))
                logger.info(
                    f"Данные сервисных приложений успешно загружены из файла "
                    f"(кол-во приложений: {app_count})."
                )
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(
            f"Неожиданная ошибка при загрузке сервисных приложений из файла: "
            f"{type(e).__name__}: {e}"
        )
        return False


# ─────────────────────── Метаданные ресурсов ───────────────────────


def build_vd_path(vd_hash: str, full_path: str) -> str:
    """Преобразует путь из входного файла (с <Root> и обратными слешами) в формат API Диска."""
    cleaned = full_path
    if cleaned.lower().startswith("<root>"):
        cleaned = cleaned[len("<root>"):]
    cleaned = cleaned.replace("\\", "/")
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    return f"vd:{vd_hash}:disk:/{cleaned}"


def normalize_vd_path_from_api(api_path: str) -> str:
    """Преобразует путь общего диска, возвращённый API в поле "path", в формат,
    ожидаемый API в параметре ?path= при последующих запросах.

    API в ответе отдаёт путь вида ``vd:/HASH/disk/<rest>``, а в запросе ожидает
    ``vd:HASH:disk:/<rest>``. Если путь не похож на формат VD-диска, возвращается
    исходное значение без изменений.

    Пример:
        ``vd:/6DE3vqG1oY9A3w/disk/Тестируем шаринг 01``
            → ``vd:6DE3vqG1oY9A3w:disk:/Тестируем шаринг 01``
    """
    if not api_path or not api_path.startswith("vd:/"):
        return api_path
    rest = api_path[len("vd:/"):]
    parts = rest.split("/", 2)
    if len(parts) < 2 or parts[1] != "disk":
        return api_path
    vd_hash = parts[0]
    tail = parts[2] if len(parts) > 2 else ""
    return f"vd:{vd_hash}:disk:/{tail}"


def build_personal_disk_path(full_path: str) -> str:
    """Преобразует путь из входного файла (с <Root> и обратными слешами) в формат API личного Диска."""
    cleaned = full_path
    if cleaned.lower().startswith("<root>"):
        cleaned = cleaned[len("<root>"):]
    cleaned = cleaned.replace("\\", "/")
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    return f"disk:/{cleaned}"


def get_resource_metadata(
    token: str, vd_path: str
) -> tuple[Optional[dict], Optional[str]]:
    """Запрашивает метаданные ресурса на Общем Диске через API."""
    url = f"{DEFAULT_DISK_API_URL}/v1/disk/virtual-disks/resources"
    headers = {"Authorization": f"OAuth {token}"}
    params = {"path": vd_path}

    retries = 0
    while True:
        try:
            logger.debug(f"GET {url} path={vd_path}")
            api_rate_limiter.acquire()
            response = get_session().get(url, headers=headers, params=params, timeout=30, verify=not IGNORE_SSL)
            logger.debug(
                f"x-request-id: {response.headers.get('x-request-id', '')}"
            )

            if response.status_code == HTTPStatus.OK:
                return response.json(), None
            elif response.status_code == HTTPStatus.NOT_FOUND:
                return None, f"404 Ресурс не найден: {vd_path}"
            elif response.status_code == HTTPStatus.FORBIDDEN:
                return None, f"403 Доступ запрещен: {vd_path}"
            elif response.status_code == HTTPStatus.UNAUTHORIZED:
                return None, f"401 Не авторизован"
            else:
                error_msg = (
                    f"HTTP {response.status_code}: {response.text}"
                )
                if retries < MAX_RETRIES:
                    retries += 1
                    logger.warning(
                        f"Повторная попытка ({retries}/{MAX_RETRIES}) для {vd_path}"
                    )
                    time.sleep(RETRIES_DELAY_SEC * retries)
                else:
                    return None, error_msg

        except requests.exceptions.RequestException as e:
            error_msg = f"Ошибка запроса: {e}"
            if retries < MAX_RETRIES:
                retries += 1
                logger.warning(
                    f"Повторная попытка ({retries}/{MAX_RETRIES}) для {vd_path}"
                )
                time.sleep(RETRIES_DELAY_SEC * retries)
            else:
                return None, error_msg


def get_personal_resource_metadata(
    token: str, disk_path: str
) -> tuple[Optional[dict], Optional[str]]:
    """Запрашивает метаданные ресурса на личном Диске пользователя через API."""
    url = f"{DEFAULT_DISK_API_URL}/v1/disk/resources"
    headers = {"Authorization": f"OAuth {token}"}
    params = {"path": disk_path}

    retries = 0
    while True:
        try:
            logger.debug(f"GET {url} path={disk_path}")
            logger.debug(f"OAuth {token}")
            api_rate_limiter.acquire()
            response = get_session().get(url, headers=headers, params=params, timeout=30, verify=not IGNORE_SSL)
            logger.debug(
                f"x-request-id: {response.headers.get('x-request-id', '')}"
            )

            if response.status_code == HTTPStatus.OK:
                return response.json(), None
            elif response.status_code == HTTPStatus.NOT_FOUND:
                return None, f"404 Ресурс не найден: {disk_path}"
            elif response.status_code == HTTPStatus.FORBIDDEN:
                return None, f"403 Доступ запрещен: {disk_path}"
            elif response.status_code == HTTPStatus.UNAUTHORIZED:
                return None, "401 Не авторизован"
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                if retries < MAX_RETRIES:
                    retries += 1
                    logger.warning(
                        f"Повторная попытка ({retries}/{MAX_RETRIES}) для {disk_path}"
                    )
                    time.sleep(RETRIES_DELAY_SEC * retries)
                else:
                    return None, error_msg

        except requests.exceptions.RequestException as e:
            error_msg = f"Ошибка запроса: {e}"
            if retries < MAX_RETRIES:
                retries += 1
                logger.warning(
                    f"Повторная попытка ({retries}/{MAX_RETRIES}) для {disk_path}"
                )
                time.sleep(RETRIES_DELAY_SEC * retries)
            else:
                return None, error_msg


DIR_LISTING_LIMIT = 20


def list_directory_page(
    token: str, dir_path: str, limit: int = DIR_LISTING_LIMIT, offset: int = 0
) -> tuple[Optional[dict], Optional[str]]:
    url = f"{DEFAULT_DISK_API_URL}/v1/disk/resources"
    headers = {"Authorization": f"OAuth {token}"}
    params = {"path": dir_path, "limit": limit, "offset": offset}

    retries = 0
    while True:
        try:
            logger.debug(f"GET {url} path={dir_path} limit={limit} offset={offset}")
            api_rate_limiter.acquire()
            response = get_session().get(url, headers=headers, params=params, timeout=30, verify=not IGNORE_SSL)
            logger.debug(
                f"x-request-id: {response.headers.get('x-request-id', '')}"
            )

            if response.status_code == HTTPStatus.OK:
                return response.json(), None
            elif response.status_code == HTTPStatus.NOT_FOUND:
                return None, f"404 Каталог не найден: {dir_path}"
            elif response.status_code == HTTPStatus.FORBIDDEN:
                return None, f"403 Доступ запрещен: {dir_path}"
            elif response.status_code == HTTPStatus.UNAUTHORIZED:
                return None, "401 Не авторизован"
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                if retries < MAX_RETRIES:
                    retries += 1
                    logger.warning(
                        f"Повторная попытка ({retries}/{MAX_RETRIES}) "
                        f"для листинга {dir_path}"
                    )
                    time.sleep(RETRIES_DELAY_SEC * retries)
                else:
                    return None, error_msg

        except requests.exceptions.RequestException as e:
            error_msg = f"Ошибка запроса: {e}"
            if retries < MAX_RETRIES:
                retries += 1
                logger.warning(
                    f"Повторная попытка ({retries}/{MAX_RETRIES}) "
                    f"для листинга {dir_path}"
                )
                time.sleep(RETRIES_DELAY_SEC * retries)
            else:
                return None, error_msg


def fetch_full_directory_listing(
    token: str, dir_path: str
) -> tuple[Optional[list[dict]], Optional[str]]:
    all_items: list[dict] = []
    offset = 0
    while True:
        data, error = list_directory_page(token, dir_path, DIR_LISTING_LIMIT, offset)
        if error:
            return None, error

        embedded = data.get("_embedded")
        if not embedded:
            return all_items, None

        items = embedded.get("items", [])
        all_items.extend(items)
        total = embedded.get("total", 0)

        if len(all_items) >= total:
            return all_items, None

        offset += DIR_LISTING_LIMIT
        time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)


def list_vd_directory_page(
    token: str, vd_dir_path: str, limit: int = DIR_LISTING_LIMIT, offset: int = 0
) -> tuple[Optional[dict], Optional[str]]:
    url = f"{DEFAULT_DISK_API_URL}/v1/disk/virtual-disks/resources"
    headers = {"Authorization": f"OAuth {token}"}
    params = {"path": vd_dir_path, "limit": limit, "offset": offset}

    retries = 0
    while True:
        try:
            logger.debug(
                f"GET {url} path={vd_dir_path} limit={limit} offset={offset}"
            )
            api_rate_limiter.acquire()
            response = get_session().get(url, headers=headers, params=params, timeout=30, verify=not IGNORE_SSL)
            logger.debug(
                f"x-request-id: {response.headers.get('x-request-id', '')}"
            )

            if response.status_code == HTTPStatus.OK:
                return response.json(), None
            elif response.status_code == HTTPStatus.NOT_FOUND:
                return None, f"404 Каталог не найден: {vd_dir_path}"
            elif response.status_code == HTTPStatus.FORBIDDEN:
                return None, f"403 Доступ запрещен: {vd_dir_path}"
            elif response.status_code == HTTPStatus.UNAUTHORIZED:
                return None, "401 Не авторизован"
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                if retries < MAX_RETRIES:
                    retries += 1
                    logger.warning(
                        f"Повторная попытка ({retries}/{MAX_RETRIES}) "
                        f"для листинга {vd_dir_path}"
                    )
                    time.sleep(RETRIES_DELAY_SEC * retries)
                else:
                    return None, error_msg

        except requests.exceptions.RequestException as e:
            error_msg = f"Ошибка запроса: {e}"
            if retries < MAX_RETRIES:
                retries += 1
                logger.warning(
                    f"Повторная попытка ({retries}/{MAX_RETRIES}) "
                    f"для листинга {vd_dir_path}"
                )
                time.sleep(RETRIES_DELAY_SEC * retries)
            else:
                return None, error_msg


def fetch_full_vd_directory_listing(
    token: str, vd_dir_path: str
) -> tuple[Optional[list[dict]], Optional[str]]:
    all_items: list[dict] = []
    offset = 0
    while True:
        data, error = list_vd_directory_page(
            token, vd_dir_path, DIR_LISTING_LIMIT, offset
        )
        if error:
            return None, error

        embedded = data.get("_embedded")
        if not embedded:
            return all_items, None

        items = embedded.get("items", [])
        all_items.extend(items)
        total = embedded.get("total", 0)

        if len(all_items) >= total:
            return all_items, None

        offset += DIR_LISTING_LIMIT
        time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)


def _parse_path_components(original_path: str) -> list[str]:
    cleaned = original_path
    if cleaned.lower().startswith("<root>"):
        cleaned = cleaned[len("<root>"):]
    cleaned = cleaned.replace("\\", "/")
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    if cleaned.endswith("/"):
        cleaned = cleaned[:-1]
    return [c for c in cleaned.split("/") if c]


def _find_in_items(items: list[dict], component: str) -> list[dict]:
    return [
        item for item in items
        if item.get("name", "").lower() == component.lower()
    ]


def resolve_case_insensitive_path(
    token: str, original_path: str, dir_cache: dict
) -> tuple[Optional[str], Optional[str]]:
    """Разрешает путь с учётом регистра, обходя дерево каталогов уровень за уровнем.

    Returns:
        (resolved_disk_path, error_message)
        resolved_disk_path is None when not found or on error.
        error_message is non-None for ambiguity / API errors.
    """
    components = _parse_path_components(original_path)
    if not components:
        return None, "Пустой путь"

    current_dir = "disk:/"
    resolved_parts: list[str] = []

    for component in components:
        cache_entry = dir_cache.get(current_dir)

        if cache_entry is not None:
            matches = _find_in_items(cache_entry["items"], component)
            if len(matches) == 1:
                real_name = matches[0]["name"]
                resolved_parts.append(real_name)
                current_dir = "disk:/" + "/".join(resolved_parts)
                continue
            if len(matches) > 1:
                return None, (
                    f"Неоднозначность: найдено {len(matches)} ресурсов "
                    f"с именем «{component}» (без учёта регистра) "
                    f"в каталоге {current_dir}"
                )
            if cache_entry.get("complete"):
                return None, None

        items, error = fetch_full_directory_listing(token, current_dir)
        if error:
            if "404" in error:
                return None, None
            return None, error

        dir_cache[current_dir] = {"items": items or [], "complete": True}

        matches = _find_in_items(items or [], component)
        if len(matches) == 1:
            real_name = matches[0]["name"]
            resolved_parts.append(real_name)
            current_dir = "disk:/" + "/".join(resolved_parts)
            continue
        if len(matches) > 1:
            return None, (
                f"Неоднозначность: найдено {len(matches)} ресурсов "
                f"с именем «{component}» (без учёта регистра) "
                f"в каталоге {current_dir}"
            )
        return None, None

    return "disk:/" + "/".join(resolved_parts), None


def resolve_case_insensitive_vd_path(
    token: str, vd_hash: str, original_path: str, dir_cache: dict
) -> tuple[Optional[str], Optional[str]]:
    """Разрешает путь на Общем диске с учётом регистра, обходя дерево каталогов.

    Returns:
        (resolved_vd_path, error_message)
        resolved_vd_path is None when not found or on error.
        error_message is non-None for ambiguity / API errors.
    """
    components = _parse_path_components(original_path)
    if not components:
        return None, "Пустой путь"

    vd_root = f"vd:{vd_hash}:disk:/"
    current_dir = vd_root
    resolved_parts: list[str] = []

    for component in components:
        cache_entry = dir_cache.get(current_dir)

        if cache_entry is not None:
            matches = _find_in_items(cache_entry["items"], component)
            if len(matches) == 1:
                real_name = matches[0]["name"]
                resolved_parts.append(real_name)
                current_dir = vd_root + "/".join(resolved_parts)
                continue
            if len(matches) > 1:
                return None, (
                    f"Неоднозначность: найдено {len(matches)} ресурсов "
                    f"с именем «{component}» (без учёта регистра) "
                    f"в каталоге {current_dir}"
                )
            if cache_entry.get("complete"):
                return None, None

        items, error = fetch_full_vd_directory_listing(token, current_dir)
        if error:
            if "404" in error:
                return None, None
            return None, error

        dir_cache[current_dir] = {"items": items or [], "complete": True}

        matches = _find_in_items(items or [], component)
        if len(matches) == 1:
            real_name = matches[0]["name"]
            resolved_parts.append(real_name)
            current_dir = vd_root + "/".join(resolved_parts)
            continue
        if len(matches) > 1:
            return None, (
                f"Неоднозначность: найдено {len(matches)} ресурсов "
                f"с именем «{component}» (без учёта регистра) "
                f"в каталоге {current_dir}"
            )
        return None, None

    return vd_root + "/".join(resolved_parts), None


def export_resources_to_csv(
    results: list[dict], output_file: str, fieldnames: list[str]
) -> bool:
    """Выгружает результаты в CSV-файл."""
    try:
        stem, ext = os.path.splitext(output_file)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{stem}_{timestamp}{ext}"
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
            writer.writeheader()
            writer.writerows(results)
        logger.info(f"Результаты сохранены в файл: {output_file}")
        return True
    except Exception as e:
        logger.error(f"Ошибка записи в файл {output_file}: {e}")
        return False


# ─────────────────────── Вспомогательные функции для листинга ───────────────────────


def safe_filename(text: str) -> str:
    """Заменяет символы, недопустимые в именах файлов, на подчёркивание."""
    return re.sub(r"[^\w\-]", "_", text)


def build_report_filepath(base_file: str, timestamp: str, suffix: str = "") -> str:
    """Формирует путь к выходному файлу с меткой времени и опциональным суффиксом."""
    stem, ext = os.path.splitext(base_file)
    if suffix:
        return f"{stem}_{suffix}_{timestamp}{ext}"
    return f"{stem}_{timestamp}{ext}"


def write_csv_file(
    results: list[dict], output_path: str, fieldnames: list[str]
) -> bool:
    """Записывает список словарей в CSV-файл по указанному пути."""
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
            writer.writeheader()
            writer.writerows(results)
        logger.info(
            f"Результаты сохранены в файл: {output_path} ({len(results)} строк)"
        )
        return True
    except Exception as e:
        logger.error(f"Ошибка записи в файл {output_path}: {e}")
        return False


def item_to_csv_row(item: dict, source: str) -> dict:
    """Преобразует элемент ответа API Диска в строку для CSV-отчёта."""
    return {
        "name": item.get("name", ""),
        "path": item.get("path", ""),
        "created": item.get("created", ""),
        "modified": item.get("modified", ""),
        "md5": item.get("md5", ""),
        "sha256": item.get("sha256", ""),
        "type": item.get("type", ""),
        "size": item.get("size", ""),
        "public_url": item.get("public_url", ""),
        "source": source,
        "error": "",
    }


def walk_vd_all_items(token: str, vd_root_path: str) -> list[dict]:
    """Рекурсивно обходит все ресурсы виртуального диска начиная с указанного пути.

    Обход выполняется по уровням BFS, листинги каталогов одного уровня запрашиваются
    параллельно (не более MAX_THREADS одновременных запросов, rate limiter контролирует
    общее количество запросов в секунду).
    """
    all_items: list[dict] = []
    visited: set[str] = set()
    current_level: list[str] = [vd_root_path]

    while current_level:
        to_fetch: list[str] = []
        for path in current_level:
            if path in visited:
                continue
            visited.add(path)
            to_fetch.append(path)

        if not to_fetch:
            break

        next_level: list[str] = []
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_path = {
                executor.submit(fetch_full_vd_directory_listing, token, path): path
                for path in to_fetch
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                items, error = future.result()
                if error:
                    logger.warning(f"Ошибка при листинге {path}: {error}")
                    continue
                for item in (items or []):
                    all_items.append(item)
                    if item.get("type") == "dir":
                        raw_item_path = item.get("path", "")
                        item_path = normalize_vd_path_from_api(raw_item_path)
                        if item_path and item_path not in visited:
                            next_level.append(item_path)

        current_level = next_level

    return all_items


def walk_personal_all_items(token: str, root_path: str) -> list[dict]:
    """Рекурсивно обходит все ресурсы личного диска начиная с указанного пути.

    Обход выполняется по уровням BFS, листинги каталогов одного уровня запрашиваются
    параллельно (не более MAX_THREADS одновременных запросов, rate limiter контролирует
    общее количество запросов в секунду).
    """
    all_items: list[dict] = []
    visited: set[str] = set()
    current_level: list[str] = [root_path]

    while current_level:
        to_fetch: list[str] = []
        for path in current_level:
            if path in visited:
                continue
            visited.add(path)
            to_fetch.append(path)

        if not to_fetch:
            break

        next_level: list[str] = []
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_path = {
                executor.submit(fetch_full_directory_listing, token, path): path
                for path in to_fetch
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                items, error = future.result()
                if error:
                    logger.warning(f"Ошибка при листинге {path}: {error}")
                    continue
                for item in (items or []):
                    all_items.append(item)
                    if item.get("type") == "dir":
                        item_path = item.get("path", "")
                        if item_path and item_path not in visited:
                            next_level.append(item_path)

        current_level = next_level

    return all_items


def get_shared_disk_resources_metadata(settings: "SettingParams"):
    input_file = settings.disk_resource_input_file
    output_file = settings.resource_output_file
    vd_hashes = settings.vd_hashes
    token = settings.oauth_token

    if not vd_hashes:
        logger.error(
            "VD_HASHES не задан. Укажите метки общих дисков в .env и повторите попытку."
        )
        return

    if not os.path.exists(input_file):
        logger.error(f"Входной файл не найден: {input_file}")
        return

    rows: list[str] = []
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                rows.append(line)
    except Exception as e:
        logger.error(f"Ошибка чтения файла {input_file}: {e}")
        return

    if not rows:
        logger.error(f"Во входном файле {input_file} нет данных для обработки.")
        return

    logger.info(f"Загружено {len(rows)} ресурсов из {input_file}")
    logger.info(
        f"Общих дисков для поиска: {len(vd_hashes)}: {', '.join(vd_hashes)}"
    )

    results: dict[int, dict] = {}
    remaining: set[int] = set(range(len(rows)))
    count_found = 0
    count_not_found = 0
    count_files = 0
    count_dirs = 0
    count_errors = 0
    count_ambiguous = 0

    # ── Фаза 1: прямой поиск по оригинальному пути ──
    logger.info("=== Фаза 1: поиск по оригинальному пути ===")

    def _phase1_fetch(idx: int, vd_path: str):
        data, meta_error = get_resource_metadata(token, vd_path)
        return idx, vd_path, data, meta_error

    for vd_num, vd_hash in enumerate(vd_hashes, start=1):
        if not remaining:
            break

        logger.info(
            f"[Фаза 1] Диск {vd_num}/{len(vd_hashes)}: vd:{vd_hash} "
            f"(осталось ресурсов: {len(remaining)})"
        )
        still_remaining: set[int] = set()
        found_by_vd = 0

        tasks = [
            (idx, build_vd_path(vd_hash, rows[idx])) for idx in sorted(remaining)
        ]
        for idx, vd_path in tasks:
            logger.debug(
                f"[{idx + 1}/{len(rows)}] [Фаза 1] Запрос у vd:{vd_hash}: {vd_path}"
            )

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [
                executor.submit(_phase1_fetch, idx, vd_path)
                for idx, vd_path in tasks
            ]
            for future in as_completed(futures):
                idx, _vd_path, data, meta_error = future.result()
                if data:
                    resource_type = data.get("type", "")
                    if resource_type == "file":
                        count_files += 1
                    elif resource_type == "dir":
                        count_dirs += 1

                    results[idx] = {
                        "name": data.get("name", ""),
                        "path": data.get("path", ""),
                        "created": data.get("created", ""),
                        "modified": data.get("modified", ""),
                        "md5": data.get("md5", ""),
                        "sha256": data.get("sha256", ""),
                        "type": resource_type,
                        "size": data.get("size", ""),
                        "public_url": data.get("public_url", ""),
                        "source": vd_hash,
                        "error": "",
                    }
                    count_found += 1
                    found_by_vd += 1
                else:
                    if meta_error and "404" not in meta_error:
                        logger.warning(
                            f"[{idx + 1}/{len(rows)}] [Фаза 1] vd:{vd_hash}: {meta_error}"
                        )
                    still_remaining.add(idx)

        remaining = still_remaining
        logger.info(
            f"[Фаза 1] Диск vd:{vd_hash}: найдено {found_by_vd}, "
            f"осталось ненайденных: {len(remaining)}"
        )

    if remaining:
        logger.info(
            f"После фазы 1 не найдено {len(remaining)} ресурс(ов). "
            f"Список не найденных путей:"
        )
        for idx in sorted(remaining):
            logger.info(f"  - {rows[idx]}")
    else:
        logger.info("После фазы 1 все ресурсы найдены.")

    # ── Фаза 2: case-insensitive поиск для ненайденных ──
    if remaining:
        logger.info("=== Фаза 2: поиск с учётом регистра (case-insensitive) ===")

        def _phase2_resolve_and_fetch(
            idx: int, full_path: str, vd_hash_inner: str, cache: dict
        ):
            resolved_path, resolve_error = resolve_case_insensitive_vd_path(
                token, vd_hash_inner, full_path, cache
            )
            if resolve_error or resolved_path is None:
                return idx, full_path, resolved_path, resolve_error, None, None
            data, meta_error = get_resource_metadata(token, resolved_path)
            return idx, full_path, resolved_path, None, data, meta_error

        for vd_num, vd_hash in enumerate(vd_hashes, start=1):
            if not remaining:
                break

            logger.info(
                f"[Фаза 2] Диск {vd_num}/{len(vd_hashes)}: vd:{vd_hash} "
                f"(осталось ресурсов: {len(remaining)})"
            )
            dir_cache: dict[str, dict] = {}
            still_remaining_p2: set[int] = set()
            found_by_vd = 0

            for idx in sorted(remaining):
                logger.debug(
                    f"[{idx + 1}/{len(rows)}] [Фаза 2] Поиск у vd:{vd_hash}: {rows[idx]}"
                )

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = [
                    executor.submit(
                        _phase2_resolve_and_fetch,
                        idx,
                        rows[idx],
                        vd_hash,
                        dir_cache,
                    )
                    for idx in sorted(remaining)
                ]
                for future in as_completed(futures):
                    (
                        idx,
                        full_path,
                        resolved_path,
                        resolve_error,
                        data,
                        meta_error,
                    ) = future.result()

                    if resolve_error:
                        logger.warning(
                            f"[{idx + 1}/{len(rows)}] [Фаза 2] vd:{vd_hash}: "
                            f"{resolve_error}"
                        )
                        is_ambiguous = "Неоднозначность" in resolve_error
                        if not is_ambiguous:
                            still_remaining_p2.add(idx)
                            continue
                        cleaned = full_path.replace("\\", "/")
                        if cleaned.lower().startswith("<root>"):
                            cleaned = cleaned[len("<root>"):]
                        name = (
                            cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
                        )
                        results[idx] = {
                            "name": name,
                            "path": full_path,
                            "created": "",
                            "modified": "",
                            "md5": "",
                            "sha256": "",
                            "type": "",
                            "size": "",
                            "public_url": "",
                            "source": vd_hash,
                            "error": resolve_error,
                        }
                        count_ambiguous += 1
                        continue

                    if resolved_path is None:
                        still_remaining_p2.add(idx)
                        continue

                    if data:
                        resource_type = data.get("type", "")
                        if resource_type == "file":
                            count_files += 1
                        elif resource_type == "dir":
                            count_dirs += 1

                        results[idx] = {
                            "name": data.get("name", ""),
                            "path": data.get("path", ""),
                            "created": data.get("created", ""),
                            "modified": data.get("modified", ""),
                            "md5": data.get("md5", ""),
                            "sha256": data.get("sha256", ""),
                            "type": resource_type,
                            "size": data.get("size", ""),
                            "public_url": data.get("public_url", ""),
                            "source": vd_hash,
                            "error": "",
                        }
                        count_found += 1
                        found_by_vd += 1
                    else:
                        if meta_error and "404" not in meta_error:
                            logger.warning(
                                f"[{idx + 1}/{len(rows)}] [Фаза 2] vd:{vd_hash}: "
                                f"{meta_error}"
                            )
                            count_errors += 1
                        still_remaining_p2.add(idx)

            remaining = still_remaining_p2
            logger.info(
                f"[Фаза 2] Диск vd:{vd_hash}: найдено {found_by_vd}, "
                f"осталось ненайденных: {len(remaining)}"
            )

    for idx in sorted(remaining):
        full_path = rows[idx]
        count_not_found += 1
        cleaned = full_path.replace("\\", "/")
        if cleaned.lower().startswith("<root>"):
            cleaned = cleaned[len("<root>"):]
        name = cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
        results[idx] = {
            "name": name,
            "path": full_path,
            "created": "",
            "modified": "",
            "md5": "",
            "sha256": "",
            "type": "",
            "size": "",
            "public_url": "",
            "source": "",
            "error": "",
        }

    ordered_results = [results[i] for i in range(len(rows)) if i in results]

    if not export_resources_to_csv(
        ordered_results, output_file, RESOURCE_OUTPUT_FIELDNAMES
    ):
        return

    print("\n" + "=" * 80)
    print("Сводная информация:")
    print(f"  Всего ресурсов во входном файле: {len(rows)}")
    print(f"  Найдено:                         {count_found}")
    print(f"    - файлов:                      {count_files}")
    print(f"    - папок:                        {count_dirs}")
    print(f"  Не найдено:                      {count_not_found}")
    print(f"  Ошибки неоднозначности:          {count_ambiguous}")
    print(f"  Ошибки API:                      {count_errors}")
    print(f"  Общих дисков проверено:          {len(vd_hashes)}")
    print(f"\nРезультаты записаны в: {output_file}")
    print("=" * 80)


def get_personal_disk_resources_metadata(settings: "SettingParams"):
    input_file = settings.disk_resource_input_file
    output_file = settings.resource_output_file

    if not settings.service_app_status:
        logger.error(
            "Сервисное приложение не настроено. "
            "Настройте сервисное приложение через меню настроек (пункт 9)."
        )
        return

    users_to_search, break_flag, double_users_flag, _all_users_flag = (
        find_users_prompt(settings)
    )
    if break_flag or double_users_flag or not users_to_search:
        if not break_flag and not double_users_flag and not users_to_search:
            logger.error("Не указаны пользователи для поиска.")
        return

    if not os.path.exists(input_file):
        logger.error(f"Входной файл не найден: {input_file}")
        return

    rows: list[str] = []
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                rows.append(line)
    except Exception as e:
        logger.error(f"Ошибка чтения файла {input_file}: {e}")
        return

    if not rows:
        logger.error(f"Во входном файле {input_file} нет данных для обработки.")
        return

    logger.info(f"Загружено {len(rows)} ресурсов из {input_file}")
    logger.info(f"Пользователей для поиска: {len(users_to_search)}")

    user_tokens: dict[str, str] = {}
    for user in users_to_search:
        email = user.get("email", "")
        if not email:
            continue
        try:
            token = get_service_app_token(settings, email)
            user_tokens[email] = token
            logger.debug(f"Получен токен для {email}")
        except TokenError as e:
            logger.warning(f"Не удалось получить токен для {email}: {e}")
        time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)

    if not user_tokens:
        logger.error("Не удалось получить токены ни для одного пользователя.")
        return

    logger.info(f"Получены токены для {len(user_tokens)} пользователей")

    results: dict[int, dict] = {}
    remaining: set[int] = set(range(len(rows)))
    count_found = 0
    count_not_found = 0
    count_files = 0
    count_dirs = 0
    count_errors = 0
    count_ambiguous = 0

    # ── Фаза 1: прямой поиск по оригинальному пути ──
    logger.info("=== Фаза 1: поиск по оригинальному пути ===")

    def _personal_phase1_fetch(idx: int, disk_path: str, user_token: str):
        data, meta_error = get_personal_resource_metadata(user_token, disk_path)
        return idx, disk_path, data, meta_error

    for user_num, (email, token) in enumerate(user_tokens.items(), start=1):
        if not remaining:
            break

        logger.info(
            f"[Фаза 1] Пользователь {user_num}/{len(user_tokens)}: {email} "
            f"(осталось ресурсов: {len(remaining)})"
        )
        still_remaining: set[int] = set()
        found_by_user = 0

        tasks: list[tuple[int, str]] = []
        for idx in sorted(remaining):
            full_path = rows[idx]
            components = _parse_path_components(full_path)
            if not components:
                still_remaining.add(idx)
                continue
            disk_path = "disk:/" + "/".join(components)
            logger.debug(
                f"[{idx + 1}/{len(rows)}] [Фаза 1] Запрос у {email}: {disk_path}"
            )
            tasks.append((idx, disk_path))

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [
                executor.submit(_personal_phase1_fetch, idx, disk_path, token)
                for idx, disk_path in tasks
            ]
            for future in as_completed(futures):
                idx, _disk_path, data, meta_error = future.result()
                if data:
                    resource_type = data.get("type", "")
                    if resource_type == "file":
                        count_files += 1
                    elif resource_type == "dir":
                        count_dirs += 1

                    results[idx] = {
                        "name": data.get("name", ""),
                        "path": data.get("path", ""),
                        "created": data.get("created", ""),
                        "modified": data.get("modified", ""),
                        "md5": data.get("md5", ""),
                        "sha256": data.get("sha256", ""),
                        "type": resource_type,
                        "size": data.get("size", ""),
                        "public_url": data.get("public_url", ""),
                        "source": email,
                        "error": "",
                    }
                    count_found += 1
                    found_by_user += 1
                else:
                    if meta_error and "404" not in meta_error:
                        logger.warning(
                            f"[{idx + 1}/{len(rows)}] [Фаза 1] {email}: {meta_error}"
                        )
                    still_remaining.add(idx)

        remaining = still_remaining
        logger.info(
            f"[Фаза 1] Пользователь {email}: найдено {found_by_user}, "
            f"осталось ненайденных: {len(remaining)}"
        )

    if remaining:
        logger.info(
            f"После фазы 1 не найдено {len(remaining)} ресурс(ов). Список не найденных путей:"
        )
        for idx in sorted(remaining):
            logger.info(f"  - {rows[idx]}")
    else:
        logger.info("После фазы 1 все ресурсы найдены.")

    # ── Фаза 2: case-insensitive поиск для ненайденных ──
    if remaining:
        logger.info("=== Фаза 2: поиск с учётом регистра (case-insensitive) ===")

        def _personal_phase2_resolve_and_fetch(
            idx: int, full_path: str, user_token: str, cache: dict
        ):
            resolved_path, resolve_error = resolve_case_insensitive_path(
                user_token, full_path, cache
            )
            if resolve_error or resolved_path is None:
                return idx, full_path, resolved_path, resolve_error, None, None
            data, meta_error = get_personal_resource_metadata(
                user_token, resolved_path
            )
            return idx, full_path, resolved_path, None, data, meta_error

        for user_num, (email, token) in enumerate(user_tokens.items(), start=1):
            if not remaining:
                break

            logger.info(
                f"[Фаза 2] Пользователь {user_num}/{len(user_tokens)}: {email} "
                f"(осталось ресурсов: {len(remaining)})"
            )
            dir_cache: dict[str, dict] = {}
            still_remaining_p2: set[int] = set()
            found_by_user = 0

            for idx in sorted(remaining):
                logger.debug(
                    f"[{idx + 1}/{len(rows)}] [Фаза 2] Поиск у {email}: {rows[idx]}"
                )

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = [
                    executor.submit(
                        _personal_phase2_resolve_and_fetch,
                        idx,
                        rows[idx],
                        token,
                        dir_cache,
                    )
                    for idx in sorted(remaining)
                ]
                for future in as_completed(futures):
                    (
                        idx,
                        full_path,
                        resolved_path,
                        resolve_error,
                        data,
                        meta_error,
                    ) = future.result()

                    if resolve_error:
                        logger.warning(
                            f"[{idx + 1}/{len(rows)}] [Фаза 2] {email}: {resolve_error}"
                        )
                        cleaned = full_path.replace("\\", "/")
                        if cleaned.lower().startswith("<root>"):
                            cleaned = cleaned[len("<root>"):]
                        name = (
                            cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
                        )
                        results[idx] = {
                            "name": name,
                            "path": full_path,
                            "created": "",
                            "modified": "",
                            "md5": "",
                            "sha256": "",
                            "type": "",
                            "size": "",
                            "public_url": "",
                            "source": email,
                            "error": resolve_error,
                        }
                        count_ambiguous += 1
                        continue

                    if resolved_path is None:
                        still_remaining_p2.add(idx)
                        continue

                    if data:
                        resource_type = data.get("type", "")
                        if resource_type == "file":
                            count_files += 1
                        elif resource_type == "dir":
                            count_dirs += 1

                        results[idx] = {
                            "name": data.get("name", ""),
                            "path": data.get("path", ""),
                            "created": data.get("created", ""),
                            "modified": data.get("modified", ""),
                            "md5": data.get("md5", ""),
                            "sha256": data.get("sha256", ""),
                            "type": resource_type,
                            "size": data.get("size", ""),
                            "public_url": data.get("public_url", ""),
                            "source": email,
                            "error": "",
                        }
                        count_found += 1
                        found_by_user += 1
                    else:
                        if meta_error and "404" not in meta_error:
                            logger.warning(
                                f"[{idx + 1}/{len(rows)}] [Фаза 2] {email}: "
                                f"{meta_error}"
                            )
                            count_errors += 1
                        still_remaining_p2.add(idx)

            remaining = still_remaining_p2
            logger.info(
                f"[Фаза 2] Пользователь {email}: найдено {found_by_user}, "
                f"осталось ненайденных: {len(remaining)}"
            )

    for idx in sorted(remaining):
        full_path = rows[idx]
        count_not_found += 1
        cleaned = full_path.replace("\\", "/")
        if cleaned.lower().startswith("<root>"):
            cleaned = cleaned[len("<root>"):]
        name = cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
        results[idx] = {
            "name": name,
            "path": full_path,
            "created": "",
            "modified": "",
            "md5": "",
            "sha256": "",
            "type": "",
            "size": "",
            "public_url": "",
            "source": "",
            "error": "",
        }

    ordered_results = [results[i] for i in range(len(rows)) if i in results]

    if not export_resources_to_csv(
        ordered_results, output_file, RESOURCE_OUTPUT_FIELDNAMES
    ):
        return

    print("\n" + "=" * 80)
    print("Сводная информация:")
    print(f"  Всего ресурсов во входном файле: {len(rows)}")
    print(f"  Найдено:                         {count_found}")
    print(f"    - файлов:                      {count_files}")
    print(f"    - папок:                        {count_dirs}")
    print(f"  Не найдено:                      {count_not_found}")
    print(f"  Ошибки неоднозначности:          {count_ambiguous}")
    print(f"  Ошибки API:                      {count_errors}")
    print(f"  Пользователей проверено:         {len(user_tokens)}")
    print(f"\nРезультаты записаны в: {output_file}")
    print("=" * 80)


def get_my_disk_resources_metadata(settings: "SettingParams"):
    """Получает метаданные ресурсов на личном Диске запустившего скрипт пользователя,
    используя OAUTH_TOKEN из .env без запроса списка пользователей."""
    input_file = settings.disk_resource_input_file
    output_file = settings.resource_output_file
    token = settings.oauth_token

    if not os.path.exists(input_file):
        logger.error(f"Входной файл не найден: {input_file}")
        return

    rows: list[str] = []
    try:
        with open(input_file, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                rows.append(line)
    except Exception as e:
        logger.error(f"Ошибка чтения файла {input_file}: {e}")
        return

    if not rows:
        logger.error(f"Во входном файле {input_file} нет данных для обработки.")
        return

    logger.info(f"Загружено {len(rows)} ресурсов из {input_file}")
    logger.info("Поиск ресурсов на личном Диске текущего пользователя (OAUTH_TOKEN)")

    results: dict[int, dict] = {}
    remaining: set[int] = set(range(len(rows)))
    count_found = 0
    count_not_found = 0
    count_files = 0
    count_dirs = 0
    count_errors = 0
    count_ambiguous = 0

    # ── Фаза 1: прямой поиск по оригинальному пути ──
    logger.info("=== Фаза 1: поиск по оригинальному пути ===")
    still_remaining: set[int] = set()

    def _my_phase1_fetch(idx: int, disk_path: str):
        data, meta_error = get_personal_resource_metadata(token, disk_path)
        return idx, disk_path, data, meta_error

    tasks: list[tuple[int, str]] = []
    for idx in sorted(remaining):
        full_path = rows[idx]
        components = _parse_path_components(full_path)
        if not components:
            still_remaining.add(idx)
            continue
        disk_path = "disk:/" + "/".join(components)
        logger.debug(
            f"[{idx + 1}/{len(rows)}] [Фаза 1] Запрос: {disk_path}"
        )
        tasks.append((idx, disk_path))

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(_my_phase1_fetch, idx, disk_path)
            for idx, disk_path in tasks
        ]
        for future in as_completed(futures):
            idx, _disk_path, data, meta_error = future.result()
            if data:
                resource_type = data.get("type", "")
                if resource_type == "file":
                    count_files += 1
                elif resource_type == "dir":
                    count_dirs += 1

                results[idx] = {
                    "name": data.get("name", ""),
                    "path": data.get("path", ""),
                    "created": data.get("created", ""),
                    "modified": data.get("modified", ""),
                    "md5": data.get("md5", ""),
                    "sha256": data.get("sha256", ""),
                    "type": resource_type,
                    "size": data.get("size", ""),
                    "public_url": data.get("public_url", ""),
                    "source": "my_disk",
                    "error": "",
                }
                count_found += 1
            else:
                if meta_error and "404" not in meta_error:
                    logger.warning(
                        f"[{idx + 1}/{len(rows)}] [Фаза 1] {meta_error}"
                    )
                still_remaining.add(idx)

    remaining = still_remaining
    logger.info(
        f"[Фаза 1] Найдено {count_found}, "
        f"осталось ненайденных: {len(remaining)}"
    )

    if remaining:
        logger.info(
            f"После фазы 1 не найдено {len(remaining)} ресурс(ов). "
            f"Список не найденных путей:"
        )
        for idx in sorted(remaining):
            logger.info(f"  - {rows[idx]}")
    else:
        logger.info("После фазы 1 все ресурсы найдены.")

    # ── Фаза 2: case-insensitive поиск для ненайденных ──
    if remaining:
        logger.info("=== Фаза 2: поиск с учётом регистра (case-insensitive) ===")
        dir_cache: dict[str, dict] = {}
        still_remaining_p2: set[int] = set()

        def _my_phase2_resolve_and_fetch(idx: int, full_path: str, cache: dict):
            resolved_path, resolve_error = resolve_case_insensitive_path(
                token, full_path, cache
            )
            if resolve_error or resolved_path is None:
                return idx, full_path, resolved_path, resolve_error, None, None
            data, meta_error = get_personal_resource_metadata(token, resolved_path)
            return idx, full_path, resolved_path, None, data, meta_error

        for idx in sorted(remaining):
            logger.debug(
                f"[{idx + 1}/{len(rows)}] [Фаза 2] Поиск: {rows[idx]}"
            )

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [
                executor.submit(
                    _my_phase2_resolve_and_fetch, idx, rows[idx], dir_cache
                )
                for idx in sorted(remaining)
            ]
            for future in as_completed(futures):
                (
                    idx,
                    full_path,
                    resolved_path,
                    resolve_error,
                    data,
                    meta_error,
                ) = future.result()

                if resolve_error:
                    logger.warning(
                        f"[{idx + 1}/{len(rows)}] [Фаза 2] {resolve_error}"
                    )
                    cleaned = full_path.replace("\\", "/")
                    if cleaned.lower().startswith("<root>"):
                        cleaned = cleaned[len("<root>"):]
                    name = cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
                    results[idx] = {
                        "name": name,
                        "path": full_path,
                        "created": "",
                        "modified": "",
                        "md5": "",
                        "sha256": "",
                        "type": "",
                        "size": "",
                        "public_url": "",
                        "source": "my_disk",
                        "error": resolve_error,
                    }
                    count_ambiguous += 1
                    continue

                if resolved_path is None:
                    still_remaining_p2.add(idx)
                    continue

                if data:
                    resource_type = data.get("type", "")
                    if resource_type == "file":
                        count_files += 1
                    elif resource_type == "dir":
                        count_dirs += 1

                    results[idx] = {
                        "name": data.get("name", ""),
                        "path": data.get("path", ""),
                        "created": data.get("created", ""),
                        "modified": data.get("modified", ""),
                        "md5": data.get("md5", ""),
                        "sha256": data.get("sha256", ""),
                        "type": resource_type,
                        "size": data.get("size", ""),
                        "public_url": data.get("public_url", ""),
                        "source": "my_disk",
                        "error": "",
                    }
                    count_found += 1
                else:
                    if meta_error and "404" not in meta_error:
                        logger.warning(
                            f"[{idx + 1}/{len(rows)}] [Фаза 2] {meta_error}"
                        )
                        count_errors += 1
                    still_remaining_p2.add(idx)

        remaining = still_remaining_p2
        logger.info(
            f"[Фаза 2] Найдено дополнительно, "
            f"осталось ненайденных: {len(remaining)}"
        )

    for idx in sorted(remaining):
        full_path = rows[idx]
        count_not_found += 1
        cleaned = full_path.replace("\\", "/")
        if cleaned.lower().startswith("<root>"):
            cleaned = cleaned[len("<root>"):]
        name = cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
        results[idx] = {
            "name": name,
            "path": full_path,
            "created": "",
            "modified": "",
            "md5": "",
            "sha256": "",
            "type": "",
            "size": "",
            "public_url": "",
            "source": "",
            "error": "",
        }

    ordered_results = [results[i] for i in range(len(rows)) if i in results]

    if not export_resources_to_csv(
        ordered_results, output_file, RESOURCE_OUTPUT_FIELDNAMES
    ):
        return

    print("\n" + "=" * 80)
    print("Сводная информация:")
    print(f"  Всего ресурсов во входном файле: {len(rows)}")
    print(f"  Найдено:                         {count_found}")
    print(f"    - файлов:                      {count_files}")
    print(f"    - папок:                        {count_dirs}")
    print(f"  Не найдено:                      {count_not_found}")
    print(f"  Ошибки неоднозначности:          {count_ambiguous}")
    print(f"  Ошибки API:                      {count_errors}")
    print(f"\nРезультаты записаны в: {output_file}")
    print("=" * 80)


# ─────────────────────── Листинг всех ресурсов ───────────────────────


def list_all_shared_disk_resources(settings: "SettingParams"):
    """Выгружает список всех ресурсов общих дисков (VD) в CSV без сравнения."""
    vd_hashes = settings.vd_hashes
    token = settings.oauth_token
    output_file = settings.resource_output_file
    single_file = settings.single_report_file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not vd_hashes:
        logger.error(
            "VD_HASHES не задан. Укажите метки общих дисков в .env и повторите попытку."
        )
        return

    all_results: list[dict] = []
    output_files: list[tuple[str, str, int]] = []
    total_count = 0

    for vd_num, vd_hash in enumerate(vd_hashes, start=1):
        logger.info(
            f"Обход ресурсов диска {vd_num}/{len(vd_hashes)}: vd:{vd_hash}"
        )
        vd_root = f"vd:{vd_hash}:disk:/"
        items = walk_vd_all_items(token, vd_root)
        count = len(items)
        total_count += count
        logger.info(f"Диск vd:{vd_hash}: найдено {count} ресурсов")

        rows = [item_to_csv_row(item, vd_hash) for item in items]

        if single_file:
            all_results.extend(rows)
        else:
            safe_hash = safe_filename(vd_hash)
            out_path = build_report_filepath(output_file, timestamp, f"vd_{safe_hash}")
            if write_csv_file(rows, out_path, RESOURCE_OUTPUT_FIELDNAMES):
                output_files.append((vd_hash, out_path, count))

    print("\n" + "=" * 80)
    print("Сводная информация:")
    if single_file:
        # Для общего диска формируем имя shared_disk_<timestamp>.csv
        stem, ext = os.path.splitext(output_file)
        out_path = f"shared_disk_{timestamp}{ext}"
        if write_csv_file(all_results, out_path, RESOURCE_OUTPUT_FIELDNAMES):
            print(f"  Всего ресурсов:           {total_count}")
            print(f"  Общих дисков обработано:  {len(vd_hashes)}")
            print(f"\n  Результаты записаны в: {out_path}")
    else:
        print(f"  Общих дисков обработано:  {len(vd_hashes)}")
        print(f"  Всего ресурсов:           {total_count}")
        print()
        for vd_hash, out_path, count in output_files:
            print(f"  vd:{vd_hash}: {count} ресурсов -> {out_path}")
    print("=" * 80)


def list_all_personal_disk_resources(settings: "SettingParams"):
    """Выгружает список всех ресурсов персональных дисков указанных пользователей в CSV."""
    output_file = settings.resource_output_file
    single_file = settings.single_report_file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not settings.service_app_status:
        logger.error(
            "Сервисное приложение не настроено. "
            "Настройте сервисное приложение через меню настроек (пункт 9)."
        )
        return

    users_to_search, break_flag, double_users_flag, _all_users_flag = (
        find_users_prompt(settings)
    )
    if break_flag or double_users_flag or not users_to_search:
        if not break_flag and not double_users_flag and not users_to_search:
            logger.error("Не указаны пользователи для поиска.")
        return

    user_tokens: dict[str, str] = {}
    for user in users_to_search:
        email = user.get("email", "")
        if not email:
            continue
        try:
            token = get_service_app_token(settings, email)
            user_tokens[email] = token
            logger.debug(f"Получен токен для {email}")
        except TokenError as e:
            logger.warning(f"Не удалось получить токен для {email}: {e}")
        time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)

    if not user_tokens:
        logger.error("Не удалось получить токены ни для одного пользователя.")
        return

    logger.info(f"Получены токены для {len(user_tokens)} пользователей")

    all_results: list[dict] = []
    output_files: list[tuple[str, str, int]] = []
    total_count = 0

    for user_num, (email, token) in enumerate(user_tokens.items(), start=1):
        logger.info(
            f"Обход ресурсов пользователя {user_num}/{len(user_tokens)}: {email}"
        )
        items = walk_personal_all_items(token, "disk:/")
        count = len(items)
        total_count += count
        logger.info(f"Пользователь {email}: найдено {count} ресурсов")

        rows = [item_to_csv_row(item, email) for item in items]

        if single_file:
            all_results.extend(rows)
        else:
            # Извлекаем имя пользователя из email (часть до @)
            username = email.split("@")[0] if "@" in email else email
            safe_username = safe_filename(username)
            stem, ext = os.path.splitext(output_file)
            out_path = f"{safe_username}_{timestamp}{ext}"
            if write_csv_file(rows, out_path, RESOURCE_OUTPUT_FIELDNAMES):
                output_files.append((email, out_path, count))

    print("\n" + "=" * 80)
    print("Сводная информация:")
    if single_file:
        # Для персональных дисков формируем имя personal_disk_<timestamp>.csv
        stem, ext = os.path.splitext(output_file)
        out_path = f"personal_disk_{timestamp}{ext}"
        if write_csv_file(all_results, out_path, RESOURCE_OUTPUT_FIELDNAMES):
            print(f"  Всего ресурсов:              {total_count}")
            print(f"  Пользователей обработано:    {len(user_tokens)}")
            print(f"\n  Результаты записаны в: {out_path}")
    else:
        print(f"  Пользователей обработано:    {len(user_tokens)}")
        print(f"  Всего ресурсов:              {total_count}")
        print()
        for email, out_path, count in output_files:
            print(f"  {email}: {count} ресурсов -> {out_path}")
    print("=" * 80)


def list_all_my_disk_resources(settings: "SettingParams"):
    """Выгружает список всех ресурсов личного Диска текущего пользователя в CSV."""
    token = settings.oauth_token
    output_file = settings.resource_output_file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    logger.info("Обход ресурсов личного Диска текущего пользователя (OAUTH_TOKEN)")
    items = walk_personal_all_items(token, "disk:/")
    count = len(items)
    logger.info(f"Найдено {count} ресурсов")

    rows = [item_to_csv_row(item, "my_disk") for item in items]
    out_path = build_report_filepath(output_file, timestamp, "mydisk")
    if not write_csv_file(rows, out_path, RESOURCE_OUTPUT_FIELDNAMES):
        return

    print("\n" + "=" * 80)
    print("Сводная информация:")
    print(f"  Всего ресурсов: {count}")
    print(f"\n  Результаты записаны в: {out_path}")
    print("=" * 80)


# ─────────────────────── Меню ───────────────────────


def service_application_status_menu(settings: SettingParams):
    while True:
        print("\n")
        print("------------------------ Сервисное приложение ------------------------")
        print("1. Проверить статус сервисного приложения.")
        print("2. Настроить сервисное приложение.")
        print("3. Удаление сервисного приложения из списка организации.")
        print("4. Выгрузить данные сервисных приложений в файл.")
        print("5. Загрузить параметры сервисных приложений из файла.")
        print("------------------------ Выйти в главное меню -------------------------")
        print("0. Выйти в главное меню.")
        choice = input("Введите ваш выбор (0-5): ")
        if choice == "0" or choice == "":
            break
        elif choice == "1":
            check_service_app_status(settings)
        elif choice == "2":
            setup_service_application(settings)
        elif choice == "3":
            delete_service_application_from_list(settings)
        elif choice == "4":
            export_service_applications_api_data(settings)
        elif choice == "5":
            import_service_applications_api_data(settings)
        else:
            print("Неверный выбор. Попробуйте снова.")
    return settings


def main_menu(settings: "SettingParams"):
    while True:
        print("\n")
        print("Выберите опцию:")
        print("1. Найти метаданные ресурсов Общего Диска по входному файлу.")
        print("2. Найти метаданные ресурсов из личных Дисков пользователей по входному файлу.")
        print("3. Найти метаданные ресурсов с моего личного Диска по входному файлу.")
        print("4. Получить список всех ресурсов общего диска.")
        print("5. Получить список всех ресурсов персональных дисков пользователей.")
        print("6. Получить список всех ресурсов моего личного диска.")
        print("9. Настройка сервисного приложения.")
        print("0. (Ctrl+C) Выход")
        print("\n")
        choice = input("Введите ваш выбор (0,1,2,3,4,5,6,9): ")

        if choice == "0":
            print("До свидания!")
            break
        elif choice == "1":
            get_shared_disk_resources_metadata(settings)
        elif choice == "2":
            get_personal_disk_resources_metadata(settings)
        elif choice == "3":
            get_my_disk_resources_metadata(settings)
        elif choice == "4":
            list_all_shared_disk_resources(settings)
        elif choice == "5":
            list_all_personal_disk_resources(settings)
        elif choice == "6":
            list_all_my_disk_resources(settings)
        elif choice == "9":
            service_application_status_menu(settings)
        else:
            logger.error("Неверный выбор. Попробуйте снова.")


if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path, verbose=True, override=True)
    else:
        logger.error("Не найден файл .env. Выход.")
        sys.exit(EXIT_CODE)

    IGNORE_SSL = os.environ.get("IGNORE_SSL", "false").lower() == "true"
    if IGNORE_SSL:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("Проверка SSL-сертификатов отключена (IGNORE_SSL=true)")

    logger.info("\n")
    logger.info("---------------------------------------------------------------------------.")
    logger.info("Запуск скрипта y360_disk.")

    settings = get_settings()
    if settings is None:
        logger.error("Проверьте настройки в файле .env и попробуйте снова.")
        sys.exit(EXIT_CODE)

    try:
        main_menu(settings)
    except KeyboardInterrupt:
        logger.info("\nCtrl+C pressed. До свидания!")
        sys.exit(EXIT_CODE)
    except Exception as exc:
        tb = traceback.extract_tb(exc.__traceback__)
        last_frame = tb[-1] if tb else None
        if last_frame:
            logger.error(
                f"{type(exc).__name__} at {last_frame.filename}:{last_frame.lineno} "
                f"in {last_frame.name}: {exc}"
            )
        else:
            logger.error(f"{type(exc).__name__}: {exc}")
        sys.exit(EXIT_CODE)
