import asyncio
import aiohttp
import ipaddress
import random
import json
import csv
from datetime import datetime
from typing import List, Dict, Tuple, Set, Optional, Union, Callable
import logging
import socket
import asyncio
from asyncio import TimeoutError

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,  # Изменили на DEBUG чтобы видеть все логи
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class PortChecker:
    """Класс для проверки различных портов"""

    @staticmethod
    async def check_ssh(ip: str, timeout: float = 5.0) -> bool:
        """Проверка SSH соединения по порту 22"""
        try:
            # Используем низкоуровневый asyncio для соединения с портом
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 22),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, TimeoutError, OSError, asyncio.TimeoutError):
            return False
        except Exception:
            return False

    @staticmethod
    async def check_http(ip: str, timeout: float = 5.0) -> bool:
        """Проверка HTTP соединения по порту 80"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 80),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, TimeoutError, OSError, asyncio.TimeoutError):
            return False
        except Exception:
            return False

    @staticmethod
    async def check_https(ip: str, timeout: float = 5.0) -> bool:
        """Проверка HTTPS соединения по порту 443"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, TimeoutError, OSError, asyncio.TimeoutError):
            return False
        except Exception:
            return False

    @staticmethod
    async def check_custom_port(ip: str, port: int, timeout: float = 5.0) -> bool:
        """Проверка кастомного порта"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, TimeoutError, OSError, asyncio.TimeoutError):
            return False
        except Exception:
            return False


class IPv4WhitelistChecker:
    def __init__(self):
        self.test_suite = [
            {"name": "Beget", "asns": ["198610"]},
        ]

        # Параметры по умолчанию
        self.timeout_ms = 5000
        self.subnet_sample_size = 25
        self.subnet_alive_min = 3
        self.subnet_only_24_prefix = True

        # Настройки проверки портов
        self.check_methods = [
            {"name": "HTTPS", "func": self.check_https_method, "enabled": True},
            {"name": "HTTP", "func": self.check_http_method, "enabled": False},
            {"name": "SSH", "func": self.check_ssh_method, "enabled": True},
            {"name": "Custom Port", "func": self.check_custom_port_method, "enabled": False, "port": 8080},
        ]

        # Требуется ли хотя бы один метод для успеха
        self.require_any_method = True

        self.cached_subnets = {}
        self.results_data = []
        self.results_count = 0

        # Статусы
        self.STATUS_READY_NON_CACHED = "Ready (non-cached ⚠️)"
        self.STATUS_READY_CACHED = "Ready (cached ⚡)"
        self.STATUS_WORKING = "Subnets checking ⏰"
        self.STATUS_CACHING = "Subnets caching ⏰"
        self.STATUS_ERROR = "Unexpected caching error ⚠️"

        self.current_status = self.STATUS_READY_NON_CACHED

        # Порты для проверки (можно настроить)
        self.port_checker = PortChecker()

    def set_params(self, timeout: int = None, sn_sample_size: int = None,
                   sn_alive_min: int = None, sn_only_24_prefix: bool = None,
                   check_methods: List[Dict] = None, require_any_method: bool = None):
        """Установка параметров"""
        if timeout:
            self.timeout_ms = timeout
        if sn_sample_size:
            self.subnet_sample_size = sn_sample_size
        if sn_alive_min:
            self.subnet_alive_min = sn_alive_min
        if sn_only_24_prefix is not None:
            self.subnet_only_24_prefix = sn_only_24_prefix
        if check_methods:
            self.check_methods = check_methods
        if require_any_method is not None:
            self.require_any_method = require_any_method

    def log_push(self, level: str, prefix: str, msg: str):
        """Аналог logPush"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        prefix_str = f"{prefix}/" if prefix else ""
        log_msg = f"[{timestamp}] {prefix_str}{level}: {msg}"

        if level == "ERR":
            logger.error(log_msg)
        elif level == "INFO":
            logger.info(log_msg)
        elif level == "DEBUG":
            logger.debug(log_msg)
        else:
            logger.debug(log_msg)

        return log_msg


    def get_subnet_sample(self, cidr: str, n: int) -> List[str]:
        """Генерация N случайных уникальных хостов из подсети (CIDR)"""
        network = ipaddress.ip_network(cidr, strict=False)

        # Для сети меньше размера выборки, возвращаем все адреса
        if network.num_addresses <= n + 2:  # +2 для network и broadcast адресов
            all_hosts = list(network.hosts())
            return [str(ip) for ip in all_hosts[:n]]

        # Fisher-Yates shuffle для случайной выборки
        block_size = network.num_addresses - 2  # исключаем network и broadcast
        swap = {}
        result = []

        for i in range(min(n, block_size)):
            r = i + random.randint(0, block_size - i - 1)

            pick = swap.get(r, r)
            swap[r] = swap.get(i, i)

            # Преобразуем в IP адрес (пропускаем network address)
            ip_int = int(network.network_address) + pick + 1
            result.append(str(ipaddress.IPv4Address(ip_int)))

        return result

    async def check_https_method(self, session: aiohttp.ClientSession, ip: str) -> bool:
        """Проверка через HTTPS HEAD запрос"""
        try:
            url = f"https://{ip}/?t={random.random()}"
            async with session.head(
                url,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout_ms / 1000),
                allow_redirects=False
            ) as response:
                return True
        except Exception as e:
            self.log_push("DEBUG", f"HTTPS[{ip}]", f"Error: {type(e).__name__}")
            return False

    async def check_http_method(self, session: aiohttp.ClientSession, ip: str) -> bool:
        """Проверка через HTTP HEAD запрос"""
        try:
            url = f"http://{ip}/?t={random.random()}"
            async with session.head(
                url,
                timeout=aiohttp.ClientTimeout(total=self.timeout_ms / 1000),
                allow_redirects=False
            ) as response:
                return True
        except Exception as e:
            self.log_push("DEBUG", f"HTTP[{ip}]", f"Error: {type(e).__name__}")
            return False

    async def check_ssh_method(self, session: aiohttp.ClientSession, ip: str) -> bool:
        """Проверка SSH порта 22"""
        try:
            result = await self.port_checker.check_ssh(ip, self.timeout_ms / 1000)
            self.log_push("DEBUG", f"SSH[{ip}]", f"Result: {'Success' if result else 'Failed'}")
            return result
        except Exception as e:
            self.log_push("DEBUG", f"SSH[{ip}]", f"Error: {type(e).__name__}")
            return False

    async def check_custom_port_method(self, session: aiohttp.ClientSession, ip: str) -> bool:
        """Проверка кастомного порта"""
        try:
            port = next((m.get('port', 8080) for m in self.check_methods if m['name'] == 'Custom Port'), 8080)
            result = await self.port_checker.check_custom_port(ip, port, self.timeout_ms / 1000)
            self.log_push("DEBUG", f"Port[{ip}:{port}]", f"Result: {'Success' if result else 'Failed'}")
            return result
        except Exception as e:
            self.log_push("DEBUG", f"Port[{ip}]", f"Error: {type(e).__name__}")
            return False

    async def check_ipv4_host(self, session: aiohttp.ClientSession, ip: str,
                              early_abort_event: asyncio.Event, ref: Dict) -> bool:
        """Проверка доступности хоста через все включенные методы"""
        if ref["alive_count"] >= self.subnet_alive_min:
            early_abort_event.set()
            self.log_push("DEBUG", f"Host checker[{ip}]", "Early abort - enough alive hosts")
            return False

        prefix = f"Host checker[{ip}]"
        self.log_push("INFO", prefix, "Started")

        # Получаем включенные методы проверки
        enabled_methods = [m for m in self.check_methods if m.get('enabled', False)]

        if not enabled_methods:
            self.log_push("WARN", prefix, "No check methods enabled!")
            return False

        results = []
        method_tasks = []

        self.log_push("DEBUG", prefix, f"Running {len(enabled_methods)} methods: {[m['name'] for m in enabled_methods]}")

        # Запускаем проверки по всем методам параллельно
        for method in enabled_methods:
            task = method['func'](session, ip)
            method_tasks.append(task)

        try:
            method_results = await asyncio.gather(*method_tasks, return_exceptions=True)

            for i, result in enumerate(method_results):
                method_name = enabled_methods[i]['name']
                if isinstance(result, bool):
                    results.append(result)
                    status = "✅" if result else "❌"
                    self.log_push("INFO", prefix, f"{method_name}: {status}")
                else:
                    results.append(False)
                    self.log_push("WARN", prefix, f"{method_name}: Error {result}")

        except Exception as e:
            self.log_push("ERR", prefix, f"Check error: {e}")
            results = [False] * len(enabled_methods)

        # Определяем общий результат
        if self.require_any_method:
            # Хост считается доступным, если хотя бы один метод успешен
            overall_result = any(results)
            self.log_push("DEBUG", prefix, f"ANY mode: {sum(results)}/{len(results)} methods succeeded")
        else:
            # Хост считается доступным, если все включенные методы успешны
            overall_result = all(results) if results else False
            self.log_push("DEBUG", prefix, f"ALL mode: {sum(results)}/{len(results)} methods succeeded")

        if overall_result:
            ref["alive_count"] += 1
            self.log_push("DEBUG", prefix, f"Host is ALIVE, total alive: {ref['alive_count']}")

        if ref["alive_count"] >= self.subnet_alive_min:
            early_abort_event.set()
            self.log_push("DEBUG", prefix, f"Enough alive hosts ({ref['alive_count']}), setting early abort")

        # Подробный лог результатов
        success_count = sum(1 for r in results if r)
        total_methods = len(results)

        if overall_result:
            status = f"Alive ✅ ({success_count}/{total_methods} methods)"
        elif early_abort_event.is_set():
            status = "Early abort ⏭️ (enough alive hosts)"
        else:
            status = f"Dead 💀 ({success_count}/{total_methods} methods)"

        self.log_push("INFO", prefix, f"{status}.")
        return overall_result

    async def check_subnet(self, session: aiohttp.ClientSession,
                           provider: str, cidr: str) -> Dict:
        """Проверка подсети на доступность"""
        prefix = f"Subnet checker[{provider} => {cidr}]"
        self.log_push("INFO", prefix, "Started")

        ips = self.get_subnet_sample(cidr, self.subnet_sample_size)
        early_abort_event = asyncio.Event()
        ref = {"alive_count": 0}

        tasks = []
        for ip in ips:
            if early_abort_event.is_set():
                self.log_push("DEBUG", prefix, "Early abort triggered, skipping remaining IPs")
                break

            task = self.check_ipv4_host(session, ip, early_abort_event, ref)
            tasks.append(task)

        # Ограничиваем количество одновременных запросов
        semaphore = asyncio.Semaphore(self.subnet_sample_size)

        async def limited_task(task):
            async with semaphore:
                return await task


        limited_tasks = [limited_task(task) for task in tasks]
        results = await asyncio.gather(*limited_tasks, return_exceptions=True)

        alive_count = sum(1 for r in results if r is True)

        result_data = {
            "provider": provider,
            "cidr": cidr,
            "alive_count": alive_count,
            "total_checked": len([r for r in results if not isinstance(r, Exception)]),
            "sample_size": len(ips)
        }

        if alive_count > 0:
            self.results_count += 1
            self.results_data.append(result_data)

            status = "✅" if alive_count >= self.subnet_alive_min else "⚠️"
            self.log_push("INFO", prefix, f"Added to results: {cidr} {status} (alive: {alive_count}/{len(ips)})")

        self.log_push("INFO", prefix, f"Done (alive: {alive_count}/{len(ips)}).")
        return result_data

    async def fetch_as_ipv4_subnets(self, session: aiohttp.ClientSession, asn: str) -> List[str]:
        """Получение подсетей для AS номера"""
        prefix = f"AS IPv4 subnets fetcher[AS{asn}]"
        self.log_push("INFO", prefix, "Started")

        try:
            ripe_api_url = "https://stat.ripe.net/data/announced-prefixes/data.json"
            params = {"resource": asn}

            async with session.get(ripe_api_url, params=params) as response:
                data = await response.json()

                prefixes = [
                    item["prefix"]
                    for item in data.get("data", {}).get("prefixes", [])
                    if "." in item["prefix"] and "/" in item["prefix"]
                ]

                self.log_push("INFO", prefix, f"Done (total: {len(prefixes)}).")
                return prefixes

        except Exception as e:
            error_msg = f"{prefix} error: {str(e)}"
            self.log_push("ERR", prefix, str(e))
            raise Exception(error_msg)


    async def fetch_provider_ipv4_subnets(self, session: aiohttp.ClientSession,
                                          provider: Dict) -> List[str]:
        """Получение подсетей для провайдера"""
        prefix = f"Provider IPv4 subnets fetcher[{provider['name']}]"
        self.log_push("INFO", prefix, "Started")

        tasks = []
        for asn in provider["asns"]:
            tasks.append(self.fetch_as_ipv4_subnets(session, asn))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Объединяем результаты и удаляем дубликаты
        all_subnets = []
        for result in all_results:
            if isinstance(result, list):
                all_subnets.extend(result)
            elif isinstance(result, Exception):
                self.log_push("ERR", prefix, f"Error fetching AS: {result}")

        merged = list(set(all_subnets))

        # Фильтрация по префиксу /24 если нужно
        if self.subnet_only_24_prefix:
            suitable = [s for s in merged if s.endswith("/24")]
        else:
            suitable = merged

        self.log_push("INFO", prefix,
                      f"Done (all: {len(all_subnets)}, merged: {len(merged)}, suitable: {len(suitable)}).")

        return suitable


    async def cache_subnets(self):
        """Кэширование подсетей"""
        self.current_status = self.STATUS_CACHING
        self.log_push("INFO", "Subnets cacher", "Started")

        self.cached_subnets = {}
        self.results_data = []
        self.results_count = 0

        try:
            async with aiohttp.ClientSession() as session:
                for provider in self.test_suite:
                    subnets = await self.fetch_provider_ipv4_subnets(session, provider)
                    self.cached_subnets[provider["name"]] = subnets

            # Сохраняем в файл (аналог localStorage)
            with open("cached_subnets.json", "w") as f:
                json.dump(self.cached_subnets, f, indent=2)

            self.current_status = self.STATUS_READY_CACHED
            self.log_push("INFO", "Subnets cacher", "Cached successfully.")

            return True

        except Exception as e:
            self.current_status = self.STATUS_ERROR
            self.log_push("ERR", "Subnets cacher", f"Unexpected caching error => {e}")
            return False


    async def check_subnets(self):
        """Основная проверка подсетей"""
        self.current_status = self.STATUS_WORKING
        prefix = "Subnets checker"
        self.log_push("INFO", prefix, "Started")

        # Сбрасываем результаты
        self.results_data = []
        self.results_count = 0

        if not self.cached_subnets:
            self.log_push("ERR", prefix, "No cached subnets found. Cache first.")
            self.current_status = self.STATUS_READY_NON_CACHED
            return False

        subnets_total = sum(len(subnets) for subnets in self.cached_subnets.values())
        subnets_checked = 0

        async with aiohttp.ClientSession() as session:
            for provider, subnets in self.cached_subnets.items():
                for subnet in subnets:
                    subnets_checked += 1
                    self.log_push("INFO", prefix,
                                  f"Progress: {subnets_checked}/{subnets_total}")
                    await self.check_subnet(session, provider, subnet)

        self.current_status = self.STATUS_READY_CACHED
        self.log_push("INFO", prefix,
                      f"Done (found: {self.results_count}, total subnets: {subnets_total}).")

        return self.results_count > 0


    def load_cached_subnets(self) -> bool:
        """Загрузка кэшированных подсетей из файла"""
        try:
            with open("cached_subnets.json", "r") as f:
                self.cached_subnets = json.load(f)

            total = sum(len(subnets) for subnets in self.cached_subnets.values())
            self.log_push("INFO", None,
                          f"Cached subnets loaded (providers: {len(self.cached_subnets)}, total subnets: {total}).")

            self.current_status = self.STATUS_READY_CACHED
            return True

        except FileNotFoundError:
            self.log_push("INFO", None, "Cached subnets not found.")
            return False
        except Exception as e:
            self.log_push("ERR", None, f"Error loading cached subnets: {e}")
            return False


    def save_results(self, filename: str = None):
        """Сохранение результатов в CSV файл"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ipv4-whitelisted-subnets-{timestamp}.csv"

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['provider', 'cidr', 'alive_count', 'total_checked', 'sample_size']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')

                writer.writeheader()
                for row in self.results_data:
                    writer.writerow({k: row.get(k, '') for k in fieldnames})

            self.log_push("INFO", "Results saver", f"Results saved to {filename}")
            return filename

        except Exception as e:
            self.log_push("ERR", "Results saver", f"Error saving results: {e}")
            return None


    def print_results_table(self):
        """Вывод результатов в виде таблицы"""
        if not self.results_data:
            print("⚠️ No results to display")
            return

        print("\n" + "=" * 80)
        print(f"{'#':<3} {'Provider':<15} {'Subnet':<20} {'Alive':<8} {'Total':<8} {'Status':<10}")
        print("-" * 80)

        for i, result in enumerate(self.results_data, 1):
            alive = result['alive_count']
            total = result.get('total_checked', result.get('sample_size', 0))
            ratio = alive / total if total > 0 else 0

            if alive >= self.subnet_alive_min:
                status = "✅ WHITELISTED"
            elif alive > 0:
                status = "⚠️ PARTIAL"
            else:
                status = "❌ BLOCKED"

            print(f"{i:<3} {result['provider']:<15} {result['cidr']:<20} "
                  f"{alive:<8} {total:<8} {status:<10}")

        print("=" * 80)
        print(f"Total: {self.results_count} subnets found")

        # Статистика по методам проверки
        enabled_methods = [m['name'] for m in self.check_methods if m.get('enabled', False)]
        if enabled_methods:
            print(f"Check methods: {', '.join(enabled_methods)}")
            if self.require_any_method:
                print("Mode: Host considered alive if ANY method succeeds")
            else:
                print("Mode: Host considered alive if ALL methods succeed")

    def get_status(self) -> str:
        """Получение текущего статуса"""
        return self.current_status

    def print_methods_info(self):
        """Вывод информации о методах проверки"""
        print("\n" + "=" * 60)
        print("Available check methods:")
        print("-" * 60)

        for i, method in enumerate(self.check_methods, 1):
            enabled = "✓" if method.get('enabled', False) else "✗"
            name = method['name']
            if name == 'Custom Port':
                port = method.get('port', 8080)
                print(f"{i}. [{enabled}] {name} (port {port})")
            else:
                print(f"{i}. [{enabled}] {name}")

        print("=" * 60)


async def main():
    """Основная функция для тестирования"""
    checker = IPv4WhitelistChecker()

    print("=" * 60)
    print("IPv4 Whitelisted Subnets Checker with Multi-Port Support")
    print("=" * 60)
    print("Current configuration:")
    print(f"  - Mode: {'ANY (host alive if ANY method succeeds)' if checker.require_any_method else 'ALL (host alive if ALL methods succeed)'}")
    print(f"  - Enabled methods: {[m['name'] for m in checker.check_methods if m.get('enabled', False)]}")
    print("=" * 60)

    # Пытаемся загрузить кэшированные данные
    has_cache = checker.load_cached_subnets()

    while True:
        print(f"\nCurrent status: {checker.get_status()}")
        print("\nMenu:")
        print("1. Cache subnets")
        print("2. Check subnets")
        print("3. Save results")
        print("4. Print results")
        print("5. Set parameters")
        print("6. Configure check methods")
        print("7. Test single IP")
        print("8. Enable debug mode")
        print("9. Exit")

        choice = input("\nSelect option (1-9): ").strip()

        if choice == "1":
            print("\nCaching subnets...")
            success = await checker.cache_subnets()
            if success:
                print("✓ Subnets cached successfully")
            else:
                print("✗ Failed to cache subnets")

        elif choice == "2":
            print("\nChecking subnets...")
            if not checker.cached_subnets:
                print("⚠️ No cached subnets found. Cache first.")
                continue

            print(f"Mode: {'ANY (OR)' if checker.require_any_method else 'ALL (AND)'}")
            print(f"Methods: {[m['name'] for m in checker.check_methods if m.get('enabled', False)]}")

            has_results = await checker.check_subnets()
            if has_results:
                print(f"✓ Found {checker.results_count} accessible subnets")
            else:
                print("✗ No accessible subnets found")

        elif choice == "3":
            if checker.results_data:
                filename = checker.save_results()
                if filename:
                    print(f"✓ Results saved to {filename}")
                else:
                    print("✗ Failed to save results")
            else:
                print("⚠️ No results to save")

        elif choice == "4":
            checker.print_results_table()

        elif choice == "5":
            print("\nSet parameters:")
            try:
                timeout = input(f"Timeout (ms) [{checker.timeout_ms}]: ").strip()
                if timeout:
                    checker.timeout_ms = int(timeout)

                sample_size = input(f"Subnet sample size [{checker.subnet_sample_size}]: ").strip()
                if sample_size:
                    checker.subnet_sample_size = int(sample_size)

                alive_min = input(f"Minimum alive hosts [{checker.subnet_alive_min}]: ").strip()
                if alive_min:
                    checker.subnet_alive_min = int(alive_min)

                only_24 = input(f"Only /24 prefixes (true/false) [{checker.subnet_only_24_prefix}]: ").strip().lower()
                if only_24:
                    checker.subnet_only_24_prefix = only_24 == "true"

                mode = input(f"Require ANY method to succeed? (true/false) [{checker.require_any_method}]: ").strip().lower()
                if mode:
                    checker.require_any_method = mode == "true"
                    print(f"✓ Mode changed to: {'ANY (OR)' if checker.require_any_method else 'ALL (AND)'}")

                print("✓ Parameters updated")
            except ValueError:
                print("✗ Invalid input")

        elif choice == "6":
            print("\nConfigure check methods:")
            checker.print_methods_info()

            try:
                method_choice = input("\nSelect method number to toggle (or 'all' to show all): ").strip()

                if method_choice.lower() == 'all':
                    for method in checker.check_methods:
                        method['enabled'] = True
                    print("✓ All methods enabled")
                elif method_choice.isdigit():
                    idx = int(method_choice) - 1
                    if 0 <= idx < len(checker.check_methods):
                        checker.check_methods[idx]['enabled'] = not checker.check_methods[idx].get('enabled', False)
                        status = "enabled" if checker.check_methods[idx]['enabled'] else "disabled"
                        print(f"✓ Method '{checker.check_methods[idx]['name']}' {status}")

                        # Если это Custom Port, спросим порт
                        if checker.check_methods[idx]['name'] == 'Custom Port' and checker.check_methods[idx]['enabled']:
                            port = input(f"Enter port number [{checker.check_methods[idx].get('port', 8080)}]: ").strip()
                            if port and port.isdigit():
                                checker.check_methods[idx]['port'] = int(port)
                    else:
                        print("✗ Invalid method number")
            except Exception as e:
                print(f"✗ Error: {e}")

        elif choice == "7":
            print("\nTest single IP address:")
            ip = input("Enter IP address: ").strip()

            if not ip:
                print("✗ No IP provided")
                continue

            try:
                ipaddress.IPv4Address(ip)  # Валидация IP

                print(f"\nTesting {ip}...")
                print(f"Mode: {'ANY (success if ANY method works)' if checker.require_any_method else 'ALL (success if ALL methods work)'}")

                # Тестируем все методы
                async with aiohttp.ClientSession() as session:
                    results = {}
                    for method in checker.check_methods:
                        if method.get('enabled', False):
                            try:
                                result = await method['func'](session, ip)
                                status = "✓" if result else "✗"
                                results[method['name']] = result
                                print(f"  {method['name']}: {status}")
                            except Exception as e:
                                print(f"  {method['name']}: Error ({e})")
                                results[method['name']] = False

                # Определяем общий результат
                if checker.require_any_method:
                    overall = any(results.values())
                else:
                    overall = all(results.values())

                print(f"\nOverall result: {'✅ ALIVE' if overall else '❌ DEAD'}")
                print(f"  ({sum(results.values())}/{len(results)} methods succeeded)")

            except ipaddress.AddressValueError:
                print("✗ Invalid IP address")

        elif choice == "8":
            # Переключаем уровень логирования
            current_level = logger.level
            if current_level == logging.INFO:
                logger.setLevel(logging.DEBUG)
                print("✓ Debug mode enabled (detailed logs)")
            else:
                logger.setLevel(logging.INFO)
                print("✓ Debug mode disabled (only important logs)")

        elif choice == "9":
            print("Goodbye!")
            break

        else:
            print("✗ Invalid choice")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")