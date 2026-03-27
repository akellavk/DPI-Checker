import asyncio
import aiohttp
import ipaddress
import random
import json
import csv
from datetime import datetime
from typing import List, Dict, Tuple, Set, Optional
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class IPv4WhitelistChecker:
    def __init__(self):
        self.test_suite = [
            {"name": "Beget", "asns": ["198610"]},
        ]

        self.timeout_ms = 5000
        self.subnet_sample_size = 25
        self.subnet_alive_min = 3
        self.subnet_only_24_prefix = True

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

    def set_params(self, timeout: int = None, sn_sample_size: int = None,
                   sn_alive_min: int = None, sn_only_24_prefix: bool = None):
        """Установка параметров (аналог getParamsHandler)"""
        if timeout:
            self.timeout_ms = timeout
        if sn_sample_size:
            self.subnet_sample_size = sn_sample_size
        if sn_alive_min:
            self.subnet_alive_min = sn_alive_min
        if sn_only_24_prefix is not None:
            self.subnet_only_24_prefix = sn_only_24_prefix

    def log_push(self, level: str, prefix: Optional[str], msg: str) -> str:
        """Аналог logPush"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        prefix_str = f"{prefix}/" if prefix else ""
        log_msg = f"[{timestamp}] {prefix_str}{level}: {msg}"

        if level == "ERR":
            logger.error(log_msg)
        elif level == "INFO":
            logger.info(log_msg)
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

    async def check_ipv4_host(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        early_abort_event: asyncio.Event,
        ref: Dict,
    ) -> bool:
        """
        Проверка одного хоста.
        """
        if early_abort_event.is_set():
            self.log_push("INFO", f"Host checker[{ip}]", "Skipped (early abort ⏭️).")
            return False

        prefix = f"Host checker[{ip}]"
        self.log_push("INFO", prefix, "Started")

        url = f"https://{ip}/?t={random.random()}"
        result = False

        try:
            async with session.head(
                url,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout_ms / 1000),
                allow_redirects=False,
            ):
                # Любой HTTP-ответ от сервера — хост жив
                result = True

        except asyncio.TimeoutError:
            # Хост не ответил за отведённое время — считаем мёртвым
            result = False

        # --- Явный список сетевых ошибок ---
        except (
            aiohttp.ClientConnectorError,  # не удалось установить соединение
            aiohttp.ServerDisconnectedError,  # сервер разорвал соединение
            aiohttp.ClientOSError,  # низкоуровневая ошибка сокета (Windows)
        ) as e:
            # --- Обрыв WiFi — ждём восстановления ---
            self.log_push("INFO", prefix,
                          f"Network error: {type(e).__name__}. Checking connectivity...")
            await wait_for_connectivity(self.log_push)
            # После восстановления соединения считаем хост недоступным —
            # мы не знаем реального состояния, безопаснее пропустить.
            result = False

        except aiohttp.ClientError:
            # Прочие ошибки клиента (неверный ответ, TLS и т.д.) — мёртвый
            result = False

        if result:
            ref["alive_count"] += 1

        if ref["alive_count"] >= self.subnet_alive_min:
            early_abort_event.set()

        if result:
            status = "Alive ✅"
        elif early_abort_event.is_set():
            status = "Early abort ⏭️"
        else:
            status = "Dead 💀"

        self.log_push("INFO", prefix, f"{status}.")
        return result

    async def check_subnet(
        self,
        session: aiohttp.ClientSession,
        provider: str,
        cidr: str,
    ) -> int:
        """
        Проверка подсети на доступность.
        1. Semaphore = SUBNET_CONCURRENCY (5), а не subnet_sample_size (25).
           Оригинал ограничивал параллельность; в старом коде semaphore был
           равен числу задач и не давал никакого ограничения.
        2. Проверка early_abort_event ВНУТРИ run_one, прямо перед захватом
           семафора — задачи, созданные до установки флага, не будут
           выполнять сетевой запрос.
        3. Подсеть добавляется в результаты только при alive_count >= subnet_alive_min,
           а не при alive_count > 0. Это исключает ложные срабатывания.
        """
        prefix = f"Subnet checker[{provider} => {cidr}]"
        self.log_push("INFO", prefix, "Started")

        ips = self.get_subnet_sample(cidr, self.subnet_sample_size)
        early_abort_event = asyncio.Event()
        ref = {"alive_count": 0}

        semaphore = asyncio.Semaphore(SUBNET_CONCURRENCY)

        async def run_one(ip: str) -> bool:
            if early_abort_event.is_set():
                return False
            async with semaphore:
                return await self.check_ipv4_host(session, ip, early_abort_event, ref)

        results = await asyncio.gather(*[run_one(ip) for ip in ips])

        alive_count = ref["alive_count"]

        if alive_count >= self.subnet_alive_min:
            self.results_count += 1
            self.results_data.append({
                "provider": provider,
                "cidr": cidr,
                "alive_count": alive_count,
            })
            self.log_push("INFO", prefix, f"Whitelisted ✅ (alive: {alive_count}).")
        else:
            self.log_push("INFO", prefix, f"Done (alive: {alive_count} — below threshold).")

        return alive_count

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
                    if "." in item["prefix"] and "/" in item["prefix"]  # Только IPv4
                ]

                self.log_push("INFO", prefix, f"Done (total: {len(prefixes)}).")
                return prefixes

        except Exception as e:
            error_msg = f"{prefix} error: {str(e)}"
            self.log_push("ERR", prefix, str(e))
            raise Exception(error_msg)

    async def fetch_provider_ipv4_subnets(
        self,
        session: aiohttp.ClientSession,
        provider: Dict,
    ) -> List[str]:
        """Получение подсетей для провайдера"""
        prefix = f"Provider IPv4 subnets fetcher[{provider['name']}]"
        self.log_push("INFO", prefix, "Started")

        tasks = [self.fetch_as_ipv4_subnets(session, asn) for asn in provider["asns"]]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        all_subnets = []
        for result in all_results:
            if isinstance(result, list):
                all_subnets.extend(result)
            elif isinstance(result, Exception):
                self.log_push("ERR", prefix, f"Error fetching AS: {result}")

        merged = list(set(all_subnets))

        if self.subnet_only_24_prefix:
            suitable = [s for s in merged if s.endswith("/24")]
        else:
            suitable = merged

        self.log_push(
            "INFO", prefix,
            f"Done (all: {len(all_subnets)}, merged: {len(merged)}, suitable: {len(suitable)}).",
        )
        return suitable

    async def cache_subnets(self):
        """Кэширование подсетей"""
        self.current_status = self.STATUS_CACHING
        self.log_push("INFO", "Subnets cacher", "Started")

        self.cached_subnets = {}
        self.results_data = []
        self.results_count = 0

        try:
            # Перед кэшированием убеждаемся, что сеть есть
            await wait_for_connectivity(self.log_push)

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

        # Перед началом проверки убеждаемся, что сеть есть
        await wait_for_connectivity(self.log_push)

        subnets_total = sum(len(s) for s in self.cached_subnets.values())
        subnets_checked = 0

        async with aiohttp.ClientSession() as session:
            for provider, subnets in self.cached_subnets.items():
                for subnet in subnets:
                    subnets_checked += 1
                    self.log_push("INFO", prefix,
                                  f"Progress: {subnets_checked}/{subnets_total}")
                    await self.check_subnet(session, provider, subnet)

        self.current_status = self.STATUS_READY_CACHED
        self.log_push(
            "INFO", prefix,
            f"Done (found: {self.results_count}, total subnets: {subnets_total}).",
        )
        return self.results_count > 0

    def load_cached_subnets(self) -> bool:
        """Загрузка кэшированных подсетей из файла"""
        try:
            with open("cached_subnets.json", "r") as f:
                self.cached_subnets = json.load(f)

            total = sum(len(s) for s in self.cached_subnets.values())
            self.log_push(
                "INFO", None,
                f"Cached subnets loaded (providers: {len(self.cached_subnets)}, "
                f"total subnets: {total}).",
            )
            self.current_status = self.STATUS_READY_CACHED
            return True

        except FileNotFoundError:
            self.log_push("INFO", None, "Cached subnets not found.")
            return False
        except Exception as e:
            self.log_push("ERR", None, f"Error loading cached subnets: {e}")
            return False

    def save_results(self, filename: str = None) -> Optional[str]:
        """Сохранение результатов в CSV файл"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ipv4-whitelisted-subnets-{timestamp}.csv"

        try:
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                fieldnames = ["provider", "cidr", "alive_count"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=";")
                writer.writeheader()
                for row in self.results_data:
                    writer.writerow(row)

            self.log_push("INFO", "Results saver", f"Results saved to {filename}")
            return filename

        except Exception as e:
            self.log_push("ERR", "Results saver", f"Error saving results: {e}")
            return None

    def print_results_table(self):
        """Вывод результатов в виде таблицы"""
        print("\n" + "=" * 60)
        print(f"{'#':<3} {'Provider':<20} {'Whitelisted Subnet':<30}")
        print("-" * 60)

        for i, result in enumerate(self.results_data, 1):
            subnet_display = f"{result['cidr']} ✅"
            print(f"{i:<3} {result['provider']:<20} {subnet_display:<30}")

        print("=" * 60)
        print(f"Total: {self.results_count} subnets found")

    def get_status(self) -> str:
        return self.current_status


async def main():
    """Основная функция для тестирования"""
    checker = IPv4WhitelistChecker()

    print("IPv4 Whitelisted Subnets Checker")
    print("-" * 40)

    checker.load_cached_subnets()

    while True:
        print(f"\nCurrent status: {checker.get_status()}")
        print("\nMenu:")
        print("1. Cache subnets")
        print("2. Check subnets")
        print("3. Save results")
        print("4. Print results")
        print("5. Set parameters")
        print("6. Exit")

        choice = input("\nSelect option (1-6): ").strip()

        if choice == "1":
            print("\nCaching subnets...")
            success = await checker.cache_subnets()
            print("✓ Subnets cached successfully" if success else "✗ Failed to cache subnets")

        elif choice == "2":
            if not checker.cached_subnets:
                print("⚠️ No cached subnets found. Cache first.")
                continue
            print("\nChecking subnets...")
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
            if checker.results_data:
                checker.print_results_table()
            else:
                print("⚠️ No results to display")

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

                only_24 = input(
                    f"Only /24 prefixes (true/false) [{checker.subnet_only_24_prefix}]: "
                ).strip().lower()
                if only_24:
                    checker.subnet_only_24_prefix = only_24 == "true"

                print("✓ Parameters updated")
            except ValueError:
                print("✗ Invalid input")

        elif choice == "6":
            print("Goodbye!")
            break

        else:
            print("✗ Invalid choice")


if __name__ == "__main__":
    # Для тестирования
    asyncio.run(main())